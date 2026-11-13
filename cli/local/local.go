// Package local provides an explicitly provisioned, offline Keyref store.
// It does not implement the synchronized vault's grants or approval protocol.
package local

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"

	keycrypto "github.com/lidessen/keyref/proto/crypto"
	_ "modernc.org/sqlite"
)

var (
	ErrNotFound     = errors.New("local secret not found")
	ErrInvalidKey   = errors.New("invalid local vault key")
	ErrInvalidStore = errors.New("invalid local vault")
	ErrClosed       = errors.New("local vault closed")
)

const maxValue = 1 << 20
const checkText = "keyref-local-v1"

// Store holds derived keys until Close. Memory wiping is best effort: Go and
// its crypto implementation may retain copies.
type Store struct {
	mu       sync.RWMutex
	db       *sql.DB
	key      []byte
	indexKey []byte
	id       string
}

// Create exclusively creates a new private store. It never overwrites a file.
// The key is not persisted and must be retained separately by the caller.
func Create(path string, key []byte) (*Store, error) { return open(path, key, true) }

// Open opens an existing private store and verifies the key without creating one.
func Open(path string, key []byte) (*Store, error) { return open(path, key, false) }

// StoreID returns the vault's random store id (32 lowercase hex
// characters). It is not a secret: clients bind external key material
// (the OS-keyring master key entry) to the vault with it.
func (s *Store) StoreID() string { return s.id }

// ReadStoreID returns a vault's store id without decrypting anything
// and without creating the file. It never needs the master key.
func ReadStoreID(path string) (string, error) {
	if path == "" || !filepath.IsAbs(path) {
		return "", ErrInvalidStore
	}
	u := &url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return "", ErrInvalidStore
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var id string
	if err := db.QueryRow("SELECT id FROM metadata").Scan(&id); err != nil {
		return "", ErrInvalidStore
	}
	if len(id) != 32 {
		return "", ErrInvalidStore
	}
	if _, err := hex.DecodeString(id); err != nil || strings.ToLower(id) != id {
		return "", ErrInvalidStore
	}
	return id, nil
}

func open(path string, key []byte, create bool) (*Store, error) {
	if len(key) != 32 {
		return nil, ErrInvalidKey
	}
	if path == "" || !filepath.IsAbs(path) {
		return nil, ErrInvalidStore
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0077 != 0 {
		return nil, ErrInvalidStore
	}
	if create {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, ErrInvalidStore
		}
		if f.Close() != nil {
			return nil, ErrInvalidStore
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return nil, ErrInvalidStore
	}
	// The file must already exist; even Open must never create a replacement if
	// it disappears between the metadata check and SQLite opening it.
	u := &url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, ErrInvalidStore
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Store, error) { _ = db.Close(); return nil, e }
	if _, err = db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		return fail(ErrInvalidStore)
	}
	s := &Store{db: db}
	derive := func() error {
		var e error
		s.key, e = hkdf.Key(sha256.New, key, []byte(s.id), "keyref-local-encryption-v1", 32)
		if e != nil {
			return e
		}
		s.indexKey, e = hkdf.Key(sha256.New, key, []byte(s.id), "keyref-local-index-v1", 32)
		if e != nil {
			keycrypto.WipeKey(s.key)
		}
		return e
	}
	wipe := func() { keycrypto.WipeKey(s.key); keycrypto.WipeKey(s.indexKey) }
	if create {
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			keycrypto.WipeKey(s.key)
			return fail(ErrInvalidStore)
		}
		s.id = hex.EncodeToString(id)
		if derive() != nil {
			return fail(ErrInvalidStore)
		}
		blob, e := keycrypto.SealBlob(s.key, []byte(checkText+":"+s.id), []byte(checkText))
		if e != nil {
			wipe()
			return fail(ErrInvalidStore)
		}
		tx, e := db.Begin()
		if e != nil {
			wipe()
			return fail(ErrInvalidStore)
		}
		defer tx.Rollback()
		if _, e = tx.Exec(`CREATE TABLE metadata (id TEXT NOT NULL, check_blob BLOB NOT NULL, writes INTEGER NOT NULL); CREATE TABLE entries (id TEXT PRIMARY KEY, blob BLOB NOT NULL);`); e == nil {
			_, e = tx.Exec("INSERT INTO metadata(id,check_blob,writes) VALUES (?,?,1)", s.id, blob)
		}
		if e == nil {
			e = tx.Commit()
		}
		if e != nil {
			wipe()
			return fail(ErrInvalidStore)
		}
	} else {
		var blob []byte
		var blobLen int64
		var writes int64
		if err = db.QueryRow("SELECT substr(id,1,33),substr(check_blob,1,129),length(check_blob),writes FROM metadata").Scan(&s.id, &blob, &blobLen, &writes); err != nil || len(s.id) != 32 || blobLen > 128 || blobLen < 28 || writes < 1 || writes > 4294967295 {
			return fail(ErrInvalidStore)
		}
		if _, err = hex.DecodeString(s.id); err != nil || strings.ToLower(s.id) != s.id {
			return fail(ErrInvalidStore)
		}
		if derive() != nil {
			return fail(ErrInvalidStore)
		}
		plain, e := keycrypto.OpenBlob(s.key, []byte(checkText+":"+s.id), blob)
		if e != nil || string(plain) != checkText {
			keycrypto.WipeKey(plain)
			wipe()
			return fail(ErrInvalidKey)
		}
		keycrypto.WipeKey(plain)
	}
	return s, nil
}

func (s *Store) entryID(ref string) (string, error) {
	if ref == "" || len(ref) > 512 || strings.ContainsRune(ref, '\x00') {
		return "", ErrInvalidStore
	}
	h := hmac.New(sha256.New, s.indexKey)
	_, _ = fmt.Fprintf(h, "keyref-local-ref-v1:%s:%s", s.id, ref)
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}

// Put atomically replaces a secret at ref. The caller retains ownership of value.
func (s *Store) Put(ctx context.Context, ref string, value []byte) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return ErrClosed
	}
	if len(value) == 0 || len(value) > maxValue {
		return ErrInvalidStore
	}
	id, err := s.entryID(ref)
	if err != nil {
		return err
	}
	aad, err := keycrypto.SecretAAD(s.id, id)
	if err != nil {
		return ErrInvalidStore
	}
	blob, err := keycrypto.SealBlob(s.key, aad, value)
	if err != nil {
		return ErrInvalidStore
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return ErrInvalidStore
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE metadata SET writes=writes+1 WHERE writes < 4294967295")
	if err != nil {
		return ErrInvalidStore
	}
	count, err := res.RowsAffected()
	if err != nil || count != 1 {
		return ErrInvalidStore
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO entries(id,blob) VALUES (?,?) ON CONFLICT(id) DO UPDATE SET blob=excluded.blob", id, blob)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return ErrInvalidStore
	}
	return nil
}

// Use decrypts only for the callback and wipes its buffer afterwards. A callback
// must not retain, log, or pass the bytes to an untrusted recipient. Close does
// not cancel a Use whose data has already been decrypted.
func (s *Store) Use(ctx context.Context, ref string, fn func([]byte) error) error {
	if fn == nil {
		return ErrInvalidStore
	}
	plain, err := s.read(ctx, ref)
	if err != nil {
		return err
	}
	defer keycrypto.WipeKey(plain)
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(plain)
}

func (s *Store) read(ctx context.Context, ref string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	id, err := s.entryID(ref)
	if err != nil {
		return nil, err
	}
	var blob []byte
	var blobLen int64
	if err = s.db.QueryRowContext(ctx, "SELECT substr(blob,1,?),length(blob) FROM entries WHERE id = ?", maxValue+29, id).Scan(&blob, &blobLen); errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	} else if err != nil {
		return nil, ErrInvalidStore
	}
	if blobLen < 28 || blobLen > maxValue+28 {
		return nil, ErrInvalidStore
	}
	aad, err := keycrypto.SecretAAD(s.id, id)
	if err != nil {
		return nil, ErrInvalidStore
	}
	plain, err := keycrypto.OpenBlob(s.key, aad, blob)
	if err != nil {
		return nil, ErrInvalidStore
	}
	return plain, nil
}

func (s *Store) Delete(ctx context.Context, ref string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return ErrClosed
	}
	id, err := s.entryID(ref)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, "DELETE FROM entries WHERE id = ?", id)
	if err != nil {
		return ErrInvalidStore
	}
	n, err := res.RowsAffected()
	if err != nil {
		return ErrInvalidStore
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.db == nil {
		return nil
	}
	err := s.db.Close()
	s.db = nil
	keycrypto.WipeKey(s.key)
	keycrypto.WipeKey(s.indexKey)
	s.key = nil
	s.indexKey = nil
	return err
}
