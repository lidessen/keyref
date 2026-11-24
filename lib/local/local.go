// Package local provides an explicitly provisioned, offline Keyref store.
// It does not implement the synchronized vault's grants or approval protocol.
package local

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/lidessen/keyref/lib/secret"
	keycrypto "github.com/lidessen/keyref/proto/crypto"
	_ "modernc.org/sqlite"
)

var (
	// ErrNotFound reports a ref with no row in the vault.
	ErrNotFound = errors.New("local secret not found")
	// ErrInvalidKey reports a master key that does not open this vault.
	ErrInvalidKey = errors.New("invalid local vault key")
	// ErrInvalidStore reports a path that cannot hold a vault (relative
	// path, not a regular file), an argument the store rejects outright
	// (an entry policy with an empty or NUL member, an import batch over
	// its limits) and database failures with nothing better to say.
	// Failures the caller can act on use the specific errors below.
	ErrInvalidStore = errors.New("invalid local vault")
	// ErrInvalidRef reports a ref outside the design §6.1 grammar.
	ErrInvalidRef = errors.New("invalid ref")
	// ErrInvalidValueSize reports a value of 0 bytes or more than 1 MiB.
	ErrInvalidValueSize = errors.New("invalid local secret size")
	// ErrMetaTooLarge reports a sealed meta blob over the 64 KiB bound.
	ErrMetaTooLarge = errors.New("local entry meta is too large")
	// ErrClosed reports an operation on a closed store.
	ErrClosed = errors.New("local vault closed")

	// The classification of design §17.7: an embedder must be able to
	// tell these apart without parsing messages.
	//
	// ErrStoreNotFound reports a vault file that is not there.
	ErrStoreNotFound = errors.New("local vault not found")
	// ErrStoreExists reports something already at the vault path when a
	// new vault was to be created.
	ErrStoreExists = errors.New("local vault already exists")
	// ErrInsecurePermissions reports a vault whose directory or file can
	// be read by other users: the directory must be mode 0700 and the
	// vault file mode 0600.
	ErrInsecurePermissions = errors.New("local vault permissions are not private")
	// ErrWriteLimit reports the 2^32−1 write budget of the metadata row:
	// the vault accepts no further writes and every written row is kept.
	ErrWriteLimit = errors.New("local vault write limit reached")
	// ErrCorruptStore reports a vault file whose contents do not read as
	// a vault: a missing or malformed metadata row, a secret or meta
	// blob that does not decrypt or validate, or a stored value outside
	// the format's limits. A master key that does not match is
	// ErrInvalidKey, reported while opening and before any row is read.
	ErrCorruptStore = errors.New("corrupt local vault")
)

// classified pairs a sentinel with a message that is safe to print and,
// optionally, the underlying error.
//
// Error() returns only the message (or the sentinel's own text when
// there is none): database and filesystem errors can carry SQL text and
// parameter values, so the library never surfaces them in its messages —
// the CLI and the MCP layer print Error() verbatim. Unwrap() exposes
// both the sentinel and the cause, so errors.Is finds the
// classification and a caller that knows its own audience can inspect
// the cause itself (design §17.7: the cause stays reachable through
// Unwrap, while Error() prints only fixed safe text).
type classified struct {
	sentinel error
	msg      string
	cause    error
}

func (e *classified) Error() string {
	if e.msg == "" {
		return e.sentinel.Error()
	}
	return e.msg
}

func (e *classified) Unwrap() []error {
	if e.cause == nil {
		return []error{e.sentinel}
	}
	return []error{e.sentinel, e.cause}
}

// classify returns the plain sentinel when there is nothing to add,
// otherwise a classified error.
func classify(sentinel error, msg string, cause error) error {
	if msg == "" && cause == nil {
		return sentinel
	}
	return &classified{sentinel: sentinel, msg: msg, cause: cause}
}

// sqlFailure classifies a database failure. A cancelled or expired
// context is returned unchanged, never folded into another error
// (design §17.7); anything else keeps the driver's message out of the
// text while still exposing it through Unwrap.
func sqlFailure(ctx context.Context, sentinel error, msg string, cause error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return classify(sentinel, msg, cause)
}

const maxValue = 1 << 20
const maxMeta = 64 << 10

// writeCap is the vault's total write budget: the metadata row's counter
// is a 32-bit value and the last writable state is exactly this many
// writes.
const writeCap = int64(4294967295)
const checkText = "keyref-local-v1"

// Policy holds the command, argv and URL host restrictions for local execution.
type Policy struct {
	AllowedHosts  []string `json:"allowedHosts"`
	AllowCommands []string `json:"allowCommands,omitempty"`
	AllowArgv     bool     `json:"allowArgv,omitempty"`
}

func (p Policy) valid() bool {
	for _, host := range append(append([]string{}, p.AllowedHosts...), p.AllowCommands...) {
		if host == "" || strings.ContainsRune(host, 0) {
			return false
		}
	}
	return true
}

// Meta is one entry's metadata plaintext before encryption. Masked and
// Bytes are computed from the value at write time, so List and Stat
// never need to decrypt the secret (design.md §17.4).
type Meta struct {
	V           int    `json:"v"`
	Ref         string `json:"ref"`
	Description string `json:"description"`
	Masked      string `json:"masked"`
	Bytes       int    `json:"bytes"`
	UpdatedAt   int64  `json:"updated_at"`
	Policy      Policy `json:"policy"`
	Type        string `json:"type,omitempty"`
	Username    string `json:"username,omitempty"`
	URL         string `json:"url,omitempty"`
	// Incomplete marks legacy metadata whose mask and size are unknown.
	// It is derived on read and is never stored in the encrypted JSON.
	Incomplete bool `json:"-"`
}

// PutOptions carries the caller-supplied part of the meta. Every Put
// writes a complete meta: a replacement without these options resets
// the description and policy, because a caller that does not know the
// value must not be able to widen its policy (design.md §17.4).
type PutOptions struct {
	Description   string
	AllowedHosts  []string
	AllowCommands []string
	AllowArgv     bool
	Username      *string
	URL           string
}

// maskPrefixes is the §6.1 longest-prefix table used for non-password
// values. A local entry has no type, so the generic branch applies.
var maskPrefixes = []string{
	"github_pat_", "sk-proj-", "sk-ant-", "glpat-", "xoxb-", "xoxp-", "xoxa-",
	"ghp_", "gho_", "sk-", "AKIA",
}

// Mask derives the display mask at write time (design.md §6.1). Values
// that are not printable ASCII are masked completely: the suffix of an
// arbitrary byte string is not safe to show and may not render.
func Mask(value []byte) string {
	if len(value) == 0 {
		return "***"
	}
	for _, b := range value {
		if b < 0x21 || b > 0x7e {
			return "***"
		}
	}
	s := value
	prefix := ""
	for _, p := range maskPrefixes {
		if bytes.HasPrefix(s, []byte(p)) && len(p) > len(prefix) {
			prefix = p
		}
	}
	if len(s) < len(prefix)+8 {
		return "***"
	}
	return prefix + "****" + string(s[len(s)-4:])
}

// refPattern is the ref grammar of design.md §6.1: one lowercase letter,
// or a lowercase-letter head, up to 62 lowercase letters/digits/hyphens
// and a lowercase letter or digit tail. No whitespace, ":", "=" or
// braces can appear.
var refPattern = regexp.MustCompile(`^(?:[a-z]|[a-z][a-z0-9-]{0,62}[a-z0-9])$`)

// ValidRef reports whether ref is a legal local ref. Reads and deletes
// still hash whatever they are given, so an invalid ref simply misses;
// only creation is refused, which keeps malformed refs out of a vault.
func ValidRef(ref string) bool { return refPattern.MatchString(ref) }

// Store holds derived keys until Close. Memory wiping is best effort: Go and
// its crypto implementation may retain copies.
type Store struct {
	mu       sync.RWMutex
	db       *sql.DB
	key      []byte
	indexKey []byte
	metaKey  []byte
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
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", classify(ErrStoreNotFound, "", err)
		}
		return "", classify(ErrInvalidStore, "", err)
	}
	u := &url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return "", classify(ErrInvalidStore, "", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	var id string
	if err := db.QueryRow("SELECT id FROM metadata").Scan(&id); err != nil {
		return "", classify(ErrCorruptStore, "corrupt local vault: could not read the metadata row", err)
	}
	if len(id) != 32 {
		return "", ErrCorruptStore
	}
	if _, err := hex.DecodeString(id); err != nil || strings.ToLower(id) != id {
		return "", ErrCorruptStore
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
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, classify(ErrStoreNotFound, "", err)
	case err != nil:
		return nil, classify(ErrInvalidStore, "", err)
	case !parent.IsDir():
		return nil, ErrInvalidStore
	case parent.Mode().Perm()&0o077 != 0:
		return nil, ErrInsecurePermissions
	}
	if create {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			if errors.Is(err, os.ErrExist) {
				// Something is already there. A vault-sized regular file
				// is "already exists"; anything else (a symlink, a
				// directory) cannot be one at all.
				if info, lerr := os.Lstat(path); lerr == nil && !info.Mode().IsRegular() {
					return nil, classify(ErrInvalidStore, "", err)
				}
				return nil, classify(ErrStoreExists, "", err)
			}
			return nil, classify(ErrInvalidStore, "", err)
		}
		if cerr := f.Close(); cerr != nil {
			return nil, classify(ErrInvalidStore, "", cerr)
		}
	}
	info, err := os.Lstat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil, classify(ErrStoreNotFound, "", err)
	case err != nil:
		return nil, classify(ErrInvalidStore, "", err)
	case !info.Mode().IsRegular():
		return nil, ErrInvalidStore
	case info.Mode().Perm() != 0o600:
		return nil, ErrInsecurePermissions
	}
	// The file must already exist; even Open must never create a replacement if
	// it disappears between the metadata check and SQLite opening it. The
	// driver applies busy_timeout to every physical connection, including a
	// replacement after a cancelled or otherwise uncertain transaction.
	u := &url.URL{Scheme: "file", Path: path, RawQuery: "mode=rw&_busy_timeout=5000"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, classify(ErrInvalidStore, "", err)
	}
	db.SetMaxOpenConns(1)
	fail := func(e error) (*Store, error) { _ = db.Close(); return nil, e }
	s := &Store{db: db}
	wipe := func() { keycrypto.WipeKey(s.key); keycrypto.WipeKey(s.indexKey); keycrypto.WipeKey(s.metaKey) }
	derive := func() error {
		var e error
		s.key, e = hkdf.Key(sha256.New, key, []byte(s.id), "keyref-local-encryption-v1", 32)
		if e != nil {
			return e
		}
		s.indexKey, e = hkdf.Key(sha256.New, key, []byte(s.id), "keyref-local-index-v1", 32)
		if e != nil {
			wipe()
			return e
		}
		s.metaKey, e = hkdf.Key(sha256.New, key, []byte(s.id), "keyref-local-meta-v1", 32)
		if e != nil {
			wipe()
		}
		return e
	}
	if create {
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			keycrypto.WipeKey(s.key)
			return fail(classify(ErrInvalidStore, "invalid local vault: could not initialize a new vault", err))
		}
		s.id = hex.EncodeToString(id)
		if derive() != nil {
			return fail(classify(ErrInvalidStore, "invalid local vault: could not derive the vault keys", nil))
		}
		blob, e := keycrypto.SealBlob(s.key, []byte(checkText+":"+s.id), []byte(checkText))
		if e != nil {
			wipe()
			return fail(classify(ErrInvalidStore, "invalid local vault: could not initialize a new vault", e))
		}
		tx, e := db.Begin()
		if e != nil {
			wipe()
			return fail(classify(ErrInvalidStore, "invalid local vault: could not initialize a new vault", e))
		}
		defer tx.Rollback()
		if _, e = tx.Exec(`CREATE TABLE metadata (id TEXT NOT NULL, check_blob BLOB NOT NULL, writes INTEGER NOT NULL); CREATE TABLE entries (id TEXT PRIMARY KEY, meta BLOB NOT NULL, blob BLOB NOT NULL); PRAGMA user_version = 1;`); e == nil {
			_, e = tx.Exec("INSERT INTO metadata(id,check_blob,writes) VALUES (?,?,1)", s.id, blob)
		}
		if e == nil {
			e = tx.Commit()
		}
		if e != nil {
			wipe()
			return fail(classify(ErrInvalidStore, "invalid local vault: could not initialize a new vault", e))
		}
	} else {
		var blob []byte
		var blobLen int64
		var writes int64
		err = db.QueryRow("SELECT substr(id,1,33),substr(check_blob,1,129),length(check_blob),writes FROM metadata").Scan(&s.id, &blob, &blobLen, &writes)
		if err != nil {
			return fail(classify(ErrCorruptStore, "corrupt local vault: could not read the metadata row", err))
		}
		if len(s.id) != 32 || blobLen > 128 || blobLen < 28 || writes < 1 || writes > writeCap {
			return fail(ErrCorruptStore)
		}
		if _, err = hex.DecodeString(s.id); err != nil || strings.ToLower(s.id) != s.id {
			return fail(ErrCorruptStore)
		}
		if derive() != nil {
			return fail(classify(ErrInvalidStore, "invalid local vault: could not derive the vault keys", nil))
		}
		plain, e := keycrypto.OpenBlob(s.key, []byte(checkText+":"+s.id), blob)
		if e != nil || string(plain) != checkText {
			// The key checked out against nothing: it does not open this
			// vault (design §17.7 distinguishes this from damage — a
			// wrong key never gets past here).
			keycrypto.WipeKey(plain)
			wipe()
			return fail(ErrInvalidKey)
		}
		keycrypto.WipeKey(plain)
		// Vaults created before encrypted meta existed get the nullable
		// column. Their rows have no ref stored, so they stay out of List
		// until Use can backfill accurate meta from an authorized read.
		if e := ensureMetaColumn(db); e != nil {
			wipe()
			return fail(classify(ErrCorruptStore, "corrupt local vault: could not migrate the schema", e))
		}
		if e := s.migrateCommandPolicy(); e != nil {
			wipe()
			return fail(classify(ErrCorruptStore, "could not migrate local credential metadata", e))
		}
	}
	return s, nil
}

// ensureMetaColumn adds the meta column to a vault created before
// encrypted meta (design.md §17.4). New vaults already have it.
func ensureMetaColumn(db *sql.DB) error {
	ctx := context.Background()
	found, err := hasMetaColumn(ctx, db)
	if err != nil || found {
		return err
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close()
	// Acquire the write reservation before rechecking the schema. Two
	// processes opening an old vault must not both attempt the ALTER.
	if _, err := conn.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		return err
	}
	defer conn.ExecContext(ctx, "ROLLBACK")
	found, err = hasMetaColumn(ctx, conn)
	if err != nil {
		return err
	}
	if !found {
		if _, err := conn.ExecContext(ctx, "ALTER TABLE entries ADD COLUMN meta BLOB"); err != nil {
			return err
		}
	}
	_, err = conn.ExecContext(ctx, "COMMIT")
	return err
}

func hasMetaColumn(ctx context.Context, db interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}) (bool, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info(entries)")
	if err != nil {
		return false, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return false, err
		}
		if name == "meta" {
			found = true
		}
	}
	return found, rows.Err()
}

func (s *Store) entryID(ref string) (string, error) {
	if ref == "" || len(ref) > 512 || strings.ContainsRune(ref, '\x00') {
		return "", ErrInvalidRef
	}
	h := hmac.New(sha256.New, s.indexKey)
	_, _ = fmt.Fprintf(h, "keyref-local-ref-v1:%s:%s", s.id, ref)
	return hex.EncodeToString(h.Sum(nil)[:16]), nil
}

// rowQuerier is what writeBudgetError needs to re-read the counter: a
// transaction or the dedicated import connection.
type rowQuerier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// writeBudgetError classifies a write-counter update that affected no
// rows. An error from the update itself is a database failure; zero
// affected rows mean either that the budget is spent or that the
// metadata row is missing, so it re-reads the counter under the same
// allowExpr the update used before saying which (design §17.7: a spent
// write budget and a corrupt vault are different failures). allowExpr
// is a SQL boolean with the same placeholders as args, both chosen by
// this package.
func writeBudgetError(ctx context.Context, q rowQuerier, allowExpr string, args []any, cause error) error {
	if cause != nil {
		return sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not count the write", cause)
	}
	// SQLite yields NOT(...) as 0 or 1, so the scan target is an integer.
	var blocked int64
	if err := q.QueryRowContext(ctx, "SELECT NOT ("+allowExpr+") FROM metadata", args...).Scan(&blocked); err != nil {
		// No metadata row (or no readable counter): the vault is damaged.
		return sqlFailure(ctx, ErrCorruptStore, "corrupt local vault: could not read the write counter", err)
	}
	if blocked != 0 {
		return ErrWriteLimit
	}
	return classify(ErrCorruptStore, "corrupt local vault: the write counter did not move", nil)
}

// Put atomically creates or replaces a secret at ref and reports whether
// the row is new. The meta (mask, size, description, policy) is sealed
// with its own key and AAD; List and Stat can read it without touching
// the secret. The caller retains ownership of value.
func (s *Store) Put(ctx context.Context, ref string, value []byte, opts PutOptions) (created bool, err error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return false, ErrClosed
	}
	if !ValidRef(ref) {
		return false, ErrInvalidRef
	}
	if len(value) == 0 || len(value) > maxValue {
		return false, ErrInvalidValueSize
	}
	if !(Policy{AllowedHosts: opts.AllowedHosts, AllowCommands: opts.AllowCommands}).valid() || (opts.Username == nil && opts.URL != "") {
		return false, ErrInvalidStore
	}
	id, err := s.entryID(ref)
	if err != nil {
		return false, err
	}
	m := &Meta{
		V:           1,
		Ref:         ref,
		Description: opts.Description,
		Masked:      Mask(value),
		Bytes:       len(value),
		UpdatedAt:   time.Now().UnixMilli(),
		Policy: Policy{
			AllowedHosts:  append([]string{}, opts.AllowedHosts...),
			AllowCommands: append([]string(nil), opts.AllowCommands...),
			AllowArgv:     opts.AllowArgv,
		},
	}
	stored := value
	if opts.Username != nil {
		if !utf8.Valid(value) || !utf8.ValidString(*opts.Username) {
			return false, ErrInvalidStore
		}
		m.Type, m.Username, m.URL = "login", *opts.Username, opts.URL
		stored, err = encodeLogin(m.Username, value)
		if err != nil {
			return false, err
		}
		defer keycrypto.WipeKey(stored)
	}
	metaBlob, err := s.sealMeta(id, m)
	if err != nil {
		return false, err
	}
	if len(metaBlob) > maxMeta {
		return false, ErrMetaTooLarge
	}
	aad, err := keycrypto.SecretAAD(s.id, id)
	if err != nil {
		return false, classify(ErrInvalidStore, "", err)
	}
	blob, err := keycrypto.SealBlob(s.key, aad, stored)
	if err != nil {
		return false, classify(ErrInvalidStore, "", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not start a transaction", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE metadata SET writes=writes+1 WHERE writes < ?", writeCap)
	if err != nil {
		return false, writeBudgetError(ctx, tx, "writes < ?", []any{writeCap}, err)
	}
	count, err := res.RowsAffected()
	if err != nil {
		return false, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not count the write", err)
	}
	if count != 1 {
		return false, writeBudgetError(ctx, tx, "writes < ?", []any{writeCap}, nil)
	}
	var exists int
	if err := tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM entries WHERE id = ?)", id).Scan(&exists); err != nil {
		return false, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not read the entry", err)
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO entries(id,meta,blob) VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET meta=excluded.meta, blob=excluded.blob", id, metaBlob, blob)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		return false, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not commit the write", err)
	}
	return exists == 0, nil
}

// sealMeta encrypts one meta plaintext with the meta key. The AAD binds
// the store and the row id, so a meta blob cannot be moved to another
// row or vault (design.md §17.4).
func (s *Store) sealMeta(id string, m *Meta) ([]byte, error) {
	plain, err := json.Marshal(m)
	if err != nil {
		return nil, ErrInvalidStore
	}
	defer keycrypto.WipeKey(plain)
	aad, err := keycrypto.MetaAAD(s.id, id)
	if err != nil {
		return nil, ErrInvalidStore
	}
	blob, err := keycrypto.SealBlob(s.metaKey, aad, plain)
	if err != nil {
		return nil, ErrInvalidStore
	}
	return blob, nil
}

// openMeta decrypts and validates one meta blob. Every failure here
// means the stored meta does not read as a meta this build understands —
// damage or a format it does not know — so it is ErrCorruptStore, never
// the caller's ref or key (design §17.7).
func (s *Store) openMeta(id string, blob []byte) (*Meta, error) {
	if len(blob) < 28 || len(blob) > maxMeta {
		return nil, ErrCorruptStore
	}
	aad, err := keycrypto.MetaAAD(s.id, id)
	if err != nil {
		return nil, classify(ErrCorruptStore, "", err)
	}
	plain, err := keycrypto.OpenBlob(s.metaKey, aad, blob)
	if err != nil {
		return nil, classify(ErrCorruptStore, "", err)
	}
	defer keycrypto.WipeKey(plain)
	var m Meta
	dec := json.NewDecoder(bytes.NewReader(plain))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, classify(ErrCorruptStore, "", err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, classify(ErrCorruptStore, "", err)
	}
	if (m.Type != "" && m.Type != "login") || (m.Type == "" && (m.Username != "" || m.URL != "")) {
		return nil, ErrCorruptStore
	}
	if m.V != 1 || !ValidRef(m.Ref) || m.Bytes < 0 || m.Bytes > maxValue || m.Masked == "" || !m.Policy.valid() {
		return nil, ErrCorruptStore
	}
	gotID, err := s.entryID(m.Ref)
	if err != nil || gotID != id {
		return nil, ErrCorruptStore
	}
	// Put forbids empty values. Zero bytes identifies the incomplete
	// meta produced by the first meta-capable version for legacy rows.
	m.Incomplete = m.Bytes == 0
	if m.Incomplete {
		m.UpdatedAt = 0
	}
	return &m, nil
}

// List returns every row's meta, sorted by ref. It never decrypts a
// secret. Rows from a pre-meta vault have no stored ref, so they are
// absent until Use(ref) backfills their meta or Put replaces them.
func (s *Store) List(ctx context.Context) ([]Meta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	rows, err := s.db.QueryContext(ctx, "SELECT substr(id,1,33), substr(meta,1,?) FROM entries WHERE meta IS NOT NULL", maxMeta+1)
	if err != nil {
		return nil, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not read the entries", err)
	}
	defer rows.Close()
	var out []Meta
	for rows.Next() {
		var id string
		var blob []byte
		if err := rows.Scan(&id, &blob); err != nil {
			return nil, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not read the entries", err)
		}
		m, err := s.openMeta(id, blob)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	if err := rows.Err(); err != nil {
		return nil, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not read the entries", err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, nil
}

// Stat returns one row's meta without decrypting the secret or writing
// the row. For a legacy row, Incomplete is true, Masked is "***", and
// Bytes and UpdatedAt are zero (unknown). Use or Put completes its meta.
func (s *Store) Stat(ctx context.Context, ref string) (*Meta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, ErrClosed
	}
	id, err := s.entryID(ref)
	if err != nil {
		// An invalid ref can have no row at all: reads still hash what
		// they are given, so it simply misses (design §6.1).
		return nil, ErrNotFound
	}
	var blob []byte
	err = s.db.QueryRowContext(ctx, "SELECT substr(meta,1,?) FROM entries WHERE id = ?", maxMeta+1, id).Scan(&blob)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not read the entry", err)
	}
	if blob != nil {
		return s.openMeta(id, blob)
	}
	return &Meta{
		V: 1, Ref: ref, Masked: "***", Incomplete: true,
		Policy: Policy{AllowedHosts: []string{}},
	}, nil
}

// Use decrypts only for the callback and wipes its buffer afterwards. A callback
// must not retain, log, or pass the bytes to an untrusted recipient. Close does
// not cancel a Use whose data has already been decrypted.
func (s *Store) Use(ctx context.Context, ref string, fn func([]byte) error) error {
	if fn == nil {
		return ErrInvalidStore
	}
	plain, m, err := s.read(ctx, ref)
	if err != nil {
		return err
	}
	defer keycrypto.WipeKey(plain)
	if err := ctx.Err(); err != nil {
		return err
	}
	if m != nil && m.Type == "login" {
		username, value, err := decodeLogin(plain, m)
		if err != nil {
			return err
		}
		defer keycrypto.WipeKey(username)
		defer keycrypto.WipeKey(value)
		return fn(value)
	}
	return fn(plain)
}

// UseLogin decrypts a structured login only for the callback.
func (s *Store) UseLogin(ctx context.Context, ref string, fn func(username, value []byte) error) error {
	if fn == nil {
		return ErrInvalidStore
	}
	plain, m, err := s.read(ctx, ref)
	if err != nil {
		return err
	}
	defer keycrypto.WipeKey(plain)
	if m == nil || m.Type != "login" {
		return ErrNotLogin
	}
	username, value, err := decodeLogin(plain, m)
	if err != nil {
		return err
	}
	defer keycrypto.WipeKey(username)
	defer keycrypto.WipeKey(value)
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(username, value)
}

// ErrNotLogin reports a request for login fields on an ordinary entry.
var ErrNotLogin = errors.New("local item is not a login")

// Version 2 stores base64-encoded byte fields. Version 1 is still read so
// vaults created by earlier development builds remain usable.
func encodeLogin(username string, value []byte) ([]byte, error) {
	const prefix = `{"v":2,"username":"`
	const middle = `","value":"`
	const suffix = `"}`
	size := len(prefix) + base64.StdEncoding.EncodedLen(len(username)) + len(middle) + base64.StdEncoding.EncodedLen(len(value)) + len(suffix)
	if size > maxValue {
		return nil, ErrInvalidValueSize
	}
	data := make([]byte, 0, size)
	data = append(data, prefix...)
	data = base64.StdEncoding.AppendEncode(data, []byte(username))
	data = append(data, middle...)
	data = base64.StdEncoding.AppendEncode(data, value)
	data = append(data, suffix...)
	return data, nil
}

func decodeLogin(plain []byte, m *Meta) ([]byte, []byte, error) {
	var header struct {
		V int `json:"v"`
	}
	if err := json.Unmarshal(plain, &header); err != nil || (header.V != 1 && header.V != 2) {
		return nil, nil, ErrCorruptStore
	}
	userField, err := secret.ExtractStringField(plain, "username")
	if err != nil {
		return nil, nil, ErrCorruptStore
	}
	defer userField.Destroy()
	valueField, err := secret.ExtractStringField(plain, "value")
	if err != nil {
		return nil, nil, ErrCorruptStore
	}
	defer valueField.Destroy()
	decode := func(field []byte) ([]byte, error) {
		if header.V == 1 {
			return append([]byte(nil), field...), nil
		}
		out := make([]byte, base64.StdEncoding.DecodedLen(len(field)))
		n, err := base64.StdEncoding.Strict().Decode(out, field)
		if err != nil {
			keycrypto.WipeKey(out)
			return nil, err
		}
		return out[:n], nil
	}
	username, err := decode(userField.Bytes())
	if err != nil {
		return nil, nil, ErrCorruptStore
	}
	value, err := decode(valueField.Bytes())
	if err != nil {
		keycrypto.WipeKey(username)
		return nil, nil, ErrCorruptStore
	}
	if !bytes.Equal(username, []byte(m.Username)) || len(value) == 0 || len(value) != m.Bytes || !utf8.Valid(username) || !utf8.Valid(value) {
		keycrypto.WipeKey(username)
		keycrypto.WipeKey(value)
		return nil, nil, ErrCorruptStore
	}
	return username, value, nil
}

func (s *Store) read(ctx context.Context, ref string) ([]byte, *Meta, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.db == nil {
		return nil, nil, ErrClosed
	}
	id, err := s.entryID(ref)
	if err != nil {
		return nil, nil, err
	}
	var blob, metaBlob []byte
	var blobLen int64
	if err = s.db.QueryRowContext(ctx, "SELECT substr(blob,1,?),length(blob),substr(meta,1,?) FROM entries WHERE id = ?", maxValue+29, maxMeta+1, id).Scan(&blob, &blobLen, &metaBlob); errors.Is(err, sql.ErrNoRows) {
		return nil, nil, ErrNotFound
	} else if err != nil {
		return nil, nil, sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not read the entry", err)
	}
	if blobLen < 28 || blobLen > maxValue+28 {
		// The stored ciphertext is outside the format's size bounds.
		return nil, nil, ErrCorruptStore
	}
	aad, err := keycrypto.SecretAAD(s.id, id)
	if err != nil {
		return nil, nil, classify(ErrInvalidStore, "", err)
	}
	plain, err := keycrypto.OpenBlob(s.key, aad, blob)
	if err != nil {
		// Opening proved the key against this vault, so a failure here is
		// the row, not the caller's key (design §17.7).
		return nil, nil, classify(ErrCorruptStore, "", err)
	}
	if err := s.backfillMeta(ctx, ref, id, blob, metaBlob, plain); err != nil {
		keycrypto.WipeKey(plain)
		return nil, nil, err
	}
	var m *Meta
	if metaBlob != nil {
		m, err = s.openMeta(id, metaBlob)
		// Preserve legacy Use behavior when metadata cannot be decoded.
		// Callers that require metadata, including the CLI, validate it first.
		if err != nil {
			m = nil
		}
	}
	return plain, m, nil
}

// backfillMeta runs only after an authorized secret read. The old format
// stored only HMAC refs, so it cannot be migrated without a caller's ref.
// Compare both ciphertexts before writing: a concurrent replacement or
// deletion must never receive metadata derived from the old value.
func (s *Store) backfillMeta(ctx context.Context, ref, id string, blob, oldMeta, plain []byte) error {
	if !ValidRef(ref) {
		return nil // legacy refs remain usable, but cannot enter the new index
	}
	m := &Meta{V: 1, Ref: ref, Policy: Policy{AllowedHosts: []string{}}}
	if oldMeta != nil {
		stored, err := s.openMeta(id, oldMeta)
		if err != nil || !stored.Incomplete {
			return nil // Use is independent of meta; only repair recognized legacy rows
		}
		m = stored
	}
	m.Masked, m.Bytes, m.UpdatedAt, m.Incomplete = Mask(plain), len(plain), 0, false
	sealed, err := s.sealMeta(id, m)
	if err != nil {
		return err
	}
	if len(sealed) > maxMeta {
		return ErrMetaTooLarge
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not start a transaction", err)
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, "UPDATE entries SET meta=? WHERE id=? AND blob=? AND meta IS ?", sealed, id, blob, oldMeta)
	if err != nil {
		return sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not backfill the meta", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not backfill the meta", err)
	}
	if n == 0 {
		return nil // another writer won; preserve its row and policy
	}
	res, err = tx.ExecContext(ctx, "UPDATE metadata SET writes=writes+1 WHERE writes < ?", writeCap)
	if err != nil {
		return writeBudgetError(ctx, tx, "writes < ?", []any{writeCap}, err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not count the write", err)
	}
	if affected != 1 {
		return writeBudgetError(ctx, tx, "writes < ?", []any{writeCap}, nil)
	}
	if err := tx.Commit(); err != nil {
		return sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not commit the meta backfill", err)
	}
	return nil
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
		return sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not delete the entry", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return sqlFailure(ctx, ErrInvalidStore, "invalid local vault: could not delete the entry", err)
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
	keycrypto.WipeKey(s.metaKey)
	s.key = nil
	s.indexKey = nil
	s.metaKey = nil
	return err
}
