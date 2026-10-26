// Package store persists the CLI's local cache: server ciphertext,
// revisions, verified signatures and the sync cursor
// (design.md §6.5). The cache holds only end-to-end ciphertext — never
// plaintext, never unwrapped keys (design §15) — so it gets no second
// encryption layer; same-user readers are the B1/B2 boundary, other Unix
// users are kept out by directory permissions.
//
// The database file is created with mode 0600 inside a 0700 directory.
// Items are cached without vault_wrapped_* columns: the server never
// delivers those to CLI devices (docs/protocol.md §8.3), and the CLI
// cannot rebuild item transcripts anyway — its integrity guarantees are
// the owner-signed grants, the AEAD tags and revision monotonicity.
package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite" // pure-Go SQLite driver, CGO-free (protocol §2.3)

	"github.com/lidessen/keyref/proto/wire"
)

// CacheFileName is the cache database file name inside the data
// directory (design.md §6.5).
const CacheFileName = "cache.sqlite"

// Store is the local cache database.
type Store struct {
	db   *sql.DB
	path string
}

// Open creates or opens the cache database inside dir, enforcing the
// permission model of design.md §6.5: directory 0700, file 0600.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, fmt.Errorf("store: data directory required")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: create data directory: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("store: enforce directory mode: %w", err)
	}
	path := filepath.Join(dir, CacheFileName)
	// A single write connection avoids SQLITE_BUSY against ourselves and
	// matches the server's single-writer shape (design §10.3).
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: open cache: %w", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec("PRAGMA busy_timeout = 10000"); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: busy timeout: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open cache: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: enforce cache file mode: %w", err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: migrate cache: %w", err)
	}
	return &Store{db: db, path: path}, nil
}

func migrate(db *sql.DB) error {
	const schema = `
CREATE TABLE IF NOT EXISTS items (
  item_id           TEXT PRIMARY KEY,
  revision          INTEGER NOT NULL,
  tombstone         INTEGER NOT NULL DEFAULT 0,
  meta_ciphertext   BLOB NOT NULL,
  secret_ciphertext BLOB,
  writer_device_id  TEXT NOT NULL,
  signature         BLOB NOT NULL,
  updated_at        INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
  item_id     TEXT NOT NULL,
  kind        TEXT NOT NULL,
  device_id   TEXT NOT NULL,
  hpke_enc    BLOB NOT NULL DEFAULT x'',
  wrapped_key BLOB NOT NULL DEFAULT x'',
  expires_at  INTEGER NOT NULL DEFAULT 0,
  revision    INTEGER NOT NULL,
  signature   BLOB NOT NULL DEFAULT x'',
  PRIMARY KEY (item_id, kind)
);
CREATE TABLE IF NOT EXISTS kv (
  k TEXT PRIMARY KEY,
  v BLOB NOT NULL
);`
	_, err := db.Exec(schema)
	return err
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// Path returns the cache database path (test helper).
func (s *Store) Path() string { return s.path }

// PutItem upserts an item row. Caller-checked revision monotonicity: the
// sync layer refuses to apply rows older than what it has seen
// (design.md §6.2).
func (s *Store) PutItem(it *wire.ItemData) error {
	if err := it.Validate(); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO items (item_id, revision, tombstone, meta_ciphertext, secret_ciphertext, writer_device_id, signature, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(item_id) DO UPDATE SET
		   revision = excluded.revision,
		   tombstone = excluded.tombstone,
		   meta_ciphertext = excluded.meta_ciphertext,
		   secret_ciphertext = excluded.secret_ciphertext,
		   writer_device_id = excluded.writer_device_id,
		   signature = excluded.signature,
		   updated_at = excluded.updated_at`,
		it.ItemID, it.Revision, boolToInt(it.Tombstone),
		it.MetaCiphertext, it.SecretCiphertext, it.WriterDeviceID,
		it.Signature, it.UpdatedAt)
	if err != nil {
		return fmt.Errorf("store: put item: %w", err)
	}
	return nil
}

// GetItem returns the cached item row for itemID.
func (s *Store) GetItem(itemID string) (*wire.ItemData, bool, error) {
	row := s.db.QueryRow(
		`SELECT item_id, revision, tombstone, meta_ciphertext, secret_ciphertext, writer_device_id, signature, updated_at
		 FROM items WHERE item_id = ?`, itemID)
	var it wire.ItemData
	var tombstone int
	err := row.Scan(&it.ItemID, &it.Revision, &tombstone, &it.MetaCiphertext,
		&it.SecretCiphertext, &it.WriterDeviceID, &it.Signature, &it.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("store: get item: %w", err)
	}
	it.Tombstone = tombstone != 0
	return &it, true, nil
}

// ItemIDs returns all cached item ids (unordered).
func (s *Store) ItemIDs() ([]string, error) {
	rows, err := s.db.Query(`SELECT item_id FROM items`)
	if err != nil {
		return nil, fmt.Errorf("store: list items: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store: scan item id: %w", err)
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

// DeleteItem removes an item row and its grants — the local effect of a
// tombstone change (design.md §6.3: item tombstone deletes all grants).
func (s *Store) DeleteItem(itemID string) error {
	if _, err := s.db.Exec(`DELETE FROM items WHERE item_id = ?`, itemID); err != nil {
		return fmt.Errorf("store: delete item: %w", err)
	}
	if _, err := s.db.Exec(`DELETE FROM grants WHERE item_id = ?`, itemID); err != nil {
		return fmt.Errorf("store: delete item grants: %w", err)
	}
	return nil
}

// PutGrant upserts a grant row for this device (the cache is
// single-device, so device_id is stored for transcript rebuilds only).
func (s *Store) PutGrant(g *wire.GrantData) error {
	if err := g.Validate(); err != nil {
		return err
	}
	_, err := s.db.Exec(
		`INSERT INTO grants (item_id, kind, device_id, hpke_enc, wrapped_key, expires_at, revision, signature)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(item_id, kind) DO UPDATE SET
		   device_id = excluded.device_id,
		   hpke_enc = excluded.hpke_enc,
		   wrapped_key = excluded.wrapped_key,
		   expires_at = excluded.expires_at,
		   revision = excluded.revision,
		   signature = excluded.signature`,
		g.ItemID, g.Kind, g.DeviceID, g.HPKEEnc, g.WrappedKey, g.ExpiresAt, g.Revision, g.Signature)
	if err != nil {
		return fmt.Errorf("store: put grant: %w", err)
	}
	return nil
}

// DeleteGrant removes a grant row — the local effect of a grant deletion
// or item tombstone change (design.md §6.3, §6.5).
func (s *Store) DeleteGrant(itemID, kind string) error {
	if _, err := s.db.Exec(`DELETE FROM grants WHERE item_id = ? AND kind = ?`, itemID, kind); err != nil {
		return fmt.Errorf("store: delete grant: %w", err)
	}
	return nil
}

// ClearGrants removes every cached grant row — the local effect of a
// fresh pairing that may point at a new vault (design.md §8.5
// re-pairing; §6.5 local cleanup).
func (s *Store) ClearGrants() error {
	if _, err := s.db.Exec(`DELETE FROM grants`); err != nil {
		return fmt.Errorf("store: clear grants: %w", err)
	}
	return nil
}

// ClearItems removes every cached item row — same re-pairing rationale
// as ClearGrants: rows of a previous vault must never survive into the
// new one (equal revisions would shadow the new ciphertext).
func (s *Store) ClearItems() error {
	if _, err := s.db.Exec(`DELETE FROM items`); err != nil {
		return fmt.Errorf("store: clear items: %w", err)
	}
	return nil
}

// Grants returns all cached grant rows.
func (s *Store) Grants() ([]wire.GrantData, error) {
	rows, err := s.db.Query(
		`SELECT item_id, kind, device_id, hpke_enc, wrapped_key, expires_at, revision, signature FROM grants`)
	if err != nil {
		return nil, fmt.Errorf("store: list grants: %w", err)
	}
	defer rows.Close()
	var out []wire.GrantData
	for rows.Next() {
		var g wire.GrantData
		if err := rows.Scan(&g.ItemID, &g.Kind, &g.DeviceID, &g.HPKEEnc, &g.WrappedKey,
			&g.ExpiresAt, &g.Revision, &g.Signature); err != nil {
			return nil, fmt.Errorf("store: scan grant: %w", err)
		}
		out = append(out, g)
	}
	return out, rows.Err()
}

// SetKV stores a small binary value under key (cursor, vault_id,
// device_id, pinned owner key, directory state).
func (s *Store) SetKV(key string, value []byte) error {
	_, err := s.db.Exec(`INSERT INTO kv (k, v) VALUES (?, ?)
		ON CONFLICT(k) DO UPDATE SET v = excluded.v`, key, value)
	if err != nil {
		return fmt.Errorf("store: set kv: %w", err)
	}
	return nil
}

// GetKV returns the value stored under key.
func (s *Store) GetKV(key string) ([]byte, bool, error) {
	var v []byte
	err := s.db.QueryRow(`SELECT v FROM kv WHERE k = ?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("store: get kv: %w", err)
	}
	return v, true, nil
}

// DeleteKV removes a kv row. Clearing state (session token, cursor)
// must go through this — SetKV with a nil value violates the NOT NULL
// constraint of the v column.
func (s *Store) DeleteKV(key string) error {
	if _, err := s.db.Exec(`DELETE FROM kv WHERE k = ?`, key); err != nil {
		return fmt.Errorf("store: delete kv: %w", err)
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
