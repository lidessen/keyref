// Package store implements the keyref-server storage layer: a single
// SQLite database file in WAL mode (design §6.3, §10.2) holding only
// ciphertexts, public keys, authorization edges and counters.
//
// The server never stores plaintext secrets, item names or refs. Errors
// returned from this package must therefore never include row contents,
// only identifiers and column names (design §15).
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // registers the "sqlite" driver, pure Go

	"github.com/lidessen/keyref/proto/wire"
)

// DBFileName is the name of the database file inside the data directory.
const DBFileName = "keyref.db"

// Store wraps the SQLite database handle.
type Store struct {
	db *sql.DB
}

// Open opens the SQLite database at path (creating parent directories
// with 0700 and applying pending migrations), and verifies the database
// ends up in WAL mode.
func Open(ctx context.Context, path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("store: database path is empty")
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("store: create data directory: %w", err)
		}
	}
	// modernc.org/sqlite accepts per-connection PRAGMAs through the DSN;
	// every pooled connection gets busy_timeout, and journal_mode=WAL is
	// a persistent property of the database file. _txlock=immediate makes
	// every transaction take the SQLite write lock at BEGIN, so a
	// read-check-write sequence inside one transaction can never race
	// with a concurrent writer.
	dsn := "file:" + filepath.ToSlash(path) + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open sqlite: %w", err)
	}
	// One connection total: the deployment model is a single SQLite
	// writer (design §6.3, §10.2). It also serializes the audit-seq
	// allocation and every revision guard below.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	s := &Store{db: db}
	if err := s.Migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	var mode string
	if err := db.QueryRowContext(ctx, "PRAGMA journal_mode").Scan(&mode); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: read journal_mode: %w", err)
	}
	if !strings.EqualFold(mode, "wal") {
		db.Close()
		return nil, fmt.Errorf("store: journal_mode is %q, want wal", mode)
	}
	return s, nil
}

// Close closes the database handle.
func (s *Store) Close() error { return s.db.Close() }

// DB exposes the underlying handle so higher layers can run
// transactions that combine row writes with change-log appends.
func (s *Store) DB() *sql.DB { return s.db }

// AppendChange appends a row to the changes log and returns its
// autoincremented seq. entityID must be a typed entity_id string
// (wire.ParseEntityID) whose prefix matches entity.
func (s *Store) AppendChange(ctx context.Context, vaultID, entity, entityID string, createdAtMs int64) (int64, error) {
	if !wire.ValidID(vaultID) {
		return 0, fmt.Errorf("store: vault_id must be 32 lowercase hex characters")
	}
	kind, _, err := wire.ParseEntityID(entityID)
	if err != nil {
		return 0, fmt.Errorf("store: invalid entity_id: %w", err)
	}
	if kind != entity {
		return 0, fmt.Errorf("store: entity does not match entity_id prefix")
	}
	res, err := s.db.ExecContext(ctx,
		"INSERT INTO changes (vault_id, entity, entity_id, created_at) VALUES (?, ?, ?, ?)",
		vaultID, entity, entityID, createdAtMs)
	if err != nil {
		return 0, fmt.Errorf("store: append change: %w", err)
	}
	seq, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store: append change: last insert id: %w", err)
	}
	return seq, nil
}

// Backup writes a consistent online snapshot of the database to out via
// VACUUM INTO, which is safe under WAL mode (design §10.4, §12.3). It
// fails if out already exists, and returns the number of bytes written.
// Never copy the hot database file instead of using this.
func (s *Store) Backup(ctx context.Context, out string) (int64, error) {
	if out == "" {
		return 0, errors.New("store: backup path is empty")
	}
	if _, err := os.Stat(out); err == nil {
		return 0, errors.New("store: backup target already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, fmt.Errorf("store: stat backup target: %w", err)
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return 0, fmt.Errorf("store: backup path: %w", err)
	}
	if dir := filepath.Dir(abs); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return 0, fmt.Errorf("store: create backup directory: %w", err)
		}
	}
	stmt := "VACUUM INTO " + quoteSQLString(abs)
	if _, err := s.db.ExecContext(ctx, stmt); err != nil {
		return 0, fmt.Errorf("store: vacuum into: %w", err)
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return 0, fmt.Errorf("store: stat backup result: %w", err)
	}
	return fi.Size(), nil
}

// quoteSQLString quotes a path as a SQLite string literal.
func quoteSQLString(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "''") + "'"
}
