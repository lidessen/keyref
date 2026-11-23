package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

// initRemote installs server-side state shared by all function instances.
func (s *Store) initRemote(ctx context.Context) error {
	for _, stmt := range []string{
		`CREATE TABLE IF NOT EXISTS keyref_runtime (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)`,
		`INSERT INTO keyref_runtime VALUES (1, 0) ON CONFLICT (id) DO NOTHING`,
		`CREATE TABLE IF NOT EXISTS keyref_challenges (key TEXT PRIMARY KEY, value BLOB NOT NULL, expires INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS keyref_challenges_expiry ON keyref_challenges (expires)`,
		`CREATE TABLE IF NOT EXISTS keyref_rate_events (key TEXT NOT NULL, expires INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS keyref_rate_events_key ON keyref_rate_events (key, expires)`,
		`CREATE INDEX IF NOT EXISTS keyref_rate_events_expiry ON keyref_rate_events (expires)`,
	} {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		var version int
		if err := tx.QueryRowContext(ctx, "SELECT version FROM keyref_runtime WHERE id = 1").Scan(&version); err != nil {
			return err
		}
		if version > SchemaVersion {
			return fmt.Errorf("store: unsupported remote schema version %d", version)
		}
		for _, m := range migrations {
			if m.version <= version {
				continue
			}
			for _, stmt := range m.stmts {
				if _, err := tx.ExecContext(ctx, stmt); err != nil {
					return err
				}
			}
		}
		_, err := tx.ExecContext(ctx, "UPDATE keyref_runtime SET version = ? WHERE id = 1", SchemaVersion)
		return err
	})
}

// PutChallenge replaces the pending challenge for a scoped key.
func (s *Store) PutChallenge(ctx context.Context, key string, value []byte, now, expires int64) error {
	return s.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM keyref_challenges WHERE expires < ?", now); err != nil {
			return err
		}
		_, err := tx.ExecContext(ctx, `INSERT INTO keyref_challenges VALUES (?, ?, ?)
			ON CONFLICT (key) DO UPDATE SET value = excluded.value, expires = excluded.expires`, key, value, expires)
		return err
	})
}

// TakeChallenge consumes a challenge even if the caller subsequently fails signature verification.
func (s *Store) TakeChallenge(ctx context.Context, key string, now int64) ([]byte, error) {
	var value []byte
	var expires int64
	err := s.db.QueryRowContext(ctx, "DELETE FROM keyref_challenges WHERE key = ? RETURNING value, expires", key).Scan(&value, &expires)
	if errors.Is(err, sql.ErrNoRows) || (err == nil && expires < now) {
		return nil, ErrNotFound
	}
	return value, err
}

// HasChallenge reports whether an issued challenge remains valid.
func (s *Store) HasChallenge(ctx context.Context, key string, now int64) (bool, error) {
	var found bool
	err := s.db.QueryRowContext(ctx, "SELECT EXISTS (SELECT 1 FROM keyref_challenges WHERE key = ? AND expires >= ?)", key, now).Scan(&found)
	return found, err
}

// AllowRateEvent atomically applies the same sliding window across function instances.
func (s *Store) AllowRateEvent(ctx context.Context, key string, now, max, window int64) (bool, error) {
	var allowed bool
	err := s.WithTx(ctx, func(tx *sql.Tx) error {
		if _, err := tx.ExecContext(ctx, "DELETE FROM keyref_rate_events WHERE expires <= ?", now); err != nil {
			return err
		}
		res, err := tx.ExecContext(ctx, `INSERT INTO keyref_rate_events SELECT ?, ?
			WHERE (SELECT COUNT(*) FROM keyref_rate_events WHERE key = ?) < ?`, key, now+window, key, max)
		if err != nil {
			return err
		}
		count, err := res.RowsAffected()
		allowed = count == 1
		return err
	})
	return allowed, err
}
