package local

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
)

func legacyStoreForTest(t *testing.T) (*Store, string) {
	t.Helper()
	path := pathForTest(t)
	s, err := Create(path, keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	if _, err := s.Put(context.Background(), "legacy", []byte("synthetic-value"), PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("ALTER TABLE entries DROP COLUMN meta"); err != nil {
		t.Fatal(err)
	}
	return s, path
}

func TestLegacyStatIsReadOnly(t *testing.T) {
	s, _ := legacyStoreForTest(t)
	if err := ensureMetaColumn(s.db); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("PRAGMA query_only=ON"); err != nil {
		t.Fatal(err)
	}
	m, err := s.Stat(context.Background(), "legacy")
	if err != nil || !m.Incomplete || m.Bytes != 0 || m.UpdatedAt != 0 || m.Masked != "***" {
		t.Fatalf("read-only legacy Stat: %+v, %v", m, err)
	}
	var missing bool
	if err := s.db.QueryRow("SELECT meta IS NULL FROM entries").Scan(&missing); err != nil || !missing {
		t.Fatalf("Stat wrote a legacy meta: missing=%v err=%v", missing, err)
	}
}

func TestLegacyConcurrentOpen(t *testing.T) {
	s, path := legacyStoreForTest(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	const workers = 16
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			store, err := Open(path, keyForTest())
			if err != nil {
				t.Errorf("concurrent migration open: %v", err)
				return
			}
			defer store.Close()
			m, err := store.Stat(context.Background(), "legacy")
			if err != nil || !m.Incomplete {
				t.Errorf("legacy row after schema migration: %+v, %v", m, err)
			}
		}()
	}
	close(start)
	wg.Wait()
}

func TestLegacyBackfillDoesNotOverwriteNewerRow(t *testing.T) {
	for _, action := range []string{"replace", "delete"} {
		t.Run(action, func(t *testing.T) {
			s, path := legacyStoreForTest(t)
			if err := ensureMetaColumn(s.db); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			id, err := s.entryID("legacy")
			if err != nil {
				t.Fatal(err)
			}
			var oldBlob []byte
			if err := s.db.QueryRow("SELECT blob FROM entries WHERE id=?", id).Scan(&oldBlob); err != nil {
				t.Fatal(err)
			}
			other, err := Open(path, keyForTest())
			if err != nil {
				t.Fatal(err)
			}
			defer other.Close()
			if action == "delete" {
				err = other.Delete(ctx, "legacy")
			} else {
				_, err = other.Put(ctx, "legacy", []byte("replacement-value"), PutOptions{AllowCommands: []string{"curl"}})
			}
			if err != nil {
				t.Fatal(err)
			}
			// Resume a migration after another process changed its snapshot.
			if err := s.backfillMeta(ctx, "legacy", id, oldBlob, nil, []byte("synthetic-value")); err != nil {
				t.Fatal(err)
			}
			m, err := s.Stat(ctx, "legacy")
			if action == "delete" {
				if !errors.Is(err, ErrNotFound) || m != nil {
					t.Fatalf("backfill resurrected a deleted row: %+v, %v", m, err)
				}
			} else if err != nil || m.Incomplete || m.Bytes != len("replacement-value") || len(m.Policy.AllowCommands) != 1 || m.Policy.AllowCommands[0] != "curl" {
				t.Fatalf("backfill overwrote newer metadata: %+v, %v", m, err)
			}
		})
	}
}

func TestLegacyBackfillRepairsPersistedIncompleteMeta(t *testing.T) {
	s, _ := legacyStoreForTest(t)
	if err := ensureMetaColumn(s.db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, _ := s.entryID("legacy")
	incomplete := &Meta{V: 1, Ref: "legacy", Masked: "***", UpdatedAt: 1,
		Policy: Policy{AllowCommands: []string{"curl"}}}
	sealed, err := s.sealMeta(id, incomplete)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", sealed, id); err != nil {
		t.Fatal(err)
	}
	before, err := s.Stat(ctx, "legacy")
	if err != nil || !before.Incomplete || before.UpdatedAt != 0 {
		t.Fatalf("incomplete meta not identified: %+v, %v", before, err)
	}
	if err := s.Use(ctx, "legacy", func(value []byte) error {
		if !bytes.Equal(value, []byte("synthetic-value")) {
			t.Error("migration changed the secret")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m, err := s.Stat(ctx, "legacy")
	if err != nil || m.Incomplete || m.Bytes != len("synthetic-value") || m.Masked != Mask([]byte("synthetic-value")) || m.UpdatedAt != 0 || len(m.Policy.AllowCommands) != 1 || m.Policy.AllowCommands[0] != "curl" {
		t.Fatalf("repaired meta = %+v, %v", m, err)
	}
}

func TestLegacyBackfillHonorsWriteLimit(t *testing.T) {
	s, _ := legacyStoreForTest(t)
	if err := ensureMetaColumn(s.db); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE metadata SET writes=4294967295"); err != nil {
		t.Fatal(err)
	}
	err := s.Use(context.Background(), "legacy", func([]byte) error {
		t.Error("failed migration delivered plaintext")
		return nil
	})
	if !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("migration at write limit: %v", err)
	}
	var missing bool
	if err := s.db.QueryRow("SELECT meta IS NULL FROM entries").Scan(&missing); err != nil || !missing {
		t.Fatalf("failed migration changed the row: missing=%v err=%v", missing, err)
	}
}
