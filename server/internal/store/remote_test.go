package store

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
)

func TestRemoteStateAcrossStoreHandles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "shared.db")
	testRemoteState(t, "sqlite", "file:"+path+"?_pragma=busy_timeout(10000)")
}

func testRemoteState(t *testing.T, driver, dsn string) {
	t.Helper()
	ctx := context.Background()
	key := filepath.Base(filepath.Dir(t.TempDir()))
	open := func() *Store {
		db, err := sql.Open(driver, dsn)
		if err != nil {
			t.Fatal("open shared database")
		}
		t.Cleanup(func() { db.Close() })
		db.SetMaxOpenConns(1)
		st := &Store{db: db, remote: true}
		if err := st.initRemote(ctx); err != nil {
			t.Fatalf("initialize shared database: %v", err)
		}
		return st
	}
	first, second := open(), open()
	if err := first.HealthzWriteProbe(ctx); err != nil {
		t.Fatal(err)
	}
	if err := first.PutChallenge(ctx, key+":session", []byte("challenge"), 0, 100); err != nil {
		t.Fatal(err)
	}
	value, err := second.TakeChallenge(ctx, key+":session", 50)
	if err != nil || string(value) != "challenge" {
		t.Fatalf("read challenge from second store: %v", err)
	}
	if _, err := first.TakeChallenge(ctx, key+":session", 50); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected consumed challenge to be missing, got %v", err)
	}
	checkRate := func(st *Store, now int64, want bool) {
		t.Helper()
		got, err := st.AllowRateEvent(ctx, key+":poll", now, 1, 100)
		if err != nil || got != want {
			t.Fatalf("rate decision = %t, %v; want %t", got, err, want)
		}
	}
	checkRate(first, 10, true)
	checkRate(second, 109, false)
	checkRate(second, 110, true)
}
