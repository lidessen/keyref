package local

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func keyForTest() []byte { return bytes.Repeat([]byte{0x42}, 32) }
func pathForTest(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(dir, "vault.sqlite")
}

func TestLocalLifecycle(t *testing.T) {
	ctx := context.Background()
	path := pathForTest(t)
	key := keyForTest()
	if _, err := Open(path, key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("missing open: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("open created store: %v", err)
	}
	if _, err := Create(path, nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("missing key: %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("missing key touched path: %v", err)
	}
	s, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("store mode: %v %v", info, err)
	}
	if _, err := Create(path, key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("overwrite accepted: %v", err)
	}
	value := []byte("synthetic-plaintext-value-not-a-real-key")
	if err := s.Put(ctx, "synthetic-ref", value); err != nil {
		t.Fatal(err)
	}
	var observed []byte
	if err := s.Use(ctx, "synthetic-ref", func(data []byte) error {
		if !bytes.Equal(data, value) {
			t.Errorf("wrong value")
		}
		observed = data
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(observed, make([]byte, len(value))) {
		t.Fatal("callback buffer was not cleared")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "synthetic-ref", value); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed put: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range [][]byte{value, []byte("synthetic-ref"), key} {
		if bytes.Contains(raw, forbidden) {
			t.Fatal("plaintext in database")
		}
	}
	if _, err := Open(path, bytes.Repeat([]byte{0x43}, 32)); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("wrong key: %v", err)
	}
	s, err = Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Use(ctx, "synthetic-ref", func(data []byte) error {
		if !bytes.Equal(data, value) {
			t.Error("reopen lost value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.Delete(ctx, "synthetic-ref"); err != nil {
		t.Fatal(err)
	}
	if err := s.Use(ctx, "synthetic-ref", func([]byte) error { t.Error("deleted value delivered"); return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted value: %v", err)
	}
	if err := s.Delete(ctx, "synthetic-ref"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted twice: %v", err)
	}
}

func TestLocalPrivatePath(t *testing.T) {
	key := keyForTest()
	dir := t.TempDir()
	path := filepath.Join(dir, "vault")
	if _, err := Create("relative", key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("relative: %v", err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(path, key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("public directory: %v", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	_ = s.Close()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("public file: %v", err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link, key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("symlink: %v", err)
	}
	if _, err := Create(link, key); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("overwrite symlink: %v", err)
	}
}

func TestLocalAADDetectsSubstitution(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Put(ctx, "first", []byte("value-one")); err != nil {
		t.Fatal(err)
	}
	if err = s.Put(ctx, "second", []byte("value-two")); err != nil {
		t.Fatal(err)
	}
	first, _ := s.entryID("first")
	second, _ := s.entryID("second")
	var blob []byte
	if err = s.db.QueryRow("SELECT blob FROM entries WHERE id = ?", first).Scan(&blob); err != nil {
		t.Fatal(err)
	}
	if _, err = s.db.Exec("UPDATE entries SET blob = ? WHERE id = ?", blob, second); err != nil {
		t.Fatal(err)
	}
	if err = s.Use(ctx, "second", func([]byte) error { t.Error("substitution delivered plaintext"); return nil }); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("tamper: %v", err)
	}
}

func TestLocalConcurrentInstances(t *testing.T) {
	ctx := context.Background()
	path := pathForTest(t)
	key := keyForTest()
	a, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	var wg sync.WaitGroup
	errs := make(chan error, 40)
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 != 0 {
				s = b
			}
			errs <- s.Put(ctx, fmt.Sprintf("ref-%d", i), []byte(fmt.Sprintf("value-%d", i)))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent put: %v", err)
		}
	}
	for i := 0; i < 40; i++ {
		i := i
		if err := a.Use(ctx, fmt.Sprintf("ref-%d", i), func(b []byte) error {
			if string(b) != fmt.Sprintf("value-%d", i) {
				t.Errorf("wrong value %d", i)
			}
			return nil
		}); err != nil {
			t.Errorf("read %d: %v", i, err)
		}
	}
}

func TestLocalInputAndCancellation(t *testing.T) {
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ctx := context.Background()
	for _, ref := range []string{"", string([]byte{'x', 0, 'y'}), string(bytes.Repeat([]byte{'x'}, 513))} {
		if err = s.Put(ctx, ref, []byte("x")); err == nil {
			t.Error("accepted invalid ref")
		}
	}
	for _, v := range [][]byte{nil, bytes.Repeat([]byte{'x'}, maxValue+1)} {
		if err = s.Put(ctx, "valid", v); err == nil {
			t.Error("accepted invalid value")
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err = s.Put(cancelled, "cancelled", []byte("x")); err == nil {
		t.Error("cancelled write succeeded")
	}
	if err = s.Put(ctx, "existing", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	if err = s.Use(cancelled, "existing", func([]byte) error { t.Error("cancelled read delivered plaintext"); return nil }); err == nil {
		t.Error("cancelled read succeeded")
	}
	if err = s.Use(ctx, "cancelled", func([]byte) error { return nil }); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cancelled write persisted: %v", err)
	}
	if err = s.Use(ctx, "valid", nil); err == nil {
		t.Error("nil callback accepted")
	}
}

func TestLocalCallbackFailureAndPanicWipe(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Put(ctx, "ref", []byte("synthetic-value")); err != nil {
		t.Fatal(err)
	}
	sentinel := errors.New("callback failure")
	var data []byte
	if err := s.Use(ctx, "ref", func(b []byte) error { data = b; return sentinel }); !errors.Is(err, sentinel) {
		t.Fatalf("callback failure: %v", err)
	}
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("callback failure did not clear plaintext")
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("callback panic was swallowed")
			}
		}()
		_ = s.Use(ctx, "ref", func(b []byte) error { data = b; panic("synthetic panic") })
	}()
	if !bytes.Equal(data, make([]byte, len(data))) {
		t.Fatal("panic did not clear plaintext")
	}
}

func TestLocalConcurrentSameRefRemainsWhole(t *testing.T) {
	ctx := context.Background()
	path := pathForTest(t)
	a, err := Create(path, keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Open(path, keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	const writes = 32
	var wg sync.WaitGroup
	errs := make(chan error, writes)
	for i := 0; i < writes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := a
			if i%2 != 0 {
				s = b
			}
			errs <- s.Put(ctx, "same-ref", []byte(fmt.Sprintf("value-%02d", i)))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("put: %v", err)
		}
	}
	if err := a.Use(ctx, "same-ref", func(value []byte) error {
		matched := false
		for i := 0; i < writes; i++ {
			if string(value) == fmt.Sprintf("value-%02d", i) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("concurrent value is not a complete write")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestLocalCallbackMayCloseStore(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "ref", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		done <- s.Use(ctx, "ref", func(value []byte) error {
			if string(value) != "synthetic" {
				return errors.New("unexpected value")
			}
			return s.Close()
		})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("callback Close deadlocked")
	}
	if err := s.Use(ctx, "ref", func([]byte) error { t.Error("closed store delivered plaintext"); return nil }); !errors.Is(err, ErrClosed) {
		t.Fatalf("closed read: %v", err)
	}
}

func TestLocalOversizedBlobRejected(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Put(ctx, "ref", []byte("synthetic")); err != nil {
		t.Fatal(err)
	}
	id, err := s.entryID("ref")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE entries SET blob=zeroblob(?) WHERE id=?", maxValue+29, id); err != nil {
		t.Fatal(err)
	}
	if err := s.Use(ctx, "ref", func([]byte) error { t.Error("oversized blob delivered plaintext"); return nil }); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("oversized blob: %v", err)
	}
}

func TestLocalWriteLimitPreservesExistingValue(t *testing.T) {
	ctx := context.Background()
	s, err := Create(pathForTest(t), keyForTest())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Put(ctx, "ref", []byte("original")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE metadata SET writes=4294967295"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put(ctx, "ref", []byte("replacement")); !errors.Is(err, ErrInvalidStore) {
		t.Fatalf("write at limit: %v", err)
	}
	if err := s.Use(ctx, "ref", func(value []byte) error {
		if string(value) != "original" {
			t.Error("rejected write modified value")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var count int64
	if err := s.db.QueryRow("SELECT writes FROM metadata").Scan(&count); err != nil || count != 4294967295 {
		t.Fatalf("counter: %d, %v", count, err)
	}
}
