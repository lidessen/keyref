package local

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestErrorsAreDistinguishable pins design §17.7: an embedder can tell
// the failures apart with errors.Is, a classified error prints only its
// safe text while the underlying cause stays reachable through Unwrap,
// and a cancelled context comes back as itself instead of being folded
// into a vault error.
func TestErrorsAreDistinguishable(t *testing.T) {
	ctx := context.Background()
	key := keyForTest()
	otherKey := bytes.Repeat([]byte{0x43}, 32)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "vault.sqlite")

	// The vault does not exist.
	_, err := Open(path, key)
	if !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("open of a missing vault = %v, want %v", err, ErrStoreNotFound)
	}
	if err.Error() != ErrStoreNotFound.Error() {
		t.Fatalf("missing vault text = %q, want the fixed sentinel", err.Error())
	}

	s, err := Create(path, key)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	// The vault already exists.
	if _, err := Create(path, key); !errors.Is(err, ErrStoreExists) || errors.Is(err, ErrCorruptStore) {
		t.Fatalf("second create = %v, want %v and not %v", err, ErrStoreExists, ErrCorruptStore)
	}

	// The directory permissions are insecure.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, key); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("open in a public directory = %v, want %v", err, ErrInsecurePermissions)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// The vault file's own mode carries the same classification.
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path, key); !errors.Is(err, ErrInsecurePermissions) {
		t.Fatalf("open of a public vault file = %v, want %v", err, ErrInsecurePermissions)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}

	// The ref is outside the grammar.
	if _, err := s.Put(ctx, "Not-A-Ref", []byte("value"), PutOptions{}); !errors.Is(err, ErrInvalidRef) {
		t.Fatalf("put with an invalid ref = %v, want %v", err, ErrInvalidRef)
	}

	// The value size is outside the limit.
	if _, err := s.Put(ctx, "tok", nil, PutOptions{}); !errors.Is(err, ErrInvalidValueSize) || errors.Is(err, ErrInvalidStore) {
		t.Fatalf("put of an empty value = %v, want %v and not %v", err, ErrInvalidValueSize, ErrInvalidStore)
	}
	if _, err := s.Put(ctx, "tok", make([]byte, maxValue+1), PutOptions{}); !errors.Is(err, ErrInvalidValueSize) {
		t.Fatalf("put of an oversized value = %v, want %v", err, ErrInvalidValueSize)
	}

	// A wrong key is about the key, never about the vault's contents.
	other, err := Open(path, otherKey)
	if other != nil {
		other.Close()
	}
	if !errors.Is(err, ErrInvalidKey) || errors.Is(err, ErrCorruptStore) {
		t.Fatalf("open with the wrong key = %v, want %v and not %v", err, ErrInvalidKey, ErrCorruptStore)
	}
	if err.Error() != ErrInvalidKey.Error() {
		t.Fatalf("wrong key text = %q, want the fixed sentinel", err.Error())
	}

	// The entry does not exist.
	if err := s.Delete(ctx, "nope"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("delete of an unknown ref = %v, want %v", err, ErrNotFound)
	}

	if _, err := s.Put(ctx, "tok", []byte("sk-abcdefghijklmnop"), PutOptions{}); err != nil {
		t.Fatal(err)
	}

	// The write budget is spent, distinct from a corrupt vault.
	if _, err := s.db.Exec("UPDATE metadata SET writes=?", writeCap); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Put(ctx, "tok", []byte("replacement-value"), PutOptions{}); !errors.Is(err, ErrWriteLimit) {
		t.Fatalf("put at the write cap = %v, want %v", err, ErrWriteLimit)
	}
	if err.Error() != ErrWriteLimit.Error() {
		t.Fatalf("write limit text = %q, want the fixed sentinel", err.Error())
	}
	// The rejected write left the row alone.
	if m, err := s.Stat(ctx, "tok"); err != nil || m.Masked != Mask([]byte("sk-abcdefghijklmnop")) {
		t.Fatalf("stat after a refused write = %+v, %v", m, err)
	}

	// A corrupt vault is about the row's contents, reported with the fixed
	// sentinel text: neither the ref nor the key of the caller.
	id, err := s.entryID("tok")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.db.Exec("UPDATE entries SET meta=? WHERE id=?", make([]byte, 32), id); err != nil {
		t.Fatal(err)
	}
	_, err = s.Stat(ctx, "tok")
	if !errors.Is(err, ErrCorruptStore) || errors.Is(err, ErrInvalidKey) {
		t.Fatalf("stat of a damaged meta = %v, want %v and not %v", err, ErrCorruptStore, ErrInvalidKey)
	}
	if err.Error() != ErrCorruptStore.Error() {
		t.Fatalf("damaged meta text = %q, want the fixed sentinel", err.Error())
	}

	// Context cancellation and timeout come back unchanged.
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Put(cancelled, "more", []byte("value"), PutOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("put with a cancelled context = %v, want context.Canceled", err)
	} else if errors.Is(err, ErrInvalidStore) || errors.Is(err, ErrCorruptStore) || errors.Is(err, ErrWriteLimit) {
		t.Fatalf("a cancelled context was folded into %v", err)
	}

	// The underlying cause stays reachable through Unwrap but is never
	// printed.
	missing := filepath.Join(dir, "absent", "vault.sqlite")
	_, err = Open(missing, key)
	if !errors.Is(err, ErrStoreNotFound) {
		t.Fatalf("open below a missing directory = %v, want %v", err, ErrStoreNotFound)
	}
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) {
		t.Fatalf("the underlying cause is not reachable through Unwrap: %v", err)
	}
	if strings.Contains(err.Error(), pathErr.Path) || strings.Contains(err.Error(), pathErr.Err.Error()) {
		t.Fatalf("the message leaks the cause: %q", err.Error())
	}
}
