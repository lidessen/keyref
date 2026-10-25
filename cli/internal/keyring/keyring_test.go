package keyring

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestDirStoreRoundtrip(t *testing.T) {
	base, err := os.MkdirTemp("", "keyring-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	st, err := NewDirStore(filepath.Join(base, "secrets"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := st.Get("keyref", "device-hpke-x25519"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get on empty store: %v, want ErrNotFound", err)
	}
	if err := st.Set("keyref", "device-hpke-x25519", "a2V5LW1hdGVyaWFs"); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("keyref", "device-hpke-x25519")
	if err != nil || got != "a2V5LW1hdGVyaWFs" {
		t.Fatalf("get: %q %v", got, err)
	}
	if err := st.Set("keyref", "device-sign-ed25519", "c2lnbg=="); err != nil {
		t.Fatal(err)
	}
	if err := st.Delete("keyref", "device-hpke-x25519"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get("keyref", "device-hpke-x25519"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("get after delete: %v, want ErrNotFound", err)
	}
	if err := st.Delete("keyref", "device-hpke-x25519"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("double delete: %v, want ErrNotFound", err)
	}
}

// TestDirStorePermissions pins the 0700/0600 model (design.md §6.5).
func TestDirStorePermissions(t *testing.T) {
	base, err := os.MkdirTemp("", "keyring-perm-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	dir := filepath.Join(base, "secrets")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	st, err := NewDirStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Set("keyref", "../escape/attempt", "x"); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("store dir mode %o, want 0700", fi.Mode().Perm())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one secret file, got %d", len(entries))
	}
	sf, err := entries[0].Info()
	if err != nil {
		t.Fatal(err)
	}
	if sf.Mode().Perm() != 0o600 {
		t.Fatalf("secret file mode %o, want 0600", sf.Mode().Perm())
	}
	// The hostile service/user pair must still resolve inside the store.
	if _, err := st.Get("keyref", "../escape/attempt"); err != nil {
		t.Fatalf("path-shaped user name broke the store: %v", err)
	}
}

func TestOSKeyringConformance(t *testing.T) {
	// Interface conformance compiled in; the live Keychain path is
	// exercised by manual runs on macOS only.
	var st SecretStore = OSKeyring{}
	_ = st
}
