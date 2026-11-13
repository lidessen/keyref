package localvault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/source"
	"github.com/lidessen/keyref/cli/local"
)

type fakeKeyring struct {
	entries map[string]string
	setErr  error
	// anyGet reports every entry as present, so a caller's
	// never-overwrite guard can be exercised.
	anyGet bool
}

func newFakeKeyring() *fakeKeyring { return &fakeKeyring{entries: map[string]string{}} }

func (f *fakeKeyring) Set(service, user, secret string) error {
	if f.setErr != nil {
		return f.setErr
	}
	f.entries[service+"/"+user] = secret
	return nil
}

func (f *fakeKeyring) Get(service, user string) (string, error) {
	if f.anyGet {
		return base64.StdEncoding.EncodeToString(make([]byte, 32)), nil
	}
	if v, ok := f.entries[service+"/"+user]; ok {
		return v, nil
	}
	return "", keyring.ErrNotFound
}

func (f *fakeKeyring) Delete(service, user string) error {
	delete(f.entries, service+"/"+user)
	return nil
}

func envKey(t *testing.T) (string, []byte) {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(key), key
}

func noEnv(string) (string, bool) { return "", false }

func constLookup(value string) func(string) (string, bool) {
	return func(string) (string, bool) { return value, true }
}

// newSpec returns a source whose vault file does not exist yet, in a
// private directory local.Create accepts.
func newSpec(t *testing.T) source.Spec {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return source.Spec{Name: "local", Kind: source.KindLocal,
		Path: filepath.Join(dir, "vault.db")}
}

// newVault creates a vault directly in the store package and returns
// its path and master key.
func newVault(t *testing.T) (string, []byte) {
	t.Helper()
	spec := newSpec(t)
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	st, err := local.Create(spec.Path, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}
	return spec.Path, key
}

func mustID(t *testing.T, path string) string {
	t.Helper()
	id, err := local.ReadStoreID(path)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestEnvironmentKeyWinsOverTheKeyring(t *testing.T) {
	path, _ := newVault(t)
	id := mustID(t, path)
	encoded, want := envKey(t)
	ks := newFakeKeyring()
	ks.entries["keyref/"+keyringPrefix+id] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	got, err := Key(ks, path, constLookup(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the environment key was not used")
	}
}

func TestMalformedEnvironmentKeyIsAnError(t *testing.T) {
	path, _ := newVault(t)
	for _, bad := range []string{"not-base64", "", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		if _, err := Key(newFakeKeyring(), path, constLookup(bad)); !errors.Is(err, ErrKey) {
			t.Fatalf("malformed key %q accepted: %v", bad, err)
		}
		// Provisioning must fail too, before it creates a file.
		spec := newSpec(t)
		if _, err := Create(newFakeKeyring(), spec, constLookup(bad)); !errors.Is(err, ErrKey) {
			t.Fatalf("create with malformed key %q: %v", bad, err)
		}
		if _, err := os.Stat(spec.Path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("a malformed environment key left a vault file behind: %v", err)
		}
	}
}

func TestKeyringFallback(t *testing.T) {
	path, key := newVault(t)
	id := mustID(t, path)
	ks := newFakeKeyring()
	ks.entries["keyref/"+keyringPrefix+id] = base64.StdEncoding.EncodeToString(key)
	got, err := Key(ks, path, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatal("wrong key returned")
	}
	// Keys are per vault: another vault's (different) store id must not
	// see this one (issue #2).
	otherPath, _ := newVault(t)
	if _, err := Key(ks, otherPath, noEnv); !errors.Is(err, ErrKey) {
		t.Fatalf("cross-vault key read: %v", err)
	}
}

func TestMissingKeyIsAnError(t *testing.T) {
	path, _ := newVault(t)
	if _, err := Key(newFakeKeyring(), path, noEnv); !errors.Is(err, ErrKey) {
		t.Fatalf("missing key = %v", err)
	}
}

func TestCreateBindsTheKeyToTheStoreID(t *testing.T) {
	spec := newSpec(t)
	ks := newFakeKeyring()
	vault, err := Create(ks, spec, noEnv)
	if err != nil {
		t.Fatal(err)
	}
	id := vault.StoreID()
	if err := vault.Close(); err != nil {
		t.Fatal(err)
	}
	if id != mustID(t, spec.Path) {
		t.Fatal("the store id changed on disk")
	}
	stored, ok := ks.entries["keyref/"+keyringPrefix+id]
	if !ok {
		t.Fatalf("the key was not stored under the store id: %v", ks.entries)
	}
	key, err := base64.StdEncoding.DecodeString(stored)
	if err != nil || len(key) != 32 {
		t.Fatalf("stored key is not 32 bytes: %v", err)
	}
	// The stored key is the one that opens this vault.
	got, err := Key(ks, spec.Path, noEnv)
	if err != nil || !bytes.Equal(got, key) {
		t.Fatalf("keyring round trip: %v", err)
	}
	reopened, err := Open(spec, got)
	if err != nil {
		t.Fatalf("the stored key does not open the vault: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestCreateWithAnEnvironmentKeyStoresNothing(t *testing.T) {
	spec := newSpec(t)
	encoded, want := envKey(t)
	ks := newFakeKeyring()
	vault, err := Create(ks, spec, constLookup(encoded))
	if err != nil {
		t.Fatal(err)
	}
	if err := vault.Close(); err != nil {
		t.Fatal(err)
	}
	if len(ks.entries) != 0 {
		t.Fatalf("an environment-provided key was copied into the keyring: %v", ks.entries)
	}
	got, err := Key(ks, spec.Path, constLookup(encoded))
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("the environment key does not open the vault: %v", err)
	}
}

func TestCreateReportsAKeyringFailureAndRemovesTheFile(t *testing.T) {
	spec := newSpec(t)
	ks := newFakeKeyring()
	ks.setErr = errors.New("no keyring on this host")
	if _, err := Create(ks, spec, noEnv); !errors.Is(err, ErrKey) {
		t.Fatalf("keyring failure = %v", err)
	}
	if _, err := os.Stat(spec.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the vault file survived a failed keyring write: %v", err)
	}
}

func TestCreateNeverOverwritesAnExistingEntry(t *testing.T) {
	spec := newSpec(t)
	ks := newFakeKeyring()
	ks.anyGet = true
	if _, err := Create(ks, spec, noEnv); !errors.Is(err, ErrKeyExists) {
		t.Fatalf("an existing entry was replaced: %v", err)
	}
	if _, err := os.Stat(spec.Path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the vault file survived a refused keyring write: %v", err)
	}
	if len(ks.entries) != 0 {
		t.Fatalf("the existing entry was touched: %v", ks.entries)
	}
}
