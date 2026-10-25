package device

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/cli/internal/keyring"
)

func tempStore(t *testing.T) *keyring.DirStore {
	t.Helper()
	base, err := os.MkdirTemp("", "device-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	st, err := keyring.NewDirStore(filepath.Join(base, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	return st
}

func TestLoadOrCreatePersistsIdentity(t *testing.T) {
	st := tempStore(t)
	id1, err := LoadOrCreate(st)
	if err != nil {
		t.Fatal(err)
	}
	if len(id1.HPKEPublic) != 32 || len(id1.SignPublic) != 32 || id1.HPKEPrivate == nil {
		t.Fatalf("bad identity shapes: %+v", id1)
	}

	id2, err := LoadOrCreate(st)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(id1.HPKEPublic, id2.HPKEPublic) {
		t.Fatal("hpke public key changed across loads")
	}
	if !bytes.Equal(id1.SignPublic, id2.SignPublic) {
		t.Fatal("sign public key changed across loads")
	}
	if !bytes.Equal(id1.HPKEPrivate, id2.HPKEPrivate) {
		t.Fatal("hpke private key changed across loads")
	}
	if !id1.SignPrivate.Equal(id2.SignPrivate) {
		t.Fatal("sign private key changed across loads")
	}

	// A fresh store generates a different identity (no global reuse).
	other := tempStore(t)
	id3, err := LoadOrCreate(other)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(id1.SignPublic, id3.SignPublic) {
		t.Fatal("two stores share a signing key")
	}
}

func TestLoadOrCreateDoesNotRegenerateOnKeyringFailure(t *testing.T) {
	st := &failingStore{err: errors.New("keychain locked")}
	if _, err := LoadOrCreate(st); err == nil {
		t.Fatal("identity regenerated over a real keyring failure")
	}
}

type failingStore struct{ err error }

func (f *failingStore) Set(service, user, secret string) error { return f.err }
func (f *failingStore) Get(service, user string) (string, error) {
	return "", f.err
}
func (f *failingStore) Delete(service, user string) error { return f.err }

func TestFingerprintFormat(t *testing.T) {
	st := tempStore(t)
	id, err := LoadOrCreate(st)
	if err != nil {
		t.Fatal(err)
	}
	fp := id.Fingerprint()
	if !fingerprintRe.MatchString(fp) {
		t.Fatalf("fingerprint %q does not match A1B2-C3D4-E5F6-7890", fp)
	}
	// Recompute independently: first 8 bytes of SHA-256 of the raw
	// signing public key, uppercase hex, grouped in fours
	// (docs/protocol.md §9.1).
	sum := sha256.Sum256(id.SignPublic)
	want := strings.ToUpper(fmt.Sprintf("%x", sum[:8]))
	var b strings.Builder
	for i := 0; i < 4; i++ {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(want[i*4 : (i+1)*4])
	}
	if fp != b.String() {
		t.Fatalf("fingerprint %q, want %q", fp, b.String())
	}
}

func TestDeleteRemovesKeys(t *testing.T) {
	st := tempStore(t)
	if _, err := LoadOrCreate(st); err != nil {
		t.Fatal(err)
	}
	if err := Delete(st); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Get(Service, UserHPKE); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("hpke key survived delete: %v", err)
	}
	if _, err := st.Get(Service, UserSign); !errors.Is(err, keyring.ErrNotFound) {
		t.Fatalf("sign key survived delete: %v", err)
	}
	if err := Delete(st); err != nil {
		t.Fatalf("delete of empty store failed: %v", err)
	}
}
