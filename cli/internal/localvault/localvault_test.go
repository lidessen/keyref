package localvault

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/lidessen/keyref/cli/internal/keyring"
)

type fakeKeyring struct {
	entries map[string]string
	setErr  error
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

func TestEnvironmentKeyWinsOverTheKeyring(t *testing.T) {
	encoded, want := envKey(t)
	ks := newFakeKeyring()
	ks.entries["keyref/local-master-local"] = base64.StdEncoding.EncodeToString(make([]byte, 32))
	lookup := func(name string) (string, bool) {
		if name == EnvMaster {
			return encoded, true
		}
		return "", false
	}
	got, err := Key(ks, "local", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("the environment key was not used")
	}
}

func TestMalformedEnvironmentKeyIsAnError(t *testing.T) {
	for _, bad := range []string{"not-base64", "", base64.StdEncoding.EncodeToString(make([]byte, 31))} {
		lookup := func(string) (string, bool) { return bad, true }
		if _, err := Key(newFakeKeyring(), "local", lookup); !errors.Is(err, ErrKey) {
			t.Fatalf("malformed key %q accepted: %v", bad, err)
		}
		// Provisioning must fail too rather than generating a different
		// key than the caller asked for.
		if _, err := Provision(newFakeKeyring(), "local", lookup); !errors.Is(err, ErrKey) {
			t.Fatalf("provision with malformed key %q: %v", bad, err)
		}
	}
}

func TestKeyringFallback(t *testing.T) {
	encoded, want := envKey(t)
	ks := newFakeKeyring()
	ks.entries["keyref/local-master-work"] = encoded
	got, err := Key(ks, "work", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("wrong key returned")
	}
	// Keys are per source: another name must not see this one.
	if _, err := Key(ks, "local", noEnv); !errors.Is(err, ErrKey) {
		t.Fatalf("cross-source key read: %v", err)
	}
}

func TestMissingKeyIsAnError(t *testing.T) {
	if _, err := Key(newFakeKeyring(), "local", noEnv); !errors.Is(err, ErrKey) {
		t.Fatalf("missing key = %v", err)
	}
}

func TestProvisionGeneratesAndStoresTheKey(t *testing.T) {
	ks := newFakeKeyring()
	key, err := Provision(ks, "local", noEnv)
	if err != nil {
		t.Fatal(err)
	}
	if len(key) != 32 {
		t.Fatalf("key length %d", len(key))
	}
	stored, ok := ks.entries["keyref/local-master-local"]
	if !ok {
		t.Fatal("the generated key was not stored in the keyring")
	}
	decoded, err := base64.StdEncoding.DecodeString(stored)
	if err != nil || !bytes.Equal(decoded, key) {
		t.Fatalf("stored key does not match: %v", err)
	}
	// The next command reads back exactly the same key.
	again, err := Key(ks, "local", noEnv)
	if err != nil || !bytes.Equal(again, key) {
		t.Fatalf("keyring round trip: %v", err)
	}
}

func TestProvisionWithAnEnvironmentKeyStoresNothing(t *testing.T) {
	encoded, want := envKey(t)
	ks := newFakeKeyring()
	lookup := func(string) (string, bool) { return encoded, true }
	key, err := Provision(ks, "local", lookup)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(key, want) {
		t.Fatal("the environment key was not used")
	}
	if len(ks.entries) != 0 {
		t.Fatalf("an environment-provided key was copied into the keyring: %v", ks.entries)
	}
}

func TestProvisionReportsAKeyringFailure(t *testing.T) {
	ks := newFakeKeyring()
	ks.setErr = errors.New("no keyring on this host")
	if _, err := Provision(ks, "local", noEnv); !errors.Is(err, ErrKey) {
		t.Fatalf("keyring failure = %v", err)
	}
}
