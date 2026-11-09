package itemcrypt

import (
	"bytes"
	"errors"
	"testing"

	"github.com/lidessen/keyref/cli/internal/secret"
	"github.com/lidessen/keyref/proto/crypto"
)

func TestDecryptLoginFields(t *testing.T) {
	f := newFixture(t)
	key, err := secret.NewKey(bytes.Clone(f.itemKey))
	if err != nil {
		t.Fatal("could not allocate fixture key")
	}
	defer key.Destroy()
	username, value, err := DecryptLoginFields(key, f.secretBlob, fxVault, fxItem)
	if err != nil {
		t.Fatal("could not decrypt login fixture")
	}
	defer username.Destroy()
	defer value.Destroy()
	if !username.EqualTo([]byte("deploy")) || !value.EqualTo([]byte(fxSecretValue)) {
		t.Fatal("login fields do not match their source fields")
	}
}

func TestDecryptLoginFieldsRequiresBoth(t *testing.T) {
	f := newFixture(t)
	key, err := secret.NewKey(bytes.Clone(f.itemKey))
	if err != nil {
		t.Fatal("could not allocate fixture key")
	}
	defer key.Destroy()
	aad, err := crypto.SecretAAD(fxVault, fxItem)
	if err != nil {
		t.Fatal("could not bind fixture")
	}
	for _, fields := range []string{`{"username":"u"}`, `{"value":"v"}`} {
		blob, err := crypto.SealBlob(f.itemKey, aad, []byte(fields))
		if err != nil {
			t.Fatal("could not seal fixture")
		}
		username, value, err := DecryptLoginFields(key, blob, fxVault, fxItem)
		if !errors.Is(err, secret.ErrFieldNotFound) || username != nil || value != nil {
			t.Fatal("missing field returned a partial login")
		}
	}
}
