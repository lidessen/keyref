package main

import (
	"bytes"
	"testing"

	"github.com/lidessen/keyref/lib/exec"
	"github.com/lidessen/keyref/lib/secret"
	"github.com/lidessen/keyref/proto/crypto"
)

func TestDecryptExecLoginFields(t *testing.T) {
	keyBytes := bytes.Repeat([]byte{7}, 32)
	key, err := secret.NewKey(bytes.Clone(keyBytes))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	const vaultID, itemID = "00000000000000000000000000000001", "00000000000000000000000000000002"
	aad, err := crypto.SecretAAD(vaultID, itemID)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.SealBlob(keyBytes, aad, []byte(`{"username":"fixture-user","value":"fixture-password"}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ ref, value, other string }{
		{"login.username", "fixture-user", "fixture-password"},
		{"login.password", "fixture-password", "fixture-user"},
		{"login", "fixture-password", "fixture-user"},
	} {
		rr := &exec.ResolvedRef{Ref: tc.ref}
		var stderr bytes.Buffer
		value, code, _ := decryptExecValue(&stderr, key, blob, vaultID, itemID, rr, true)
		if code != 0 || value == nil || rr.Username == nil {
			t.Fatalf("%s: %d %s", tc.ref, code, stderr.String())
		}
		if string(value.Bytes()) != tc.value || string(rr.Username.Bytes()) != tc.other {
			t.Errorf("%s returned wrong fields", tc.ref)
		}
		value.Destroy()
		rr.Username.Destroy()
	}
}
