package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestGenerateDeviceKeys(t *testing.T) {
	keys, err := GenerateDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	if keys.HPKEKEM != "X25519" || len(keys.HPKEPublic) != 32 {
		t.Fatalf("bad hpke key: kem=%s len=%d", keys.HPKEKEM, len(keys.HPKEPublic))
	}
	if keys.SignAlg != "ed25519" || len(keys.SignPublic) != 32 {
		t.Fatalf("bad sign key: alg=%s len=%d", keys.SignAlg, len(keys.SignPublic))
	}
	msg := []byte("transcript-bytes")
	sig := ed25519.Sign(keys.SignPrivate, msg)
	if !ed25519.Verify(ed25519.PublicKey(keys.SignPublic), msg, sig) {
		t.Fatal("device signature does not verify")
	}
	// A second identity must differ (fresh CSPRNG key material).
	again, err := GenerateDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(again.SignPublic, keys.SignPublic) {
		t.Fatal("two generated identities share a signing key")
	}
}

func TestGenerateOwnerKeys(t *testing.T) {
	signPriv, signPub, hpkePriv, hpkePub, err := GenerateOwnerKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(signPub) != 65 || signPub[0] != 0x04 {
		t.Fatalf("owner sign pub must be SEC1 uncompressed, got %d bytes", len(signPub))
	}
	if len(hpkePub) != 65 || len(hpkePriv) == 0 {
		t.Fatal("owner hpke P-256 key shapes wrong")
	}
	digest := sha256.Sum256([]byte("owner transcript"))
	sig, err := ecdsa.SignASN1(rand.Reader, signPriv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !ecdsa.VerifyASN1(&signPriv.PublicKey, digest[:], sig) {
		t.Fatal("owner signature does not verify")
	}
}
