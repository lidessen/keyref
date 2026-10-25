package crypto

import (
	"bytes"
	"crypto/ed25519"
	"testing"
)

func TestRecoveryKeysFromSeed(t *testing.T) {
	seed := bytes.Repeat([]byte{0x77}, RecoverySeedLen)
	kek1, sign1, err := RecoveryKeysFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	kek2, sign2, err := RecoveryKeysFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kek1, kek2) {
		t.Fatal("kek derivation is not deterministic")
	}
	if len(kek1) != 32 {
		t.Fatalf("kek length %d, want 32", len(kek1))
	}
	if !sign1.Equal(sign2) {
		t.Fatal("recovery signing key is not deterministic")
	}
	// The recovery signing key must verify as Ed25519 with a derivable
	// public key (recovery_sign_pub on the server, protocol §3.8).
	msg := []byte("takeover directory transcript")
	sig := ed25519.Sign(sign1, msg)
	pub := sign1.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, msg, sig) {
		t.Fatal("recovery signature does not verify")
	}
	// Domain separation: a different seed yields entirely different keys,
	// and kek never equals the signing seed material.
	otherSeed := bytes.Repeat([]byte{0x78}, RecoverySeedLen)
	kekOther, signOther, err := RecoveryKeysFromSeed(otherSeed)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(kekOther, kek1) {
		t.Fatal("kek collision across seeds")
	}
	if signOther.Equal(sign1) {
		t.Fatal("signing key collision across seeds")
	}
	if bytes.Equal(kek1, seed) {
		t.Fatal("kek equals the raw seed")
	}
	if _, _, err := RecoveryKeysFromSeed(seed[:31]); err == nil {
		t.Fatal("short seed accepted")
	}
}
