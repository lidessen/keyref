package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"
)

// Recovery-code derivations (docs/protocol.md §3.8, design.md §8.5).
// The recovery code payload is vault_id (16 raw bytes) ‖ seed (32 bytes);
// only the seed enters HKDF. Both derivations are domain separated and
// mutually independent: the kek decrypts recovery_wrap, the signing key
// re-anchors the device directory, and neither can do the other's job.
const (
	hkdfInfoRecoveryKEK  = "recovery-kek"
	hkdfInfoRecoverySign = "recovery-sign"
)

// RecoverySeedLen is the byte length of the recovery seed.
const RecoverySeedLen = 32

// RecoveryKeysFromSeed derives, from the 32-byte recovery seed:
//
//	kek       = HKDF-Expand(HKDF-Extract(SHA-256, seed, salt=nil), "recovery-kek",  32)
//	sign seed = HKDF-Expand(HKDF-Extract(SHA-256, seed, salt=nil), "recovery-sign", 32)
//
// and expands the sign seed into an Ed25519 private key whose public key
// is recovery_sign_pub (docs/protocol.md §3.8).
func RecoveryKeysFromSeed(seed []byte) (kek []byte, signPrivate ed25519.PrivateKey, err error) {
	if len(seed) != RecoverySeedLen {
		return nil, nil, fmt.Errorf("crypto: recovery seed must be %d bytes", RecoverySeedLen)
	}
	prk, err := hkdf.Extract(sha256.New, seed, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hkdf extract failed: %w", err)
	}
	kek, err = hkdf.Expand(sha256.New, prk, hkdfInfoRecoveryKEK, SizeKey32)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hkdf expand failed: %w", err)
	}
	signSeed, err := hkdf.Expand(sha256.New, prk, hkdfInfoRecoverySign, ed25519.SeedSize)
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: hkdf expand failed: %w", err)
	}
	signPrivate = ed25519.NewKeyFromSeed(signSeed)
	// Best-effort wipe of the heap-resident derived seed; the Ed25519
	// private key keeps its own copy, recorded as §12.2 residual.
	for i := range signSeed {
		signSeed[i] = 0
	}
	return kek, signPrivate, nil
}
