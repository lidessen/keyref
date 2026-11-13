package wire

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"testing"
)

func newOwnerKey(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := EncodeP256PublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return key, pub
}

func newEd25519Key(t *testing.T) (ed25519.PrivateKey, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestSignVerifyRoundTrip(t *testing.T) {
	ownerKey, ownerPub := newOwnerKey(t)
	otherOwnerKey, otherOwnerPub := newOwnerKey(t)
	cliPriv, cliPub := newEd25519Key(t)
	_, otherCLIPub := newEd25519Key(t)

	itemBytes := mustBuild(t, func() ([]byte, error) {
		return BuildItemTranscript(ItemTranscript{
			VaultID: tvVault, ItemID: tvItem, Revision: 4,
			MetaCiphertext: []byte{1}, SecretCiphertext: []byte{2},
			VaultWrappedMetaKey: []byte{3}, VaultWrappedItemKey: []byte{4},
			WriterDeviceID: tvWriter,
		})
	})
	registerBytes := mustBuild(t, func() ([]byte, error) {
		return BuildPairRegisterTranscript(rep(1, SizePairNonce), "build-agent-1")
	})
	sessionBytes := mustBuild(t, func() ([]byte, error) {
		return BuildSessionTranscript(tvDevice, rep(2, SizeChallenge))
	})

	ownerSig, err := SignOwnerECDSA(itemBytes, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	cliSig, err := SignEd25519(registerBytes, cliPriv)
	if err != nil {
		t.Fatal(err)
	}
	sessionSig, err := SignEd25519(sessionBytes, cliPriv)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name       string
		transcript []byte
		signature  []byte
		verify     func() error
	}{
		{"owner ecdsa over item transcript", itemBytes, ownerSig, func() error {
			return VerifyOwnerSignature(itemBytes, ownerSig, ownerPub)
		}},
		{"cli ed25519 over pair-register transcript", registerBytes, cliSig, func() error {
			return VerifyCLISignature(registerBytes, cliSig, cliPub)
		}},
		{"cli ed25519 over session transcript", sessionBytes, sessionSig, func() error {
			return VerifyDeviceSignature(sessionBytes, sessionSig, SignAlgEd25519, cliPub)
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.verify(); err != nil {
				t.Fatalf("honest verification failed: %v", err)
			}
		})
	}

	tampered := append([]byte{}, itemBytes...)
	tampered[len(tampered)-1] ^= 0x01 // flip a byte inside the writer id hex

	badSig := append([]byte{}, ownerSig...)
	badSig[0] ^= 0xff

	if err := VerifyOwnerSignature(tampered, ownerSig, ownerPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered transcript: got %v, want ErrBadSignature", err)
	}
	if err := VerifyOwnerSignature(itemBytes, badSig, ownerPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("tampered signature: got %v, want ErrBadSignature", err)
	}
	if err := VerifyOwnerSignature(itemBytes, ownerSig, otherOwnerPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong owner key: got %v, want ErrBadSignature", err)
	}
	if err := VerifyCLISignature(registerBytes, cliSig, otherCLIPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("wrong cli key: got %v, want ErrBadSignature", err)
	}
	if err := VerifyOwnerSignature(itemBytes, nil, ownerPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("nil signature: got %v, want ErrBadSignature", err)
	}
	if err := VerifyOwnerSignature(itemBytes, ownerSig[:len(ownerSig)-2], ownerPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("truncated signature: got %v, want ErrBadSignature", err)
	}
	// A key encoded for one algorithm must not verify under the other.
	if err := VerifyOwnerSignature(itemBytes, cliSig, cliPub); err == nil {
		t.Error("ed25519 signature verified as ecdsa-p256")
	}
	if err := VerifyDeviceSignature(itemBytes, ownerSig, "ecdsa-p256", cliPub); err == nil {
		t.Error("ecdsa signature verified with a 32-byte key")
	}
	if err := VerifyDeviceSignature(itemBytes, ownerSig, "rsa-4096", ownerPub); err == nil {
		t.Error("unknown sign_alg accepted")
	}
	// Cross-keyer: a signature by the other owner key must fail.
	otherSig, err := SignOwnerECDSA(itemBytes, otherOwnerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOwnerSignature(itemBytes, otherSig, ownerPub); !errors.Is(err, ErrBadSignature) {
		t.Errorf("signature by a different owner key: got %v, want ErrBadSignature", err)
	}
}

// TestStructuredFieldTamperRejection covers the verification model the
// server uses (protocol D3): it rebuilds transcript bytes from the
// structured request fields and checks the signature over the rebuild.
// Changing any signed field must break verification.
func TestStructuredFieldTamperRejection(t *testing.T) {
	ownerKey, ownerPub := newOwnerKey(t)
	cliPriv, cliPub := newEd25519Key(t)

	base := ItemTranscript{
		VaultID: tvVault, ItemID: tvItem, Revision: 4,
		MetaCiphertext: []byte{0xaa}, SecretCiphertext: []byte{0xbb},
		VaultWrappedMetaKey: []byte{0xcc}, VaultWrappedItemKey: []byte{0xdd},
		WriterDeviceID: tvWriter,
	}
	signedBytes := mustBuild(t, func() ([]byte, error) { return BuildItemTranscript(base) })
	sig, err := SignOwnerECDSA(signedBytes, ownerKey)
	if err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*ItemTranscript){
		"revision": func(it *ItemTranscript) { it.Revision = 5 },
		"meta ciphertext": func(it *ItemTranscript) {
			it.MetaCiphertext = []byte{0xab} // replace, not share, the slice
		},
		"secret ciphertext": func(it *ItemTranscript) {
			it.SecretCiphertext = append([]byte{}, it.SecretCiphertext...)
			it.SecretCiphertext = append(it.SecretCiphertext, 0x00)
		},
		"writer device": func(it *ItemTranscript) { it.WriterDeviceID = tvDevice },
		"vault id":      func(it *ItemTranscript) { it.VaultID = tvItem2 },
	}
	for name, mutate := range mutations {
		t.Run("item/"+name, func(t *testing.T) {
			mutated := base
			mutate(&mutated)
			rebuilt, err := BuildItemTranscript(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyOwnerSignature(rebuilt, sig, ownerPub); !errors.Is(err, ErrBadSignature) {
				t.Fatalf("signature accepted after mutating %s", name)
			}
		})
	}

	// Grant transcript: swapping the kind must invalidate the signature.
	grant := GrantTranscript{
		VaultID: tvVault, DeviceID: tvDevice, ItemID: tvItem,
		Kind: GrantKindView, Revision: 2, ExpiresAt: 1790000000000,
		HPKEEnc: rep(1, SizeX25519Key), WrappedKey: rep(2, SizeMessageWrappedKey),
	}
	grantSig, err := SignOwnerECDSA(mustBuild(t, func() ([]byte, error) {
		return BuildGrantTranscript(grant)
	}), ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	grant.Kind = GrantKindUse
	rebuilt, err := BuildGrantTranscript(grant)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOwnerSignature(rebuilt, grantSig, ownerPub); !errors.Is(err, ErrBadSignature) {
		t.Fatal("signature accepted after swapping grant kind")
	}

	// Pair transcript: changing the label must invalidate the signature.
	pair := PairTranscript{
		VaultID:            tvVault,
		OwnerSignPublicKey: append([]byte{0x04}, rep(1, 64)...),
		Nonce:              tvNonce, DeviceID: tvDevice,
		HPKEKEM:       KEMX25519,
		HPKEPublicKey: rep(2, SizeX25519Key),
		SignAlg:       SignAlgEd25519,
		SignPublicKey: rep(3, SizeEd25519Key),
		Label:         "build-agent-1",
	}
	pairSig, err := SignOwnerECDSA(mustBuild(t, func() ([]byte, error) {
		return BuildPairTranscript(pair)
	}), ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	pair.Label = "attacker-agent"
	rebuilt, err = BuildPairTranscript(pair)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyOwnerSignature(rebuilt, pairSig, ownerPub); !errors.Is(err, ErrBadSignature) {
		t.Fatal("signature accepted after changing the device label")
	}

	// Pair-register: changing the proposed name must invalidate the CLI
	// signature.
	registerSig, err := SignEd25519(mustBuild(t, func() ([]byte, error) {
		return BuildPairRegisterTranscript(rep(7, SizePairNonce), "build-agent-1")
	}), cliPriv)
	if err != nil {
		t.Fatal(err)
	}
	renamed, err := BuildPairRegisterTranscript(rep(7, SizePairNonce), "evil-agent")
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCLISignature(renamed, registerSig, cliPub); !errors.Is(err, ErrBadSignature) {
		t.Fatal("signature accepted after changing the proposed name")
	}
}

// TestRecoveryTakeoverDoubleSignature covers design §8.5 / protocol §7.3:
// the recovery signing authority and the new owner sign the SAME new
// directory transcript; the server checks both signatures over those
// exact bytes.
func TestRecoveryTakeoverDoubleSignature(t *testing.T) {
	recoveryPriv, recoveryPub := newEd25519Key(t)
	newOwnerKey, newOwnerPub := newOwnerKey(t)

	digest, err := GrantsDigest(nil)
	if err != nil {
		t.Fatal(err)
	}
	directory := DirectoryTranscript{
		VaultID:           tvVault,
		DirectoryRevision: 8,
		Devices: []DirectoryDevice{
			{
				DeviceID:      tvDevice,
				Kind:          DeviceKindIOS,
				Status:        DeviceStatusActive,
				HPKEKEM:       KEMP256,
				HPKEPublicKey: append([]byte{0x04}, rep(0x11, 64)...),
				SignAlg:       SignAlgECDSAP256,
				SignPublicKey: newOwnerPub,
				GrantsDigest:  digest,
			},
			{
				DeviceID:      tvDevice2, // lost phone, now revoked
				Kind:          DeviceKindIOS,
				Status:        DeviceStatusRevoked,
				HPKEKEM:       KEMP256,
				HPKEPublicKey: append([]byte{0x04}, rep(0x22, 64)...),
				SignAlg:       SignAlgECDSAP256,
				SignPublicKey: append([]byte{0x04}, rep(0x33, 64)...),
				GrantsDigest:  digest,
			},
		},
	}
	transcript := mustBuild(t, func() ([]byte, error) {
		return BuildDirectoryTranscript(directory)
	})

	recoverySig, err := SignEd25519(transcript, recoveryPriv)
	if err != nil {
		t.Fatal(err)
	}
	ownerSig, err := SignOwnerECDSA(transcript, newOwnerKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRecoverySignature(transcript, recoverySig, recoveryPub); err != nil {
		t.Fatalf("recovery authority signature rejected: %v", err)
	}
	if err := VerifyOwnerSignature(transcript, ownerSig, newOwnerPub); err != nil {
		t.Fatalf("new owner signature rejected: %v", err)
	}

	// Re-anchoring a different directory (bumped revision) under the same
	// signatures must fail both checks.
	directory.DirectoryRevision = 9
	otherBytes := mustBuild(t, func() ([]byte, error) {
		return BuildDirectoryTranscript(directory)
	})
	if bytes.Equal(otherBytes, transcript) {
		t.Fatal("expected different transcript bytes")
	}
	if err := VerifyRecoverySignature(otherBytes, recoverySig, recoveryPub); !errors.Is(err, ErrBadSignature) {
		t.Fatal("recovery signature accepted over a different directory")
	}
	if err := VerifyOwnerSignature(otherBytes, ownerSig, newOwnerPub); !errors.Is(err, ErrBadSignature) {
		t.Fatal("owner signature accepted over a different directory")
	}
}
