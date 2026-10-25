package wire

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The golden vectors in ../crypto/testdata/vectors.json were produced by
// an independent stdlib-only generator that implements protocol.md §3
// directly (docs/protocol.md §11.5). These tests pin the library to
// those bytes so the transcript format cannot drift between the server
// and CLI implementations.

type vecGrant struct {
	VaultID    string `json:"vault_id"`
	DeviceID   string `json:"device_id"`
	ItemID     string `json:"item_id"`
	Kind       string `json:"kind"`
	Revision   uint64 `json:"revision"`
	ExpiresAt  uint64 `json:"expires_at"`
	HPKEEnc    string `json:"hpke_enc"`
	WrappedKey string `json:"wrapped_key"`
}

type vecItem struct {
	VaultID             string `json:"vault_id"`
	ItemID              string `json:"item_id"`
	Revision            uint64 `json:"revision"`
	MetaCiphertext      string `json:"meta_ciphertext"`
	SecretCiphertext    string `json:"secret_ciphertext"`
	VaultWrappedMetaKey string `json:"vault_wrapped_meta_key"`
	VaultWrappedItemKey string `json:"vault_wrapped_item_key"`
	WriterDeviceID      string `json:"writer_device_id"`
}

type vecDevice struct {
	DeviceID             string `json:"device_id"`
	Kind                 string `json:"kind"`
	Status               string `json:"status"`
	HPKEKEM              string `json:"hpke_kem"`
	HPKEPublicKey        string `json:"hpke_public_key"`
	SignAlg              string `json:"sign_alg"`
	SignPublicKey        string `json:"sign_public_key"`
	RenewalSignPublicKey string `json:"renewal_sign_public_key"`
	GrantsDigest         string `json:"grants_digest"`
}

type vectorsFile struct {
	ItemTranscript struct {
		Input      vecItem `json:"input"`
		Transcript string  `json:"transcript"`
	} `json:"item_transcript"`
	GrantTranscript struct {
		Input      vecGrant `json:"input"`
		Transcript string   `json:"transcript"`
	} `json:"grant_transcript"`
	GrantDeleteTranscript struct {
		Input      vecGrant `json:"input"`
		Transcript string   `json:"transcript"`
	} `json:"grant_delete_transcript"`
	DirectoryTranscript struct {
		Input struct {
			VaultID           string      `json:"vault_id"`
			DirectoryRevision uint64      `json:"directory_revision"`
			Devices           []vecDevice `json:"devices"`
		} `json:"input"`
		Transcript string `json:"transcript"`
	} `json:"directory_transcript"`
	GrantsDigest struct {
		Input struct {
			VaultID string     `json:"vault_id"`
			Grants  []vecGrant `json:"grants"`
		} `json:"input"`
		Digest string `json:"digest"`
	} `json:"grants_digest"`
	PairTranscript struct {
		Input struct {
			VaultID            string     `json:"vault_id"`
			OwnerSignPublicKey string     `json:"owner_sign_public_key"`
			Nonce              string     `json:"nonce"`
			Device             vecDevice  `json:"device"`
			Label              string     `json:"label"`
			Grants             []vecGrant `json:"grants"`
		} `json:"input"`
		Transcript string `json:"transcript"`
	} `json:"pair_transcript"`
	PairRegisterTranscript struct {
		Input struct {
			Nonce        string `json:"nonce"`
			ProposedName string `json:"proposed_name"`
		} `json:"input"`
		Transcript string `json:"transcript"`
	} `json:"pair_register_transcript"`
	SessionTranscript struct {
		Input struct {
			DeviceID  string `json:"device_id"`
			Challenge string `json:"challenge"`
		} `json:"input"`
		Transcript string `json:"transcript"`
	} `json:"session_transcript"`
	VaultDeleteTranscript struct {
		Input struct {
			VaultID   string `json:"vault_id"`
			Challenge string `json:"challenge"`
		} `json:"input"`
		Transcript string `json:"transcript"`
	} `json:"vault_delete_transcript"`
	VaultRecoveryTranscript struct {
		Input struct {
			VaultID         string `json:"vault_id"`
			RecoveryWrap    string `json:"recovery_wrap"`
			RecoveryKDFJSON string `json:"recovery_kdf_json"`
			RecoverySignPub string `json:"recovery_sign_pub"`
		} `json:"input"`
		Transcript string `json:"transcript"`
	} `json:"vault_recovery_transcript"`
	Ed25519Signature struct {
		Seed      string `json:"seed"`
		Public    string `json:"public"`
		Message   string `json:"message"`
		Signature string `json:"signature"`
	} `json:"ed25519_signature"`
	ECDSAP256Signature struct {
		Public       string `json:"public"`
		Message      string `json:"message"`
		SignatureDER string `json:"signature_der"`
	} `json:"ecdsa_p256_signature"`
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in vectors: %v", err)
	}
	return b
}

func loadVectors(t *testing.T) *vectorsFile {
	t.Helper()
	raw, err := os.ReadFile("../crypto/testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vectorsFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

func grantFromVec(t *testing.T, g vecGrant) GrantTranscript {
	t.Helper()
	return GrantTranscript{
		VaultID:    g.VaultID,
		DeviceID:   g.DeviceID,
		ItemID:     g.ItemID,
		Kind:       g.Kind,
		Revision:   g.Revision,
		ExpiresAt:  g.ExpiresAt,
		HPKEEnc:    mustHex(t, g.HPKEEnc),
		WrappedKey: mustHex(t, g.WrappedKey),
	}
}

func TestVectorItemTranscript(t *testing.T) {
	v := loadVectors(t)
	in := v.ItemTranscript.Input
	got, err := BuildItemTranscript(ItemTranscript{
		VaultID:             in.VaultID,
		ItemID:              in.ItemID,
		Revision:            in.Revision,
		MetaCiphertext:      mustHex(t, in.MetaCiphertext),
		SecretCiphertext:    mustHex(t, in.SecretCiphertext),
		VaultWrappedMetaKey: mustHex(t, in.VaultWrappedMetaKey),
		VaultWrappedItemKey: mustHex(t, in.VaultWrappedItemKey),
		WriterDeviceID:      in.WriterDeviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, v.ItemTranscript.Transcript)) {
		t.Fatalf("item transcript diverges from golden vector:\n got: %x\nwant: %x", got, mustHex(t, v.ItemTranscript.Transcript))
	}
}

func TestVectorGrantTranscripts(t *testing.T) {
	v := loadVectors(t)
	for name, tt := range map[string]struct {
		in   vecGrant
		want string
	}{
		"grant":    {v.GrantTranscript.Input, v.GrantTranscript.Transcript},
		"deletion": {v.GrantDeleteTranscript.Input, v.GrantDeleteTranscript.Transcript},
	} {
		got, err := BuildGrantTranscript(grantFromVec(t, tt.in))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !bytes.Equal(got, mustHex(t, tt.want)) {
			t.Fatalf("%s grant transcript diverges from golden vector", name)
		}
	}
}

func TestVectorDirectoryTranscript(t *testing.T) {
	v := loadVectors(t)
	in := v.DirectoryTranscript.Input
	devices := make([]DirectoryDevice, len(in.Devices))
	for i, d := range in.Devices {
		devices[i] = DirectoryDevice{
			DeviceID:             d.DeviceID,
			Kind:                 d.Kind,
			Status:               d.Status,
			HPKEKEM:              d.HPKEKEM,
			HPKEPublicKey:        mustHex(t, d.HPKEPublicKey),
			SignAlg:              d.SignAlg,
			SignPublicKey:        mustHex(t, d.SignPublicKey),
			RenewalSignPublicKey: mustHex(t, d.RenewalSignPublicKey),
			GrantsDigest:         mustHex(t, d.GrantsDigest),
		}
	}
	got, err := BuildDirectoryTranscript(DirectoryTranscript{
		VaultID:           in.VaultID,
		DirectoryRevision: in.DirectoryRevision,
		Devices:           devices,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, v.DirectoryTranscript.Transcript)) {
		t.Fatal("directory transcript diverges from golden vector (device order or record layout)")
	}
}

func TestVectorGrantsDigest(t *testing.T) {
	v := loadVectors(t)
	grants := make([]GrantTranscript, len(v.GrantsDigest.Input.Grants))
	for i, g := range v.GrantsDigest.Input.Grants {
		grants[i] = grantFromVec(t, g)
	}
	got, err := GrantsDigest(grants)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, v.GrantsDigest.Digest)) {
		t.Fatal("grants digest diverges from golden vector (sort order or transcript bytes)")
	}
}

func TestVectorPairTranscript(t *testing.T) {
	v := loadVectors(t)
	in := v.PairTranscript.Input
	grants := make([]GrantTranscript, len(in.Grants))
	for i, g := range in.Grants {
		grants[i] = grantFromVec(t, g)
	}
	got, err := BuildPairTranscript(PairTranscript{
		VaultID:            in.VaultID,
		OwnerSignPublicKey: mustHex(t, in.OwnerSignPublicKey),
		Nonce:              in.Nonce,
		DeviceID:           in.Device.DeviceID,
		HPKEKEM:            in.Device.HPKEKEM,
		HPKEPublicKey:      mustHex(t, in.Device.HPKEPublicKey),
		SignAlg:            in.Device.SignAlg,
		SignPublicKey:      mustHex(t, in.Device.SignPublicKey),
		Label:              in.Label,
		Grants:             grants,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, v.PairTranscript.Transcript)) {
		t.Fatal("pair transcript diverges from golden vector")
	}
}

func TestVectorSimpleTranscripts(t *testing.T) {
	v := loadVectors(t)

	got, err := BuildPairRegisterTranscript(mustHex(t, v.PairRegisterTranscript.Input.Nonce), v.PairRegisterTranscript.Input.ProposedName)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, v.PairRegisterTranscript.Transcript)) {
		t.Fatal("pair-register transcript diverges from golden vector")
	}

	got, err = BuildSessionTranscript(v.SessionTranscript.Input.DeviceID, mustHex(t, v.SessionTranscript.Input.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, v.SessionTranscript.Transcript)) {
		t.Fatal("session transcript diverges from golden vector")
	}

	got, err = BuildVaultDeleteTranscript(v.VaultDeleteTranscript.Input.VaultID, mustHex(t, v.VaultDeleteTranscript.Input.Challenge))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, v.VaultDeleteTranscript.Transcript)) {
		t.Fatal("vault-delete transcript diverges from golden vector")
	}

	rin := v.VaultRecoveryTranscript.Input
	got, err = BuildVaultRecoveryTranscript(rin.VaultID, mustHex(t, rin.RecoveryWrap), rin.RecoveryKDFJSON, mustHex(t, rin.RecoverySignPub))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, mustHex(t, v.VaultRecoveryTranscript.Transcript)) {
		t.Fatal("vault-recovery transcript diverges from golden vector")
	}
}

// TestVectorSignatures pins both device signature schemes over golden
// transcripts. Ed25519 is deterministic, so signing is pinned too.
func TestVectorSignatures(t *testing.T) {
	v := loadVectors(t)

	// CLI device (Ed25519).
	ed := v.Ed25519Signature
	sig, err := SignEd25519(mustHex(t, ed.Message), ed25519.NewKeyFromSeed(mustHex(t, ed.Seed)))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, mustHex(t, ed.Signature)) {
		t.Fatal("ed25519 signature diverges from golden vector")
	}
	if err := VerifyCLISignature(mustHex(t, ed.Message), mustHex(t, ed.Signature), mustHex(t, ed.Public)); err != nil {
		t.Fatalf("golden ed25519 signature does not verify: %v", err)
	}
	// Tampering must fail.
	bad := append([]byte(nil), mustHex(t, ed.Message)...)
	bad[len(bad)-1] ^= 1
	if err := VerifyCLISignature(bad, mustHex(t, ed.Signature), mustHex(t, ed.Public)); err == nil {
		t.Fatal("ed25519 verification accepted a tampered message")
	}

	// Owner (ECDSA P-256, ASN.1 DER over SHA-256).
	ec := v.ECDSAP256Signature
	if err := VerifyOwnerSignature(mustHex(t, ec.Message), mustHex(t, ec.SignatureDER), mustHex(t, ec.Public)); err != nil {
		t.Fatalf("golden ecdsa signature does not verify: %v", err)
	}
	badSig := append([]byte(nil), mustHex(t, ec.SignatureDER)...)
	badSig[10] ^= 1
	if err := VerifyOwnerSignature(mustHex(t, ec.Message), badSig, mustHex(t, ec.Public)); err == nil {
		t.Fatal("ecdsa verification accepted a tampered signature")
	}
}
