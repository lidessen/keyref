package crypto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// The golden vectors in testdata/vectors.json were produced by an
// independent stdlib-only generator implementing protocol.md §1–§3
// directly (docs/protocol.md §11.5). Agreement proves the library's
// byte-level interpretation of the contract, not merely self-consistency.

type vecFile struct {
	InfoItemKey struct {
		Input struct {
			Purpose           string `json:"purpose"`
			VaultID           string `json:"vault_id"`
			RecipientDeviceID string `json:"recipient_device_id"`
		} `json:"input"`
		Info string `json:"info"`
	} `json:"info_item_key"`
	InfoOneTime struct {
		Input struct {
			VaultID           string `json:"vault_id"`
			RecipientDeviceID string `json:"recipient_device_id"`
			ItemID            string `json:"item_id"`
			ApprovalID        string `json:"approval_id"`
			RequestCiphertext string `json:"request_ciphertext"`
		} `json:"input"`
		Info string `json:"info"`
	} `json:"info_one_time"`
	AAD struct {
		VaultID   string `json:"vault_id"`
		ItemID    string `json:"item_id"`
		DeviceID  string `json:"device_id"`
		Secret    string `json:"secret"`
		Meta      string `json:"meta"`
		VaultMeta string `json:"vault_meta_key"`
		VaultItem string `json:"vault_item_key"`
		Recovery  string `json:"recovery"`
		Audit     string `json:"audit"`
	} `json:"aad"`
	AEADBlob struct {
		Key       string `json:"key"`
		AAD       string `json:"aad"`
		Nonce     string `json:"nonce"`
		Plaintext string `json:"plaintext"`
		Blob      string `json:"blob"`
	} `json:"aead_blob"`
	RecoveryDerivation struct {
		Seed       string `json:"seed"`
		KEK        string `json:"kek"`
		SignPublic string `json:"sign_public"`
	} `json:"recovery_derivation"`
}

func hexB(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex in vectors: %v", err)
	}
	return b
}

func loadVec(t *testing.T) *vecFile {
	t.Helper()
	raw, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var v vecFile
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	return &v
}

func TestVectorInfoStrings(t *testing.T) {
	v := loadVec(t)
	in := v.InfoItemKey.Input
	got, err := Info(in.Purpose, in.VaultID, in.RecipientDeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, hexB(t, v.InfoItemKey.Info)) {
		t.Fatalf("info diverges from golden vector:\n got: %x\nwant: %x", got, hexB(t, v.InfoItemKey.Info))
	}

	ot := v.InfoOneTime.Input
	got, err = OneTimeItemKeyInfo(ot.VaultID, ot.RecipientDeviceID, ot.ItemID, ot.ApprovalID, hexB(t, ot.RequestCiphertext))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, hexB(t, v.InfoOneTime.Info)) {
		t.Fatalf("one-time info diverges from golden vector:\n got: %x\nwant: %x", got, hexB(t, v.InfoOneTime.Info))
	}
}

func TestVectorAADs(t *testing.T) {
	v := loadVec(t)
	a := v.AAD
	cases := []struct {
		name string
		got  []byte
		want string
	}{
		{"secret", mustAAD2(t, SecretAAD, a.VaultID, a.ItemID), a.Secret},
		{"meta", mustAAD2(t, MetaAAD, a.VaultID, a.ItemID), a.Meta},
		{"vault-meta-key", mustAAD2(t, VaultWrappedMetaKeyAAD, a.VaultID, a.ItemID), a.VaultMeta},
		{"vault-item-key", mustAAD2(t, VaultWrappedItemKeyAAD, a.VaultID, a.ItemID), a.VaultItem},
	}
	for _, c := range cases {
		if !bytes.Equal(c.got, hexB(t, c.want)) {
			t.Errorf("%s aad diverges from golden vector", c.name)
		}
	}
	rec, err := RecoveryAAD(a.VaultID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(rec, hexB(t, a.Recovery)) {
		t.Error("recovery aad diverges from golden vector")
	}
	aud, err := AuditAAD(a.VaultID, a.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(aud, hexB(t, a.Audit)) {
		t.Error("audit aad diverges from golden vector")
	}
}

func mustAAD2(t *testing.T, f func(string, string) ([]byte, error), vault, item string) []byte {
	t.Helper()
	b, err := f(vault, item)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestVectorAEADBlob(t *testing.T) {
	v := loadVec(t)
	b := v.AEADBlob
	blob := hexB(t, b.Blob)
	// Layout: the fixed nonce must lead the blob (protocol §1.5).
	if !bytes.Equal(blob[:12], hexB(t, b.Nonce)) {
		t.Fatal("blob does not start with the vector nonce")
	}
	pt, err := OpenBlob(hexB(t, b.Key), hexB(t, b.AAD), blob)
	if err != nil {
		t.Fatalf("golden blob does not open: %v", err)
	}
	if !bytes.Equal(pt, hexB(t, b.Plaintext)) {
		t.Fatal("golden blob decrypts to unexpected plaintext")
	}
	// Cross-check with the independent generator's AAD binding: the
	// same blob under the meta AAD must fail.
	if _, err := OpenBlob(hexB(t, b.Key), hexB(t, v.AAD.Meta), blob); err == nil {
		t.Fatal("blob opened under a foreign AAD")
	}
}

func TestVectorRecoveryDerivation(t *testing.T) {
	v := loadVec(t)
	kek, signPriv, err := RecoveryKeysFromSeed(hexB(t, v.RecoveryDerivation.Seed))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(kek, hexB(t, v.RecoveryDerivation.KEK)) {
		t.Fatal("recovery kek diverges from golden vector")
	}
	pub := signPriv.Public().(ed25519.PublicKey)
	if !bytes.Equal(pub, hexB(t, v.RecoveryDerivation.SignPublic)) {
		t.Fatal("recovery signing public key diverges from golden vector")
	}
}
