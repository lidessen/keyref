// Package testowner is a software P-256 owner for tests and the e2e
// suite (docs/protocol.md §11.2): it signs transcripts, wraps grants
// to CLI devices and seals item ciphertexts using the shared proto
// code, exactly like the future iOS owner will.
package testowner

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/itemcrypt"
)

// Owner is one software owner identity bound to one vault.
type Owner struct {
	TB       *testing.T
	SignPriv *ecdsa.PrivateKey
	SignPub  []byte // SEC1 65
	HPKEPriv []byte // P-256, receives approvals/audit (unused here)
	HPKEPub  []byte
	VaultID  string
	OwnerDev string
}

// New generates a fresh owner for vaultID.
func New(t *testing.T, vaultID, ownerDev string) *Owner {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := wire.EncodeP256PublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	hpub, hpriv, err := crypto.GenerateHPKEKeyPair(wire.KEMP256)
	if err != nil {
		t.Fatal(err)
	}
	return &Owner{TB: t, SignPriv: priv, SignPub: pub, HPKEPriv: hpriv, HPKEPub: hpub, VaultID: vaultID, OwnerDev: ownerDev}
}

// Sign signs any transcript bytes with the owner P-256 key.
func (o *Owner) Sign(transcript []byte) []byte {
	o.TB.Helper()
	sig, err := wire.SignOwnerECDSA(transcript, o.SignPriv)
	if err != nil {
		o.TB.Fatal(err)
	}
	return sig
}

// WrapGrant wraps key (meta or item key) to the CLI X25519 public key
// and returns a fully signed GrantData row.
func (o *Owner) WrapGrant(cliPub []byte, deviceID, itemID, kind string, revision uint64, expiresAt int64, key []byte) wire.GrantData {
	o.TB.Helper()
	purpose := crypto.PurposeItemKey
	if kind == wire.GrantKindView {
		purpose = crypto.PurposeMetaKey
	}
	info, err := crypto.Info(purpose, o.VaultID, deviceID)
	if err != nil {
		o.TB.Fatal(err)
	}
	enc, wrapped, err := crypto.WrapKey(wire.KEMX25519, cliPub, info, key)
	if err != nil {
		o.TB.Fatal(err)
	}
	g := wire.GrantData{
		DeviceID:   deviceID,
		ItemID:     itemID,
		Kind:       kind,
		HPKEEnc:    enc,
		WrappedKey: wrapped,
		ExpiresAt:  expiresAt,
		Revision:   revision,
	}
	tb, err := wire.BuildGrantTranscript(g.Transcript(o.VaultID))
	if err != nil {
		o.TB.Fatal(err)
	}
	g.Signature = o.Sign(tb)
	return g
}

// SealedItem is an item row plus the keys that sealed it.
type SealedItem struct {
	Data    wire.ItemData
	MetaKey []byte
	ItemKey []byte
}

// SealItem seals a meta/secret pair under fresh keys.
func (o *Owner) SealItem(itemID, writerDev, ref, name, masked, secretValue string) *SealedItem {
	o.TB.Helper()
	metaKey := rand32(o.TB)
	itemKey := rand32(o.TB)
	meta := itemcrypt.Meta{
		V:          1,
		Ref:        ref,
		Name:       name,
		Type:       "api_key",
		Masked:     masked,
		Injectable: true,
		Policy:     itemcrypt.MetaPolicy{Sensitivity: "standard", CommandPolicy: "deny-shells"},
	}
	metaJSON, err := json.Marshal(meta)
	if err != nil {
		o.TB.Fatal(err)
	}
	secretJSON := fmt.Sprintf(`{"v":1,"value":%q,"username":"","notes":"","fields":{}}`, secretValue)
	metaAAD, err := crypto.MetaAAD(o.VaultID, itemID)
	if err != nil {
		o.TB.Fatal(err)
	}
	secretAAD, err := crypto.SecretAAD(o.VaultID, itemID)
	if err != nil {
		o.TB.Fatal(err)
	}
	metaCT, err := crypto.SealBlob(metaKey, metaAAD, metaJSON)
	if err != nil {
		o.TB.Fatal(err)
	}
	secretCT, err := crypto.SealBlob(itemKey, secretAAD, []byte(secretJSON))
	if err != nil {
		o.TB.Fatal(err)
	}
	vwMeta, err := crypto.SealBlob(rand32(o.TB), mustAAD(o, "vault-meta-key", itemID), []byte("vmk-wrapped"))
	if err != nil {
		o.TB.Fatal(err)
	}
	vwItem, err := crypto.SealBlob(rand32(o.TB), mustAAD(o, "vault-item-key", itemID), []byte("vik-wrapped"))
	if err != nil {
		o.TB.Fatal(err)
	}
	it := wire.ItemData{
		VaultID:             o.VaultID,
		ItemID:              itemID,
		Revision:            1,
		MetaCiphertext:      metaCT,
		SecretCiphertext:    secretCT,
		VaultWrappedMetaKey: vwMeta,
		VaultWrappedItemKey: vwItem,
		WriterDeviceID:      writerDev,
		Signature:           nil, // owner signs the §3.1 transcript
		UpdatedAt:           1790000000000,
	}
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: o.VaultID, ItemID: itemID, Revision: 1,
		MetaCiphertext: metaCT, SecretCiphertext: secretCT,
		VaultWrappedMetaKey: vwMeta, VaultWrappedItemKey: vwItem,
		WriterDeviceID: writerDev,
	})
	if err != nil {
		o.TB.Fatal(err)
	}
	it.FillDigests()
	it.Signature = o.Sign(tb)
	return &SealedItem{Data: it, MetaKey: metaKey, ItemKey: itemKey}
}

// TombstoneRow builds a signed tombstone row for itemID (protocol §3.1
// v2: the tombstone flag is inside the signed transcript).
func (o *Owner) TombstoneRow(itemID, writerDev string, revision uint64) wire.ItemData {
	o.TB.Helper()
	it := wire.ItemData{
		VaultID:        o.VaultID,
		ItemID:         itemID,
		Revision:       revision,
		Tombstone:      true,
		WriterDeviceID: writerDev,
		UpdatedAt:      1790000000000,
	}
	it.FillDigests()
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: o.VaultID, ItemID: itemID, Revision: revision,
		Tombstone: true, WriterDeviceID: writerDev,
	})
	if err != nil {
		o.TB.Fatal(err)
	}
	it.Signature = o.Sign(tb)
	return it
}

// DeleteGrantRow builds a signed grant deletion row (protocol §3.2
// deletion form).
func (o *Owner) DeleteGrantRow(deviceID, itemID, kind string, revision uint64) wire.GrantData {
	o.TB.Helper()
	g := wire.GrantData{
		DeviceID: deviceID,
		ItemID:   itemID,
		Kind:     kind,
		Revision: revision,
		Deleted:  true,
	}
	tb, err := wire.BuildGrantTranscript(g.Transcript(o.VaultID))
	if err != nil {
		o.TB.Fatal(err)
	}
	g.Signature = o.Sign(tb)
	return g
}

func mustAAD(o *Owner, label, itemID string) []byte {
	o.TB.Helper()
	var aad []byte
	var err error
	switch label {
	case "vault-meta-key":
		aad, err = crypto.VaultWrappedMetaKeyAAD(o.VaultID, itemID)
	case "vault-item-key":
		aad, err = crypto.VaultWrappedItemKeyAAD(o.VaultID, itemID)
	}
	if err != nil {
		o.TB.Fatal(err)
	}
	return aad
}

func rand32(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := readRand(b); err != nil {
		t.Fatal(err)
	}
	return b
}
