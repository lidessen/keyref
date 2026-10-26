package itemcrypt

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"errors"
	"testing"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"
)

const (
	fxVault  = "00112233445566778899aabbccddeeff"
	fxItem   = "ffeeddccbbaa99887766554433221100"
	fxDevice = "0123456789abcdef0123456789abcdef"
	fxOther  = "99999999999999999999999999999999"
)

// fixtureSecretValue is the plaintext the tests must never see on any
// output path; it stands in for a real API key.
const fxSecretValue = "sk-PLAINTEXT-FIXTURE-do-not-leak-0123456789"

// fixture assembles an owner-side view: item and meta keys, sealed
// ciphertexts, an owner signing key, and grants wrapped to the CLI
// device. It mirrors what the e2e software owner will do
// (docs/protocol.md §11.2).
type fixture struct {
	ownerSignPriv *ecdsa.PrivateKey
	ownerSignPub  []byte
	cliHPKEPriv   []byte
	cliHPKEPub    []byte

	itemKey []byte
	metaKey []byte

	secretBlob []byte
	metaBlob   []byte

	useGrant  wire.GrantData
	viewGrant wire.GrantData
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{}

	var err error
	f.ownerSignPriv, err = ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatal(err)
	}
	f.ownerSignPub, err = wire.EncodeP256PublicKey(&f.ownerSignPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	f.cliHPKEPub, f.cliHPKEPriv, err = crypto.GenerateHPKEKeyPair(wire.KEMX25519)
	if err != nil {
		t.Fatal(err)
	}

	f.itemKey = bytes.Repeat([]byte{0x51}, 32)
	f.metaKey = bytes.Repeat([]byte{0x4d}, 32)

	secretJSON := []byte(`{"v":1,"value":"` + fxSecretValue + `","username":"deploy","notes":"","fields":{}}`)
	secretAAD, err := crypto.SecretAAD(fxVault, fxItem)
	if err != nil {
		t.Fatal(err)
	}
	f.secretBlob, err = crypto.SealBlob(f.itemKey, secretAAD, secretJSON)
	if err != nil {
		t.Fatal(err)
	}
	metaJSON := []byte(`{"v":1,"ref":"openai-prod","name":"OpenAI production","description":"doc agent","type":"api_key","masked":"sk-****abcd","injectable":true,"policy":{"sensitivity":"standard","commandPolicy":"deny-shells","allowCommands":[],"allowedHosts":["api.openai.com"],"allowArgv":false}}`)
	metaAAD, err := crypto.MetaAAD(fxVault, fxItem)
	if err != nil {
		t.Fatal(err)
	}
	f.metaBlob, err = crypto.SealBlob(f.metaKey, metaAAD, metaJSON)
	if err != nil {
		t.Fatal(err)
	}

	f.useGrant, err = signGrant(t, f, wire.GrantKindUse, f.itemKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	f.viewGrant, err = signGrant(t, f, wire.GrantKindView, f.metaKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func signGrant(t *testing.T, f *fixture, kind string, key []byte, revision uint64) (wire.GrantData, error) {
	t.Helper()
	purpose := crypto.PurposeItemKey
	if kind == wire.GrantKindView {
		purpose = crypto.PurposeMetaKey
	}
	info, err := crypto.Info(purpose, fxVault, fxDevice)
	if err != nil {
		return wire.GrantData{}, err
	}
	enc, wrapped, err := crypto.WrapKey(wire.KEMX25519, f.cliHPKEPub, info, key)
	if err != nil {
		return wire.GrantData{}, err
	}
	g := wire.GrantData{
		DeviceID:   fxDevice,
		ItemID:     fxItem,
		Kind:       kind,
		HPKEEnc:    enc,
		WrappedKey: wrapped,
		ExpiresAt:  1790000000000,
		Revision:   revision,
	}
	tb, err := wire.BuildGrantTranscript(g.Transcript(fxVault))
	if err != nil {
		return wire.GrantData{}, err
	}
	sig, err := wire.SignOwnerECDSA(tb, f.ownerSignPriv)
	if err != nil {
		return wire.GrantData{}, err
	}
	g.Signature = sig
	return g, nil
}

// TestGrantUnwrapAndDecryptRoundtrip covers the full CLI crypto path:
// verify the owner signature on the grant transcript, unwrap the granted
// key into guarded memory, decrypt meta and secret, and read back the
// original plaintexts (ask: decrypt roundtrip).
func TestGrantUnwrapAndDecryptRoundtrip(t *testing.T) {
	f := newFixture(t)

	itemKey, err := UnwrapGrantKey(fxVault, &f.useGrant, f.cliHPKEPriv, f.ownerSignPub)
	if err != nil {
		t.Fatal(err)
	}
	defer itemKey.Destroy()
	if !itemKey.EqualTo(f.itemKey) {
		t.Fatal("unwrapped item key does not match the wrapped key")
	}

	metaKey, err := UnwrapGrantKey(fxVault, &f.viewGrant, f.cliHPKEPriv, f.ownerSignPub)
	if err != nil {
		t.Fatal(err)
	}
	defer metaKey.Destroy()
	if !metaKey.EqualTo(f.metaKey) {
		t.Fatal("unwrapped meta key does not match the wrapped key")
	}

	value, err := DecryptSecretValue(itemKey, f.secretBlob, fxVault, fxItem)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Destroy()
	if !bytes.Equal(value.Bytes(), []byte(fxSecretValue)) {
		t.Fatalf("secret value mismatch: got %q", value.Bytes())
	}

	meta, err := DecryptMeta(metaKey, f.metaBlob, fxVault, fxItem)
	if err != nil {
		t.Fatal(err)
	}
	if meta.Ref != "openai-prod" || meta.Name != "OpenAI production" ||
		meta.Type != "api_key" || meta.Masked != "sk-****abcd" || !meta.Injectable {
		t.Fatalf("meta mismatch: %+v", meta)
	}
	if meta.Policy.Sensitivity != "standard" || meta.Policy.CommandPolicy != "deny-shells" ||
		meta.Policy.AllowArgv || len(meta.Policy.AllowedHosts) != 1 {
		t.Fatalf("meta policy mismatch: %+v", meta.Policy)
	}
}

// TestAADMismatchRejected: ciphertexts must refuse to open under the AAD
// of another item or vault, and tampering must fail closed
// (ask: AAD mismatch rejection; design §4.4).
func TestAADMismatchRejected(t *testing.T) {
	f := newFixture(t)
	itemKey, err := UnwrapGrantKey(fxVault, &f.useGrant, f.cliHPKEPriv, f.ownerSignPub)
	if err != nil {
		t.Fatal(err)
	}
	defer itemKey.Destroy()

	if _, err := DecryptSecretValue(itemKey, f.secretBlob, fxVault, fxOther); err == nil {
		t.Fatal("secret opened under the AAD of another item")
	}
	if _, err := DecryptSecretValue(itemKey, f.secretBlob, fxOther, fxItem); err == nil {
		t.Fatal("secret opened under the AAD of another vault")
	}
	tampered := append([]byte(nil), f.secretBlob...)
	tampered[len(tampered)-1] ^= 1
	if _, err := DecryptSecretValue(itemKey, tampered, fxVault, fxItem); err == nil {
		t.Fatal("tampered secret blob accepted")
	}
	truncated := f.secretBlob[:len(f.secretBlob)-5]
	if _, err := DecryptSecretValue(itemKey, truncated, fxVault, fxItem); err == nil {
		t.Fatal("truncated secret blob accepted")
	}

	metaKey, err := UnwrapGrantKey(fxVault, &f.viewGrant, f.cliHPKEPriv, f.ownerSignPub)
	if err != nil {
		t.Fatal(err)
	}
	defer metaKey.Destroy()
	// meta ciphertext under the meta key, but the secret AAD.
	secretAAD, _ := crypto.SecretAAD(fxVault, fxItem)
	if _, err := crypto.OpenBlob(metaKey.Bytes(), secretAAD, f.metaBlob); err == nil {
		t.Fatal("meta blob opened under the secret AAD")
	}
	if _, err := DecryptMeta(metaKey, f.metaBlob, fxVault, fxOther); err == nil {
		t.Fatal("meta opened under the AAD of another item")
	}
}

// TestGrantSignatureRejectedBeforeUnwrap: a grant whose transcript does
// not verify under the pinned owner key yields no key material at all
// (ask: transcript verification; design §9.1 verify-before-decrypt).
func TestGrantSignatureRejectedBeforeUnwrap(t *testing.T) {
	f := newFixture(t)

	tampered := f.useGrant
	tampered.WrappedKey = append([]byte(nil), f.useGrant.WrappedKey...)
	tampered.WrappedKey[0] ^= 1 // breaks both signature and AEAD
	if _, err := UnwrapGrantKey(fxVault, &tampered, f.cliHPKEPriv, f.ownerSignPub); !errors.Is(err, ErrBadGrantSignature) {
		t.Fatalf("tampered grant: got %v, want ErrBadGrantSignature", err)
	}

	unsigned := f.useGrant
	unsigned.Signature = nil
	if _, err := UnwrapGrantKey(fxVault, &unsigned, f.cliHPKEPriv, f.ownerSignPub); !errors.Is(err, ErrBadGrantSignature) {
		t.Fatalf("unsigned grant: got %v, want ErrBadGrantSignature", err)
	}

	bumped := f.useGrant
	bumped.Revision++
	if _, err := UnwrapGrantKey(fxVault, &bumped, f.cliHPKEPriv, f.ownerSignPub); !errors.Is(err, ErrBadGrantSignature) {
		t.Fatalf("revised grant without re-signing: got %v, want ErrBadGrantSignature", err)
	}

	// A different honest owner must not validate either (pinned keys).
	otherPriv, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatal(err)
	}
	otherPub, err := wire.EncodeP256PublicKey(&otherPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnwrapGrantKey(fxVault, &f.useGrant, f.cliHPKEPriv, otherPub); !errors.Is(err, ErrBadGrantSignature) {
		t.Fatalf("grant verified under a foreign owner key: got %v", err)
	}

	// The intact grant still unwraps after all the rejections above.
	key, err := UnwrapGrantKey(fxVault, &f.useGrant, f.cliHPKEPriv, f.ownerSignPub)
	if err != nil {
		t.Fatal(err)
	}
	key.Destroy()
}

// TestOneTimeWrapBinding: approval wraps open only for the exact
// approval, item and request ciphertext they were made for
// (docs/protocol.md §3.7 D4, design §8.3).
func TestOneTimeWrapBinding(t *testing.T) {
	f := newFixture(t)
	ephPub, ephPriv, err := crypto.GenerateHPKEKeyPair(wire.KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	reqCT := []byte("request ciphertext bytes")
	info, err := crypto.OneTimeItemKeyInfo(fxVault, fxDevice, fxItem, fxOther, reqCT)
	if err != nil {
		t.Fatal(err)
	}
	enc, wrapped, err := crypto.WrapKey(wire.KEMX25519, ephPub, info, f.itemKey)
	if err != nil {
		t.Fatal(err)
	}

	key, err := UnwrapOneTimeItemKey(fxVault, fxDevice, fxItem, fxOther, reqCT, enc, wrapped, ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	if !key.EqualTo(f.itemKey) {
		t.Fatal("one-time key mismatch")
	}

	if _, err := UnwrapOneTimeItemKey(fxVault, fxDevice, fxItem, fxItem, reqCT, enc, wrapped, ephPriv); err == nil {
		t.Fatal("one-time wrap opened for a different approval id")
	}
	if _, err := UnwrapOneTimeItemKey(fxVault, fxDevice, fxOther, fxOther, reqCT, enc, wrapped, ephPriv); err == nil {
		t.Fatal("one-time wrap opened for a different item")
	}
	if _, err := UnwrapOneTimeItemKey(fxVault, fxDevice, fxItem, fxOther, []byte("other request"), enc, wrapped, ephPriv); err == nil {
		t.Fatal("one-time wrap opened for a different request ciphertext")
	}
}

// TestOneTimeSecretUnwrap covers the LOCAL-item decision payload
// (design §6.6, v0.7): the same D4 info binding, but the sealed payload
// is the secret value itself, delivered in guarded memory.
func TestOneTimeSecretUnwrap(t *testing.T) {
	ephPub, ephPriv, err := crypto.GenerateHPKEKeyPair(wire.KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	reqCT := []byte("request ciphertext bytes")
	info, err := crypto.OneTimeItemKeyInfo(fxVault, fxDevice, fxItem, fxOther, reqCT)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{0x3d}, 2048)
	enc, wrapped, err := crypto.WrapKey(wire.KEMX25519, ephPub, info, payload)
	if err != nil {
		t.Fatal(err)
	}
	value, err := UnwrapOneTimeSecret(fxVault, fxDevice, fxItem, fxOther, reqCT, enc, wrapped, ephPriv)
	if err != nil {
		t.Fatal(err)
	}
	if !value.EqualTo(payload) {
		t.Fatal("one-time secret mismatch")
	}
	value.Destroy()
	if len(value.Bytes()) != 0 {
		t.Fatal("one-time secret not wiped by Destroy")
	}

	// The binding is as strict as the item-key path.
	if _, err := UnwrapOneTimeSecret(fxVault, fxDevice, fxItem, fxItem, reqCT, enc, wrapped, ephPriv); err == nil {
		t.Fatal("one-time secret opened for a different approval id")
	}
	if _, err := UnwrapOneTimeSecret(fxVault, fxDevice, fxItem, fxOther, []byte("other request"), enc, wrapped, ephPriv); err == nil {
		t.Fatal("one-time secret opened for a different request ciphertext")
	}
}

// TestGrantKeyIsGuarded: the unwrapped key must live in guarded memory —
// bytes are accessible but the buffer reports alive until destroyed.
func TestGrantKeyIsGuarded(t *testing.T) {
	f := newFixture(t)
	key, err := UnwrapGrantKey(fxVault, &f.useGrant, f.cliHPKEPriv, f.ownerSignPub)
	if err != nil {
		t.Fatal(err)
	}
	if len(key.Bytes()) != 32 {
		t.Fatal("guarded key has wrong size")
	}
	key.Destroy()
	if key.Bytes() != nil {
		t.Fatal("guarded key outlived Destroy")
	}
}
