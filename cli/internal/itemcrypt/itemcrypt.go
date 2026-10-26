// Package itemcrypt is the CLI-side decryption path: it verifies owner
// signatures on grants, unwraps granted meta and item keys with HPKE,
// and decrypts item meta and secret ciphertexts with AES-256-GCM
// (docs/protocol.md §3.7; design.md §6.5, §9).
//
// Unwrapped keys and secret plaintexts live exclusively in guarded
// memory (design.md §12.2): keys in secret.Key buffers, the secret value
// in a guarded memguard buffer extracted from the decrypted JSON without
// any heap string. Meta plaintext is decrypted into guarded memory and
// then parsed with encoding/json: meta fields (ref, name, masked) are
// presented to the agent in list/get output anyway, so their heap
// residency is bounded by what the product already shows
// (design.md §6.5, §12.2).
package itemcrypt

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/secret"
)

// ErrBadGrantSignature reports that a grant row did not verify under the
// pinned owner key; no key material is unwrapped in that case
// (design.md §9.1: clients verify signatures before decrypting).
var ErrBadGrantSignature = errors.New("itemcrypt: grant signature verification failed")

// ErrDecrypt wraps AEAD and HPKE failures without echoing any ciphertext
// or key bytes.
var ErrDecrypt = errors.New("itemcrypt: decrypt failed")

// UnwrapGrantKey verifies the grant transcript against the pinned owner
// signing key and unwraps the granted key for this device into guarded
// memory. view grants carry the meta key (purpose meta-key), use grants
// carry the item key (purpose item-key); the HPKE info binds vault and
// recipient device (docs/protocol.md §3.7). hpkePrivate is the CLI
// device's scheme-marshaled X25519 private key.
func UnwrapGrantKey(vaultID string, grant *wire.GrantData, hpkePrivate, ownerSignPublicKey []byte) (*secret.Key, error) {
	if err := grant.VerifyOwnerSignature(vaultID, ownerSignPublicKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrBadGrantSignature, err)
	}
	var purpose string
	switch grant.Kind {
	case wire.GrantKindView:
		purpose = crypto.PurposeMetaKey
	case wire.GrantKindUse:
		purpose = crypto.PurposeItemKey
	default:
		return nil, fmt.Errorf("%w: unknown grant kind", ErrDecrypt)
	}
	info, err := crypto.Info(purpose, vaultID, grant.DeviceID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	pt, err := crypto.UnwrapKey(wire.KEMX25519, hpkePrivate, info, grant.HPKEEnc, grant.WrappedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	// circl returned the key on the ordinary heap: move it into guarded
	// memory, which wipes this intermediate in constant time.
	key, err := secret.NewKey(pt)
	if err != nil {
		secret.Wipe(pt)
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return key, nil
}

// UnwrapOneTimeItemKey unwraps an approval-driven one-time item-key wrap.
// The HPKE info binds vault, recipient device, item, approval and the
// SHA-256 of the request ciphertext (docs/protocol.md §3.7, D4; design
// §8.3), so a wrap answered to any other request or item fails to open.
// The device uses a fresh ephemeral X25519 key per request
// (design §8.3); hpkePrivate is that key.
func UnwrapOneTimeItemKey(vaultID, deviceID, itemID, approvalID string, requestCiphertext, enc, wrappedKey, hpkePrivate []byte) (*secret.Key, error) {
	info, err := oneTimeInfo(vaultID, deviceID, itemID, approvalID, requestCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	pt, err := crypto.UnwrapKey(wire.KEMX25519, hpkePrivate, info, enc, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	key, err := secret.NewKey(pt)
	if err != nil {
		secret.Wipe(pt)
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return key, nil
}

// UnwrapOneTimeSecret unwraps the decision payload of a LOCAL item
// (design §6.6, v0.7): the owner HPKE-sealed the secret value itself —
// not an item key — to the request's ephemeral public key, under the
// SAME one-time info binding (purpose=one-time-item-key + item, approval
// and request digest). The plaintext lands directly in guarded memory
// and the HPKE intermediate is wiped: the value exists for this single
// exec only, never in the cache or the keyring (design §15).
func UnwrapOneTimeSecret(vaultID, deviceID, itemID, approvalID string, requestCiphertext, enc, wrappedKey, hpkePrivate []byte) (*secret.Plaintext, error) {
	info, err := oneTimeInfo(vaultID, deviceID, itemID, approvalID, requestCiphertext)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	pt, err := crypto.UnwrapKey(wire.KEMX25519, hpkePrivate, info, enc, wrappedKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	value, err := secret.NewPlaintextFromBytes(pt)
	if err != nil {
		secret.Wipe(pt)
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return value, nil
}

// oneTimeInfo builds the D4 one-time wrap info shared by both payload
// kinds (item key for synced approval items, the secret itself for
// local items — the server cannot tell them apart).
func oneTimeInfo(vaultID, deviceID, itemID, approvalID string, requestCiphertext []byte) ([]byte, error) {
	return crypto.OneTimeItemKeyInfo(vaultID, deviceID, itemID, approvalID, requestCiphertext)
}

// Meta is the decrypted meta plaintext of an item (design.md §6.1).
// list and get display these fields; they never decrypt the secret.
type Meta struct {
	V           int        `json:"v"`
	Ref         string     `json:"ref"`
	Name        string     `json:"name"`
	Description string     `json:"description"`
	Type        string     `json:"type"`
	Masked      string     `json:"masked"`
	Injectable  bool       `json:"injectable"`
	Policy      MetaPolicy `json:"policy"`
}

// MetaPolicy is the per-item policy block (design.md §6.1).
type MetaPolicy struct {
	Sensitivity   string   `json:"sensitivity"`
	CommandPolicy string   `json:"commandPolicy"`
	AllowCommands []string `json:"allowCommands"`
	AllowedHosts  []string `json:"allowedHosts"`
	AllowArgv     bool     `json:"allowArgv"`
}

// DecryptMeta decrypts an item meta ciphertext with a guarded meta key.
// The AAD binds vault and item but not revision (design.md §9.1).
func DecryptMeta(key *secret.Key, blob []byte, vaultID, itemID string) (*Meta, error) {
	aad, err := crypto.MetaAAD(vaultID, itemID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	pt, err := crypto.OpenBlob(key.Bytes(), aad, blob)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	defer secret.Wipe(pt)
	var m Meta
	if err := unmarshalStrict(pt, &m); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	return &m, nil
}

// DecryptSecretValue decrypts an item secret ciphertext with a guarded
// item key and returns just the "value" field in guarded memory. The
// full decrypted JSON lives in guarded memory only for the duration of
// the extraction and is wiped afterwards (design.md §6.5: secret
// plaintext exists only during a single use; §12.2: no heap strings).
// The caller must Destroy the returned value.
func DecryptSecretValue(key *secret.Key, blob []byte, vaultID, itemID string) (*secret.Plaintext, error) {
	aad, err := crypto.SecretAAD(vaultID, itemID)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	jsonBuf, err := secret.NewPlaintext(len(blob))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	// Open into the guarded buffer: AEAD.Open appends within capacity,
	// so the plaintext never lands on the Go heap.
	pt, err := crypto.OpenBlobInto(jsonBuf.Bytes()[:0], key.Bytes(), aad, blob)
	if err != nil {
		jsonBuf.Destroy()
		return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
	}
	value, err := secret.ExtractStringField(pt, "value")
	jsonBuf.Destroy() // wipes the full decrypted JSON
	if err != nil {
		if errors.Is(err, secret.ErrFieldNotFound) || errors.Is(err, secret.ErrSyntax) ||
			errors.Is(err, secret.ErrNotAString) {
			return nil, fmt.Errorf("%w: %v", ErrDecrypt, err)
		}
		return nil, err
	}
	return value, nil
}

// unmarshalStrict decodes JSON rejecting unknown fields, so a malformed
// or future-format plaintext fails loudly instead of half-applying
// (same policy as the wire layer, docs/protocol.md §1.2).
func unmarshalStrict(data []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}
