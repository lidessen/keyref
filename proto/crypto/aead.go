// Package crypto implements the keyref cryptographic core shared by the
// CLI and the e2e software owner: HPKE key wrapping (RFC 9180 via circl),
// AES-256-GCM ciphertext blobs, HPKE info / AAD construction, device key
// generation and recovery-code derivations (docs/protocol.md §1.4–§1.5,
// §3.7–§3.8; design.md §9).
//
// Only proto/crypto may import circl (docs/protocol.md §2.2).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"runtime"
)

// unitSep is the ASCII unit separator used inside HPKE info strings and
// AADs (docs/protocol.md §1.1, §3.7).
func unitSep() byte { return 0x1f }

// domainPrefix starts every info string and AAD (docs/protocol.md §3.7).
const domainPrefix = "keyref v1"

// HPKE info purposes (docs/protocol.md §3.7).
const (
	PurposeVMK             = "vmk"
	PurposeMetaKey         = "meta-key"
	PurposeItemKey         = "item-key"
	PurposeOneTimeItemKey  = "one-time-item-key"
	PurposeAuditEventKey   = "audit-event-key"
	PurposeApprovalRequest = "approval-request"
)

// AAD labels (docs/protocol.md §3.7).
const (
	LabelSecret       = "secret"
	LabelMeta         = "meta"
	LabelVaultMetaKey = "vault-meta-key"
	LabelVaultItemKey = "vault-item-key"
	LabelRecovery     = "recovery"
	LabelAudit        = "audit"
)

// ErrBlob is returned for ciphertext blobs that are too short or fail
// authentication. It never carries key or plaintext material.
var ErrBlob = errors.New("crypto: invalid or unauthenticated blob")

const (
	nonceSize = 12 // AES-GCM random nonce (design §9.1)
	tagSize   = 16
	minBlob   = nonceSize + tagSize
)

// Info builds the HPKE info string
//
//	"keyref v1" <US> purpose <US> vault_id(hex) <US> recipient_device_id(hex)
//
// (docs/protocol.md §3.7). vaultID and recipientDeviceID are validated
// lowercase-hex identifiers.
func Info(purpose, vaultID, recipientDeviceID string) ([]byte, error) {
	if !validHexID(vaultID) || !validHexID(recipientDeviceID) {
		return nil, errors.New("crypto: info ids must be 32 lowercase hex characters")
	}
	b := make([]byte, 0, len(domainPrefix)+1+len(purpose)+1+len(vaultID)+1+len(recipientDeviceID))
	b = append(b, domainPrefix...)
	b = append(b, unitSep())
	b = append(b, purpose...)
	b = append(b, unitSep())
	b = append(b, vaultID...)
	b = append(b, unitSep())
	b = append(b, recipientDeviceID...)
	return b, nil
}

// OneTimeItemKeyInfo builds the info of the one-time item-key wrap
// (docs/protocol.md §3.7, D4): the item-key base info followed by
//
//	<US> item_id(hex) <US> approval_id(hex) <US> SHA-256(request_ciphertext)
//
// so that a wrap is usable only for the very request it answers.
func OneTimeItemKeyInfo(vaultID, recipientDeviceID, itemID, approvalID string, requestCiphertext []byte) ([]byte, error) {
	base, err := Info(PurposeOneTimeItemKey, vaultID, recipientDeviceID)
	if err != nil {
		return nil, err
	}
	if !validHexID(itemID) || !validHexID(approvalID) {
		return nil, errors.New("crypto: info ids must be 32 lowercase hex characters")
	}
	sum := sha256.Sum256(requestCiphertext)
	b := append(base, unitSep())
	b = append(b, itemID...)
	b = append(b, unitSep())
	b = append(b, approvalID...)
	b = append(b, unitSep())
	b = append(b, sum[:]...)
	return b, nil
}

// itemAAD builds "keyref v1 <US> label <US> vault_id(hex) <US> item_id(hex)"
// for meta and secret ciphertexts and for vault-wrapped keys
// (docs/protocol.md §3.7). The AAD deliberately excludes revision
// (design §9.1: rewrapping keys must not require re-encryption).
func itemAAD(label, vaultID, itemID string) ([]byte, error) {
	if !validHexID(vaultID) || !validHexID(itemID) {
		return nil, errors.New("crypto: aad ids must be 32 lowercase hex characters")
	}
	b := make([]byte, 0, len(domainPrefix)+1+len(label)+1+len(vaultID)+1+len(itemID))
	b = append(b, domainPrefix...)
	b = append(b, unitSep())
	b = append(b, label...)
	b = append(b, unitSep())
	b = append(b, vaultID...)
	b = append(b, unitSep())
	b = append(b, itemID...)
	return b, nil
}

// SecretAAD is the AAD of an item secret ciphertext (label "secret").
func SecretAAD(vaultID, itemID string) ([]byte, error) { return itemAAD(LabelSecret, vaultID, itemID) }

// MetaAAD is the AAD of an item meta ciphertext (label "meta").
func MetaAAD(vaultID, itemID string) ([]byte, error) { return itemAAD(LabelMeta, vaultID, itemID) }

// VaultWrappedMetaKeyAAD is the AAD of vault_wrapped_meta_key (label
// "vault-meta-key", docs/protocol.md §3.1).
func VaultWrappedMetaKeyAAD(vaultID, itemID string) ([]byte, error) {
	return itemAAD(LabelVaultMetaKey, vaultID, itemID)
}

// VaultWrappedItemKeyAAD is the AAD of vault_wrapped_item_key (label
// "vault-item-key", docs/protocol.md §3.1).
func VaultWrappedItemKeyAAD(vaultID, itemID string) ([]byte, error) {
	return itemAAD(LabelVaultItemKey, vaultID, itemID)
}

// RecoveryAAD is the AAD of recovery_wrap (docs/protocol.md §3.7).
func RecoveryAAD(vaultID string) ([]byte, error) {
	if !validHexID(vaultID) {
		return nil, errors.New("crypto: aad ids must be 32 lowercase hex characters")
	}
	b := []byte(domainPrefix)
	b = append(b, unitSep())
	b = append(b, LabelRecovery...)
	b = append(b, unitSep())
	b = append(b, vaultID...)
	return b, nil
}

// AuditAAD is the AAD of an audit-event AES segment; deviceID is the
// reporting device (docs/protocol.md §3.7).
func AuditAAD(vaultID, deviceID string) ([]byte, error) {
	if !validHexID(vaultID) || !validHexID(deviceID) {
		return nil, errors.New("crypto: aad ids must be 32 lowercase hex characters")
	}
	b := []byte(domainPrefix)
	b = append(b, unitSep())
	b = append(b, LabelAudit...)
	b = append(b, unitSep())
	b = append(b, vaultID...)
	b = append(b, unitSep())
	b = append(b, deviceID...)
	return b, nil
}

func validHexID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("crypto: AES-256 key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// SealBlob encrypts plaintext with AES-256-GCM under a fresh random
// nonce and returns the blob layout nonce(12) ‖ ct ‖ tag(16)
// (docs/protocol.md §1.5).
//
// NOTE: the AEAD key schedule expands derived round keys on the Go heap;
// callers holding the key in guarded memory accept this residual per
// design §12.2 (B1/B2). Plaintext is copied into the returned slice only.
func SealBlob(key, aad, plaintext []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("crypto: nonce generation failed: %w", err)
	}
	return aead.Seal(nonce, nonce, plaintext, aad), nil
}

// OpenBlob decrypts a blob produced by SealBlob. The plaintext is
// returned on the ordinary Go heap: use OpenBlobInto with guarded memory
// for secrets (design §12.2).
func OpenBlob(key, aad, blob []byte) ([]byte, error) {
	return openBlob(nil, key, aad, blob)
}

// OpenBlobInto decrypts a blob appending the plaintext to dst, which must
// have spare capacity for len(blob)-28 bytes (e.g. a guarded buffer).
// When capacity suffices the returned slice aliases dst and no plaintext
// is placed on the Go heap.
func OpenBlobInto(dst, key, aad, blob []byte) ([]byte, error) {
	return openBlob(dst, key, aad, blob)
}

func openBlob(dst, key, aad, blob []byte) ([]byte, error) {
	aead, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(blob) < minBlob {
		return nil, ErrBlob
	}
	pt, err := aead.Open(dst, blob[:nonceSize], blob[nonceSize:], aad)
	if err != nil {
		return nil, ErrBlob
	}
	return pt, nil
}

// WipeKey best-effort zeroes a symmetric key slice that briefly lived
// on the ordinary heap (for example the audit event key after
// sealing). KeepAlive pins the writes against dead-code elimination.
func WipeKey(key []byte) {
	for i := range key {
		key[i] = 0
	}
	runtime.KeepAlive(key)
}
