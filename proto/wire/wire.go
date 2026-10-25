// Package wire implements the keyref wire-protocol transcript and
// entity-id formats defined in docs/protocol.md §3 and §8.2.
//
// This file carries the JSON data shapes of protocol §8 (sync changes) and
// §1.1 (binary fields as standard Base64). The transcript builders and
// signature verification live in transcript.go and signature.go.
//
// Only the standard library is used in this package (protocol §2.2).
package wire

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// Blob is a binary field carried inside JSON as standard Base64 with
// padding (RFC 4648, docs/protocol.md §1.1).
type Blob []byte

func (b Blob) MarshalJSON() ([]byte, error) {
	return json.Marshal(base64.StdEncoding.EncodeToString(b))
}

func (b *Blob) UnmarshalJSON(p []byte) error {
	var s string
	if err := json.Unmarshal(p, &s); err != nil {
		return fmt.Errorf("blob field is not a base64 string: %w", err)
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("blob field is not valid standard base64: %w", err)
	}
	*b = raw
	return nil
}

// ItemData is the item row as delivered by GET /v1/items and by the sync
// "item" entity data (docs/protocol.md §6.9, §8.3). Owner devices receive
// the full row; CLI devices receive vault_wrapped_* zero-length (§8.3:
// those columns are owner-only), and the CLI therefore cannot rebuild item
// transcripts — its integrity guarantees are the owner-signed grants, the
// AEAD tags of the ciphertexts and revision monotonicity (design §6.5).
type ItemData struct {
	VaultID             string `json:"vault_id"`
	ItemID              string `json:"item_id"`
	Revision            uint64 `json:"revision"`
	Tombstone           bool   `json:"tombstone"`
	MetaCiphertext      Blob   `json:"meta_ciphertext"`
	SecretCiphertext    Blob   `json:"secret_ciphertext"`
	VaultWrappedMetaKey Blob   `json:"vault_wrapped_meta_key"`
	VaultWrappedItemKey Blob   `json:"vault_wrapped_item_key"`
	WriterDeviceID      string `json:"writer_device_id"`
	Signature           Blob   `json:"signature"`
	UpdatedAt           int64  `json:"updated_at"`
}

// Validate checks the identifier fields of an item row.
func (i *ItemData) Validate() error {
	for _, f := range []struct{ name, id string }{
		{"vault_id", i.VaultID},
		{"item_id", i.ItemID},
		{"writer_device_id", i.WriterDeviceID},
	} {
		if err := requireID(f.name, f.id); err != nil {
			return err
		}
	}
	if i.Revision < 1 {
		return fmt.Errorf("%w: revision must be >= 1", ErrInvalidField)
	}
	return nil
}

// GrantData is a grant row (docs/protocol.md §8.3, §3.2): the wire form of
// PUT /v1/grants entries, of grants/self rows, and of sync "grant" data.
// Deleted rows are carried by sync with Deleted=true, a bumped Revision
// and empty crypto fields; their transcript is the deletion form (§3.2).
type GrantData struct {
	DeviceID   string `json:"device_id"`
	ItemID     string `json:"item_id"`
	Kind       string `json:"kind"` // view | use
	HPKEEnc    Blob   `json:"hpke_enc"`
	WrappedKey Blob   `json:"wrapped_key"`
	ExpiresAt  int64  `json:"expires_at"` // unix milliseconds; 0 = never
	Revision   uint64 `json:"revision"`
	Signature  Blob   `json:"signature"`
	Deleted    bool   `json:"deleted,omitempty"`
}

// Validate checks the identifier fields, kind and revision of a grant row.
func (g *GrantData) Validate() error {
	for _, f := range []struct{ name, id string }{
		{"device_id", g.DeviceID},
		{"item_id", g.ItemID},
	} {
		if err := requireID(f.name, f.id); err != nil {
			return err
		}
	}
	if err := requireGrantKind(g.Kind); err != nil {
		return err
	}
	if g.Revision < 1 {
		return fmt.Errorf("%w: revision must be >= 1", ErrInvalidField)
	}
	if g.ExpiresAt < 0 {
		return fmt.Errorf("%w: expires_at must be >= 0", ErrInvalidField)
	}
	if (len(g.HPKEEnc) == 0) != (len(g.WrappedKey) == 0) {
		return fmt.Errorf("%w: hpke_enc and wrapped_key must be both empty or both present", ErrInvalidField)
	}
	return nil
}

// Transcript returns the structured grant transcript of this row
// (docs/protocol.md §3.2). Deleted rows produce the deletion form.
// The vault id is supplied by the caller's context (VaultID field of the
// enclosing object); see VerifyOwnerSignature.
func (g *GrantData) Transcript(vaultID string) GrantTranscript {
	return GrantTranscript{
		VaultID:    vaultID,
		DeviceID:   g.DeviceID,
		ItemID:     g.ItemID,
		Kind:       g.Kind,
		Revision:   g.Revision,
		ExpiresAt:  uint64(g.ExpiresAt),
		HPKEEnc:    g.HPKEEnc,
		WrappedKey: g.WrappedKey,
	}
}

// VerifyOwnerSignature checks the row's signature by rebuilding its
// transcript (write-only transcripts, protocol §1.5/D3). vaultID is the
// vault the row was received for; it is not carried in the JSON.
func (g *GrantData) VerifyOwnerSignature(vaultID string, ownerSignPublicKey []byte) error {
	tb, err := BuildGrantTranscript(g.Transcript(vaultID))
	if err != nil {
		return err
	}
	return VerifyOwnerSignature(tb, g.Signature, ownerSignPublicKey)
}

// DeviceData is the sync "device" entity data (docs/protocol.md §8.3):
// status summary of a device row, without key material.
type DeviceData struct {
	DeviceID  string `json:"device_id"`
	Kind      string `json:"kind"`
	Status    string `json:"status"`
	Label     string `json:"label"`
	CreatedAt int64  `json:"created_at"`
	RevokedAt *int64 `json:"revoked_at"`
}

// DirectoryData is the sync "directory" entity data (docs/protocol.md
// §8.3): the signed transcript blob and its owner signature.
type DirectoryData struct {
	DirectoryRevision uint64 `json:"directory_revision"`
	Signed            Blob   `json:"directory_signed"`
	Signature         Blob   `json:"directory_signature"`
}

// SyncChange is one row of a sync response (docs/protocol.md §8.1). Data
// holds the raw JSON object whose shape depends on Entity.
type SyncChange struct {
	Seq       int64           `json:"seq"`
	Entity    string          `json:"entity"`
	EntityID  string          `json:"entity_id"`
	CreatedAt int64           `json:"created_at"`
	Data      json.RawMessage `json:"data"`
}

// SyncResponse is the payload of GET /v1/sync (docs/protocol.md §8.1).
type SyncResponse struct {
	Cursor  int64        `json:"cursor"`
	HasMore bool         `json:"has_more"`
	Changes []SyncChange `json:"changes"`
}
