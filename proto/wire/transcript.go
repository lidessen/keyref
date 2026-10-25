// Package wire implements the keyref wire-protocol transcript and
// entity-id formats defined in docs/protocol.md §3 and §8.2.
//
// Transcripts are write-only byte strings: a signer assembles them from
// structured fields in the exact order the protocol fixes, and a verifier
// rebuilds the very same bytes from the structured fields it wants to
// assert, then checks the signature over them (protocol §1.5, decision
// D3). Transcripts must never be parsed by splitting on NUL separators:
// binary fields such as ciphertexts and public keys may contain 0x00.
//
// Only the standard library is used in this package (protocol §2.2).
package wire

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// fieldSep separates fields inside a signed transcript (protocol §1.1).
const fieldSep byte = 0x00

// TranscriptPrefix is the ASCII prefix every transcript starts with
// (protocol §3).
const TranscriptPrefix = "KEYREF1"

// Fixed binary field sizes in bytes (protocol §1.4).
const (
	SizeX25519Key  = 32
	SizeP256Key    = 65
	SizeEd25519Key = 32
	SizeDigest     = 32
	SizeChallenge  = 32
	SizePairNonce  = 16
)

// Algorithm identifiers carried in the devices table and in JSON
// (protocol §1.4).
const (
	KEMX25519 = "X25519"
	KEMP256   = "P-256"

	SignAlgEd25519   = "ed25519"
	SignAlgECDSAP256 = "ecdsa-p256"
)

// Device kinds and statuses (design §6.3).
const (
	DeviceKindIOS = "ios"
	DeviceKindCLI = "cli"

	DeviceStatusPending = "pending"
	DeviceStatusActive  = "active"
	DeviceStatusRevoked = "revoked"
)

// Grant kinds (design §6.3): view wraps the meta key, use wraps the item
// key.
const (
	GrantKindView = "view"
	GrantKindUse  = "use"
)

// LabelNameMaxBytes bounds user-chosen device labels and proposed pairing
// names (design §6.4).
const LabelNameMaxBytes = 32

// Errors returned for malformed inputs and failed signature checks.
// Error messages never contain field values, only field names.
var (
	ErrInvalidField = errors.New("wire: invalid transcript field")
	ErrBadSignature = errors.New("wire: signature verification failed")
)

// ValidID reports whether s is a 16-byte identifier encoded as 32
// lowercase hex characters (protocol §1.1).
func ValidID(s string) bool {
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

func requireID(name, v string) error {
	if !ValidID(v) {
		return fmt.Errorf("%w: %s must be 32 lowercase hex characters", ErrInvalidField, name)
	}
	return nil
}

func requireKEM(kem string) error {
	if kem != KEMX25519 && kem != KEMP256 {
		return fmt.Errorf("%w: hpke_kem must be %q or %q", ErrInvalidField, KEMX25519, KEMP256)
	}
	return nil
}

func requireSignAlg(alg string) error {
	if alg != SignAlgEd25519 && alg != SignAlgECDSAP256 {
		return fmt.Errorf("%w: sign_alg must be %q or %q", ErrInvalidField, SignAlgEd25519, SignAlgECDSAP256)
	}
	return nil
}

func requireHPKEKey(name, kem string, pub []byte) error {
	if err := requireKEM(kem); err != nil {
		return err
	}
	want := kemKeySize(kem)
	if len(pub) != want {
		return fmt.Errorf("%w: %s must be %d bytes for hpke_kem %s", ErrInvalidField, name, want, kem)
	}
	return nil
}

func requireSignKey(name, alg string, pub []byte) error {
	if err := requireSignAlg(alg); err != nil {
		return err
	}
	want := signKeySize(alg)
	if len(pub) != want {
		return fmt.Errorf("%w: %s must be %d bytes for sign_alg %s", ErrInvalidField, name, want, alg)
	}
	return nil
}

func requireGrantKind(kind string) error {
	if kind != GrantKindView && kind != GrantKindUse {
		return fmt.Errorf("%w: kind must be %q or %q", ErrInvalidField, GrantKindView, GrantKindUse)
	}
	return nil
}

func kemKeySize(kem string) int {
	switch kem {
	case KEMX25519:
		return SizeX25519Key
	case KEMP256:
		return SizeP256Key
	}
	return -1
}

func signKeySize(alg string) int {
	switch alg {
	case SignAlgEd25519:
		return SizeEd25519Key
	case SignAlgECDSAP256:
		return SizeP256Key
	}
	return -1
}

// beginTranscript starts a transcript of the given record kind.
func beginTranscript(kind string) []byte {
	b := make([]byte, 0, 128)
	b = append(b, TranscriptPrefix...)
	b = append(b, fieldSep)
	b = append(b, kind...)
	b = append(b, fieldSep)
	return b
}

func appendSep(b []byte) []byte { return append(b, fieldSep) }

func appendU64(b []byte, v uint64) []byte {
	var t [8]byte
	binary.BigEndian.PutUint64(t[:], v)
	return append(b, t[:]...)
}

// ItemTranscript is the structured form of the item transcript
// (protocol §3.1). A tombstone row carries four zero-length ciphertext
// fields; every other rule is unchanged.
type ItemTranscript struct {
	VaultID             string
	ItemID              string
	Revision            uint64 // >= 1, monotonically increasing (design §6.2)
	MetaCiphertext      []byte
	SecretCiphertext    []byte
	VaultWrappedMetaKey []byte
	VaultWrappedItemKey []byte
	WriterDeviceID      string
}

// BuildItemTranscript assembles the signed transcript bytes:
//
//	"KEYREF1" NUL "item" NUL vault_id(hex) NUL item_id(hex) NUL
//	u64be(revision) NUL meta_ciphertext NUL secret_ciphertext NUL
//	vault_wrapped_meta_key NUL vault_wrapped_item_key NUL
//	writer_device_id(hex)
//
// There is no trailing NUL.
func BuildItemTranscript(t ItemTranscript) ([]byte, error) {
	for _, f := range []struct{ name, id string }{
		{"vault_id", t.VaultID},
		{"item_id", t.ItemID},
		{"writer_device_id", t.WriterDeviceID},
	} {
		if err := requireID(f.name, f.id); err != nil {
			return nil, err
		}
	}
	if t.Revision < 1 {
		return nil, fmt.Errorf("%w: revision must be >= 1", ErrInvalidField)
	}
	b := beginTranscript("item")
	b = append(b, t.VaultID...)
	b = appendSep(b)
	b = append(b, t.ItemID...)
	b = appendSep(b)
	b = appendU64(b, t.Revision)
	b = appendSep(b)
	b = append(b, t.MetaCiphertext...)
	b = appendSep(b)
	b = append(b, t.SecretCiphertext...)
	b = appendSep(b)
	b = append(b, t.VaultWrappedMetaKey...)
	b = appendSep(b)
	b = append(b, t.VaultWrappedItemKey...)
	b = appendSep(b)
	b = append(b, t.WriterDeviceID...)
	return b, nil
}

// GrantTranscript is the structured form of the grant transcript
// (protocol §3.2). The deletion form uses the same layout with
// ExpiresAt 0 and both HPKEEnc and WrappedKey empty.
type GrantTranscript struct {
	VaultID    string
	DeviceID   string
	ItemID     string
	Kind       string // view | use
	Revision   uint64 // >= 1, owner-side monotonic (design §6.3)
	ExpiresAt  uint64 // unix milliseconds, 0 = never expires (protocol D5)
	HPKEEnc    []byte // KEM encapsulation, empty only in deletion form
	WrappedKey []byte // HPKE ciphertext, empty only in deletion form
}

// BuildGrantTranscript assembles the signed transcript bytes:
//
//	"KEYREF1" NUL "grant" NUL vault_id(hex) NUL device_id(hex) NUL
//	item_id(hex) NUL kind NUL u64be(revision) NUL u64be(expires_at) NUL
//	hpke_enc NUL wrapped_key
//
// There is no trailing NUL.
func BuildGrantTranscript(t GrantTranscript) ([]byte, error) {
	for _, f := range []struct{ name, id string }{
		{"vault_id", t.VaultID},
		{"device_id", t.DeviceID},
		{"item_id", t.ItemID},
	} {
		if err := requireID(f.name, f.id); err != nil {
			return nil, err
		}
	}
	if err := requireGrantKind(t.Kind); err != nil {
		return nil, err
	}
	if t.Revision < 1 {
		return nil, fmt.Errorf("%w: revision must be >= 1", ErrInvalidField)
	}
	if (len(t.HPKEEnc) == 0) != (len(t.WrappedKey) == 0) {
		return nil, fmt.Errorf("%w: hpke_enc and wrapped_key must be both empty (deletion form) or both present", ErrInvalidField)
	}
	b := beginTranscript("grant")
	b = append(b, t.VaultID...)
	b = appendSep(b)
	b = append(b, t.DeviceID...)
	b = appendSep(b)
	b = append(b, t.ItemID...)
	b = appendSep(b)
	b = append(b, t.Kind...)
	b = appendSep(b)
	b = appendU64(b, t.Revision)
	b = appendSep(b)
	b = appendU64(b, t.ExpiresAt)
	b = appendSep(b)
	b = append(b, t.HPKEEnc...)
	b = appendSep(b)
	b = append(b, t.WrappedKey...)
	return b, nil
}

// sortGrantTranscripts orders grants by (item_id hex ascending, kind byte
// ascending); ASCII "use" sorts before "view" (protocol §3.3, D6).
func sortGrantTranscripts(gs []GrantTranscript) {
	slices.SortStableFunc(gs, func(a, b GrantTranscript) int {
		if c := strings.Compare(a.ItemID, b.ItemID); c != 0 {
			return c
		}
		return strings.Compare(a.Kind, b.Kind)
	})
}

// GrantsDigest computes the per-device grants digest carried in
// directory records (protocol §3.3): the SHA-256 over the concatenation
// of the device's grant transcripts ordered by (item_id ascending, kind
// byte ascending). All grants must belong to the same vault and device.
// An empty grant set digests the empty string.
func GrantsDigest(grants []GrantTranscript) ([]byte, error) {
	sorted := slices.Clone(grants)
	sortGrantTranscripts(sorted)
	h := sha256.New()
	for _, g := range sorted {
		if g.VaultID != sorted[0].VaultID || g.DeviceID != sorted[0].DeviceID {
			return nil, fmt.Errorf("%w: grants_digest covers the grants of a single device", ErrInvalidField)
		}
		tb, err := BuildGrantTranscript(g)
		if err != nil {
			return nil, err
		}
		h.Write(tb)
	}
	return h.Sum(nil), nil
}

// DirectoryDevice is one device record inside a directory transcript
// (protocol §3.3).
type DirectoryDevice struct {
	DeviceID             string
	Kind                 string // ios | cli
	Status               string // pending | active | revoked
	HPKEKEM              string // X25519 | P-256
	HPKEPublicKey        []byte
	SignAlg              string // ed25519 | ecdsa-p256
	SignPublicKey        []byte
	RenewalSignPublicKey []byte // Ed25519, zero length when the device has none
	GrantsDigest         []byte // 32-byte SHA-256 from GrantsDigest
}

// DirectoryTranscript is the structured form of the signed device
// directory (protocol §3.3).
type DirectoryTranscript struct {
	VaultID           string
	DirectoryRevision uint64 // >= 1
	Devices           []DirectoryDevice
}

func validateDirectoryDevice(d DirectoryDevice) error {
	if err := requireID("device_id", d.DeviceID); err != nil {
		return err
	}
	if d.Kind != DeviceKindIOS && d.Kind != DeviceKindCLI {
		return fmt.Errorf("%w: kind must be %q or %q", ErrInvalidField, DeviceKindIOS, DeviceKindCLI)
	}
	if d.Status != DeviceStatusPending && d.Status != DeviceStatusActive && d.Status != DeviceStatusRevoked {
		return fmt.Errorf("%w: status must be %q, %q or %q", ErrInvalidField,
			DeviceStatusPending, DeviceStatusActive, DeviceStatusRevoked)
	}
	if err := requireHPKEKey("hpke_public_key", d.HPKEKEM, d.HPKEPublicKey); err != nil {
		return err
	}
	if err := requireSignKey("sign_public_key", d.SignAlg, d.SignPublicKey); err != nil {
		return err
	}
	if n := len(d.RenewalSignPublicKey); n != 0 && n != SizeEd25519Key {
		return fmt.Errorf("%w: renewal_sign_public_key must be empty or %d bytes", ErrInvalidField, SizeEd25519Key)
	}
	if len(d.GrantsDigest) != SizeDigest {
		return fmt.Errorf("%w: grants_digest must be %d bytes", ErrInvalidField, SizeDigest)
	}
	return nil
}

// BuildDirectoryTranscript assembles the signed transcript bytes:
//
//	"KEYREF1" NUL "directory" NUL vault_id(hex) NUL
//	u64be(directory_revision) NUL
//	<device records ordered by device_id hex ascending, joined by a
//	 single NUL, no trailing NUL>
//
// with each record:
//
//	device_id(hex) NUL kind NUL status NUL hpke_kem NUL hpke_public_key
//	NUL sign_alg NUL sign_public_key NUL renewal_sign_public_key NUL
//	grants_digest(32 raw bytes)
//
// The input devices are sorted by device_id; duplicates are rejected.
func BuildDirectoryTranscript(t DirectoryTranscript) ([]byte, error) {
	if err := requireID("vault_id", t.VaultID); err != nil {
		return nil, err
	}
	if t.DirectoryRevision < 1 {
		return nil, fmt.Errorf("%w: directory_revision must be >= 1", ErrInvalidField)
	}
	sorted := slices.Clone(t.Devices)
	slices.SortStableFunc(sorted, func(a, b DirectoryDevice) int {
		return strings.Compare(a.DeviceID, b.DeviceID)
	})
	b := beginTranscript("directory")
	b = append(b, t.VaultID...)
	b = appendSep(b)
	b = appendU64(b, t.DirectoryRevision)
	b = appendSep(b)
	for i, d := range sorted {
		if err := validateDirectoryDevice(d); err != nil {
			return nil, err
		}
		if i > 0 {
			if d.DeviceID == sorted[i-1].DeviceID {
				return nil, fmt.Errorf("%w: duplicate device_id in directory", ErrInvalidField)
			}
			b = appendSep(b)
		}
		b = append(b, d.DeviceID...)
		b = appendSep(b)
		b = append(b, d.Kind...)
		b = appendSep(b)
		b = append(b, d.Status...)
		b = appendSep(b)
		b = append(b, d.HPKEKEM...)
		b = appendSep(b)
		b = append(b, d.HPKEPublicKey...)
		b = appendSep(b)
		b = append(b, d.SignAlg...)
		b = appendSep(b)
		b = append(b, d.SignPublicKey...)
		b = appendSep(b)
		b = append(b, d.RenewalSignPublicKey...)
		b = appendSep(b)
		b = append(b, d.GrantsDigest...)
	}
	return b, nil
}

// PairTranscript is the structured form of the pairing transcript signed
// by the owner at pair completion (protocol §3.4).
type PairTranscript struct {
	VaultID            string
	OwnerSignPublicKey []byte // SEC1 uncompressed P-256 point, 65 bytes
	Nonce              string // 16-byte pairing nonce as 32 hex characters
	DeviceID           string // the CLI device being admitted
	HPKEKEM            string
	HPKEPublicKey      []byte
	SignAlg            string
	SignPublicKey      []byte
	Label              string            // utf-8, at most 32 bytes
	Grants             []GrantTranscript // sorted by (item_id, kind) by the builder
}

// BuildPairTranscript assembles the signed transcript bytes:
//
//	"KEYREF1" NUL "pair" NUL vault_id(hex) NUL owner_sign_public_key NUL
//	nonce(hex) NUL device_id(hex) NUL hpke_kem NUL hpke_public_key NUL
//	sign_alg NUL sign_public_key NUL label(utf-8) NUL
//	u64be(grant_count) NUL <grant transcripts sorted by (item_id, kind),
//	concatenated with no separator>
func BuildPairTranscript(t PairTranscript) ([]byte, error) {
	for _, f := range []struct{ name, id string }{
		{"vault_id", t.VaultID},
		{"nonce", t.Nonce},
		{"device_id", t.DeviceID},
	} {
		if err := requireID(f.name, f.id); err != nil {
			return nil, err
		}
	}
	if len(t.OwnerSignPublicKey) != SizeP256Key || t.OwnerSignPublicKey[0] != 0x04 {
		return nil, fmt.Errorf("%w: owner_sign_public_key must be a %d-byte uncompressed P-256 point", ErrInvalidField, SizeP256Key)
	}
	if err := requireHPKEKey("hpke_public_key", t.HPKEKEM, t.HPKEPublicKey); err != nil {
		return nil, err
	}
	if err := requireSignKey("sign_public_key", t.SignAlg, t.SignPublicKey); err != nil {
		return nil, err
	}
	if !utf8.ValidString(t.Label) || len(t.Label) > LabelNameMaxBytes {
		return nil, fmt.Errorf("%w: label must be valid utf-8 of at most %d bytes", ErrInvalidField, LabelNameMaxBytes)
	}
	grants := slices.Clone(t.Grants)
	sortGrantTranscripts(grants)
	for _, g := range grants {
		if g.VaultID != t.VaultID {
			return nil, fmt.Errorf("%w: grant vault_id does not match the pair transcript", ErrInvalidField)
		}
		if g.DeviceID != t.DeviceID {
			return nil, fmt.Errorf("%w: grant device_id does not match the paired device", ErrInvalidField)
		}
	}
	b := beginTranscript("pair")
	b = append(b, t.VaultID...)
	b = appendSep(b)
	b = append(b, t.OwnerSignPublicKey...)
	b = appendSep(b)
	b = append(b, t.Nonce...)
	b = appendSep(b)
	b = append(b, t.DeviceID...)
	b = appendSep(b)
	b = append(b, t.HPKEKEM...)
	b = appendSep(b)
	b = append(b, t.HPKEPublicKey...)
	b = appendSep(b)
	b = append(b, t.SignAlg...)
	b = appendSep(b)
	b = append(b, t.SignPublicKey...)
	b = appendSep(b)
	b = append(b, t.Label...)
	b = appendSep(b)
	b = appendU64(b, uint64(len(grants)))
	b = appendSep(b)
	for _, g := range grants {
		gb, err := BuildGrantTranscript(g)
		if err != nil {
			return nil, err
		}
		b = append(b, gb...)
	}
	return b, nil
}

// BuildPairRegisterTranscript assembles the transcript signed by the CLI
// when registering a pairing session (protocol §3.5):
//
//	"KEYREF1" NUL "pair-register" NUL nonce(16 raw bytes) NUL
//	proposed_name(utf-8)
func BuildPairRegisterTranscript(nonce []byte, proposedName string) ([]byte, error) {
	if len(nonce) != SizePairNonce {
		return nil, fmt.Errorf("%w: nonce must be %d raw bytes", ErrInvalidField, SizePairNonce)
	}
	if !utf8.ValidString(proposedName) || len(proposedName) > LabelNameMaxBytes {
		return nil, fmt.Errorf("%w: proposed_name must be valid utf-8 of at most %d bytes", ErrInvalidField, LabelNameMaxBytes)
	}
	b := beginTranscript("pair-register")
	b = append(b, nonce...)
	b = appendSep(b)
	b = append(b, proposedName...)
	return b, nil
}

// BuildSessionTranscript assembles the session challenge transcript
// (protocol §3.6):
//
//	"KEYREF1" NUL "session" NUL device_id(hex) NUL challenge(32 raw bytes)
func BuildSessionTranscript(deviceID string, challenge []byte) ([]byte, error) {
	if err := requireID("device_id", deviceID); err != nil {
		return nil, err
	}
	if len(challenge) != SizeChallenge {
		return nil, fmt.Errorf("%w: challenge must be %d raw bytes", ErrInvalidField, SizeChallenge)
	}
	b := beginTranscript("session")
	b = append(b, deviceID...)
	b = appendSep(b)
	b = append(b, challenge...)
	return b, nil
}

// BuildVaultDeleteTranscript assembles the vault deletion challenge
// transcript (protocol §3.6):
//
//	"KEYREF1" NUL "vault-delete" NUL vault_id(hex) NUL challenge(32 raw bytes)
func BuildVaultDeleteTranscript(vaultID string, challenge []byte) ([]byte, error) {
	if err := requireID("vault_id", vaultID); err != nil {
		return nil, err
	}
	if len(challenge) != SizeChallenge {
		return nil, fmt.Errorf("%w: challenge must be %d raw bytes", ErrInvalidField, SizeChallenge)
	}
	b := beginTranscript("vault-delete")
	b = append(b, vaultID...)
	b = appendSep(b)
	b = append(b, challenge...)
	return b, nil
}

// BuildVaultRecoveryTranscript assembles the transcript signed by the
// owner when replacing recovery material (protocol §3.6):
//
//	"KEYREF1" NUL "vault-recovery" NUL vault_id(hex) NUL recovery_wrap NUL
//	recovery_kdf_json(utf-8) NUL recovery_sign_pub
func BuildVaultRecoveryTranscript(vaultID string, recoveryWrap []byte, recoveryKDFJSON string, recoverySignPub []byte) ([]byte, error) {
	if err := requireID("vault_id", vaultID); err != nil {
		return nil, err
	}
	if !utf8.ValidString(recoveryKDFJSON) {
		return nil, fmt.Errorf("%w: recovery_kdf_json must be valid utf-8", ErrInvalidField)
	}
	if len(recoverySignPub) != SizeEd25519Key {
		return nil, fmt.Errorf("%w: recovery_sign_pub must be %d bytes", ErrInvalidField, SizeEd25519Key)
	}
	b := beginTranscript("vault-recovery")
	b = append(b, vaultID...)
	b = appendSep(b)
	b = append(b, recoveryWrap...)
	b = appendSep(b)
	b = append(b, recoveryKDFJSON...)
	b = appendSep(b)
	b = append(b, recoverySignPub...)
	return b, nil
}
