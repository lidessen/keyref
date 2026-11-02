// Package audit seals and uploads exec audit events
// (design.md §7.7, docs/protocol.md §6.23). The plaintext event JSON
// carries no secret values; it is encrypted with a fresh event key
// that is HPKE-wrapped to an active owner device. Upload is
// best-effort and never blocks or fails the exec.
package audit

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/client"
)

// OwnerRecipient is one owner device the audit event is wrapped to.
type OwnerRecipient struct {
	DeviceID      string
	HPKEKEM       string
	HPKEPublicKey []byte
}

// DeviceRecord is one device entry of a parsed directory transcript.
type DeviceRecord struct {
	DeviceID             string
	Kind                 string
	Status               string
	HPKEKEM              string
	HPKEPublicKey        []byte
	SignAlg              string
	SignPublicKey        []byte
	RenewalSignPublicKey []byte
	GrantsDigest         []byte
	// ReceiverRole is the SMS-inbox role carried as one byte directly
	// after grants_digest (design v0.8 §14.4, protocol §3.3): 0 none,
	// 1 primary receiver, 2 inbox.
	ReceiverRole uint8
}

// ParseDirectory returns the device records of a directory transcript,
// validated by rebuild-compare (see parseDirectory). The signature must
// have been verified by the caller on the same bytes.
func ParseDirectory(signed []byte) ([]DeviceRecord, error) {
	devices, err := parseDirectory(signed)
	if err != nil {
		return nil, err
	}
	out := make([]DeviceRecord, len(devices))
	for i, d := range devices {
		out[i] = DeviceRecord(d)
	}
	return out, nil
}

// Event is the audit plaintext (design.md §7.7): argv in placeholder
// form, never injected secrets. DecisionDeviceID names the device that
// signed the approval decision behind an `approval_result` (design v0.8
// §14.5/§14.8, protocol §6.22) — owner or decider; it is omitted when no
// approval decided the run. The message an SMS consumption targeted is
// already in Refs as `sms:<id>`, so no separate id field exists here.
type Event struct {
	Time             int64    `json:"time"`
	DeviceID         string   `json:"device_id"`
	Refs             []string `json:"refs"`
	Injection        []string `json:"injection"`
	Argv             []string `json:"argv"`
	AllowArgv        bool     `json:"allow_argv"`
	PolicyResult     string   `json:"policy_result"`
	ApprovalResult   string   `json:"approval_result,omitempty"`
	DecisionDeviceID string   `json:"decision_device_id,omitempty"`
	ChildExit        int      `json:"child_exit"`
	Redactions       int      `json:"redactions"`
}

// OwnersFromDirectory extracts the active owner (kind=ios) records
// from a signed directory transcript. Directory transcripts are
// write-only (protocol §1.5): this reader is a structured parser whose
// result is validated by rebuilding the transcript bytes and requiring
// byte equality — a misparse cannot survive. Callers must additionally
// have verified the directory signature before trusting these keys.
func OwnersFromDirectory(signed []byte) ([]OwnerRecipient, error) {
	devices, err := ParseDirectory(signed)
	if err != nil {
		return nil, err
	}
	var owners []OwnerRecipient
	for _, d := range devices {
		if d.Kind == wire.DeviceKindIOS && d.Status == wire.DeviceStatusActive {
			owners = append(owners, OwnerRecipient{
				DeviceID:      d.DeviceID,
				HPKEKEM:       d.HPKEKEM,
				HPKEPublicKey: d.HPKEPublicKey,
			})
		}
	}
	return owners, nil
}

type dirDevice = DeviceRecord

// parseDirectory walks the fixed layout with length-aware field reads
// (public-key lengths follow from the KEM/alg identifiers, so binary
// fields containing 0x00 are unambiguous) and validates itself by
// rebuilding.
func parseDirectory(signed []byte) ([]dirDevice, error) {
	fail := func(what string) error {
		return fmt.Errorf("audit: malformed directory transcript: %s", what)
	}
	const prefix = "KEYREF1\x00directory\x00"
	if !bytes.HasPrefix(signed, []byte(prefix)) {
		return nil, fail("bad prefix")
	}
	rest := signed[len(prefix):]
	// vault_id (32 hex) NUL u64be NUL
	if len(rest) < 32+1+8+1 {
		return nil, fail("truncated header")
	}
	vaultID := string(rest[:32])
	if !wire.ValidID(vaultID) || rest[32] != 0x00 {
		return nil, fail("bad vault id")
	}
	rest = rest[33:]
	rev := binary.BigEndian.Uint64(rest[:8])
	if rest[8] != 0x00 {
		return nil, fail("bad revision separator")
	}
	rest = rest[9:]

	var devices []dirDevice
	for len(rest) > 0 {
		var d dirDevice
		// device_id(32 hex) NUL kind NUL status NUL kem NUL
		strFields := []*string{&d.DeviceID, &d.Kind, &d.Status, &d.HPKEKEM}
		for _, p := range strFields {
			i := bytes.IndexByte(rest, 0x00)
			if i < 0 {
				return nil, fail("truncated record")
			}
			*p = string(rest[:i])
			rest = rest[i+1:]
		}
		if !wire.ValidID(d.DeviceID) {
			return nil, fail("bad device id")
		}
		kemLen := map[string]int{wire.KEMX25519: 32, wire.KEMP256: 65}[d.HPKEKEM]
		if kemLen == 0 || len(rest) < kemLen+1 {
			return nil, fail("bad hpke key")
		}
		d.HPKEPublicKey = rest[:kemLen]
		if rest[kemLen] != 0x00 {
			return nil, fail("bad hpke key separator")
		}
		rest = rest[kemLen+1:]

		i := bytes.IndexByte(rest, 0x00)
		if i < 0 {
			return nil, fail("truncated sign alg")
		}
		d.SignAlg = string(rest[:i])
		rest = rest[i+1:]
		signLen := map[string]int{wire.SignAlgEd25519: 32, wire.SignAlgECDSAP256: 65}[d.SignAlg]
		if signLen == 0 || len(rest) < signLen+1 {
			return nil, fail("bad sign key")
		}
		d.SignPublicKey = rest[:signLen]
		if rest[signLen] != 0x00 {
			return nil, fail("bad sign key separator")
		}
		rest = rest[signLen+1:]

		i = bytes.IndexByte(rest, 0x00)
		if i < 0 {
			return nil, fail("truncated renewal key")
		}
		d.RenewalSignPublicKey = rest[:i]
		if n := len(d.RenewalSignPublicKey); n != 0 && n != 32 {
			return nil, fail("bad renewal key length")
		}
		rest = rest[i+1:]

		if len(rest) < 32+1 {
			return nil, fail("truncated grants digest")
		}
		d.GrantsDigest = rest[:32]
		rest = rest[32:]
		// receiver_role sits directly after the digest, before the record
		// separator (protocol §3.3 / design §14.4).
		d.ReceiverRole = rest[0]
		rest = rest[1:]
		if len(rest) > 0 {
			if rest[0] != 0x00 {
				return nil, fail("bad record separator")
			}
			rest = rest[1:]
		}
		devices = append(devices, d)
	}

	// Self-validation: rebuilding must reproduce the signed bytes
	// exactly, otherwise the parse is rejected (write-only
	// transcripts, protocol §1.5).
	rebuilt, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID:           vaultID,
		DirectoryRevision: rev,
		Devices:           toWireDevices(devices),
	})
	if err != nil || !bytes.Equal(rebuilt, signed) {
		return nil, fail("rebuild mismatch")
	}
	return devices, nil
}

func toWireDevices(ds []dirDevice) []wire.DirectoryDevice {
	out := make([]wire.DirectoryDevice, 0, len(ds))
	for _, d := range ds {
		out = append(out, wire.DirectoryDevice{
			DeviceID:             d.DeviceID,
			Kind:                 d.Kind,
			Status:               d.Status,
			HPKEKEM:              d.HPKEKEM,
			HPKEPublicKey:        d.HPKEPublicKey,
			SignAlg:              d.SignAlg,
			SignPublicKey:        d.SignPublicKey,
			RenewalSignPublicKey: d.RenewalSignPublicKey,
			GrantsDigest:         d.GrantsDigest,
			ReceiverRole:         d.ReceiverRole,
		})
	}
	return out
}

// SealEnvelope encrypts the event JSON for the given owner recipients:
//
//	u8 wrap_count ‖ per owner { u16be enc_len ‖ enc ‖ 48B wrapped key }
//	‖ nonce‖ct‖tag (AES-256-GCM(event key), AAD = audit AAD)
//
// (docs/protocol.md §6.23). One random event key is wrapped separately
// for EVERY active owner device (wrap_count = len(recipients)), so each
// iPhone owner can decrypt the event independently (design.md §7.7).
func SealEnvelope(eventJSON []byte, vaultID, reporterDeviceID string, recipients []OwnerRecipient) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("audit: no owner recipient")
	}
	if len(recipients) > 255 {
		return nil, errors.New("audit: too many recipients")
	}
	eventKey := make([]byte, 32)
	if _, err := rand.Read(eventKey); err != nil {
		return nil, fmt.Errorf("audit: event key: %w", err)
	}
	defer crypto.WipeKey(eventKey)

	aad, err := crypto.AuditAAD(vaultID, reporterDeviceID)
	if err != nil {
		return nil, err
	}
	blob, err := crypto.SealBlob(eventKey, aad, eventJSON)
	if err != nil {
		return nil, err
	}

	out := make([]byte, 0, 1+len(recipients)*(2+32+48)+len(blob))
	out = append(out, byte(len(recipients)))
	for _, rec := range recipients {
		info, err := crypto.Info(crypto.PurposeAuditEventKey, vaultID, rec.DeviceID)
		if err != nil {
			return nil, err
		}
		enc, wrapped, err := crypto.WrapKey(rec.HPKEKEM, rec.HPKEPublicKey, info, eventKey)
		if err != nil {
			return nil, err
		}
		if len(wrapped) != 48 {
			return nil, fmt.Errorf("audit: unexpected wrapped key length")
		}
		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(len(enc)))
		out = append(out, lenBuf[0], lenBuf[1])
		out = append(out, enc...)
		out = append(out, wrapped...)
	}
	out = append(out, blob...)
	return out, nil
}

// UploadBestEffort posts the sealed envelope, swallowing every error
// (design.md §7.7 flow: audit must not block or fail the exec).
func UploadBestEffort(cl *client.Client, envelope []byte) {
	if cl == nil || len(envelope) == 0 {
		return
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = cl.PostAudit(envelope)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
}
