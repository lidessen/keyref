package crypto

// Message envelope (docs/protocol.md §3.9, D15; design v0.8 §14.3).
//
// Layout:
//
//	u8 wrap_count
//	‖ per record (ordered by device_id hex ascending, no separators):
//	    u16be(32) ‖ device_id(hex ascii) ‖ u16be(enc_len) ‖ enc ‖ wrapped
//	‖ body blob: nonce(12) ‖ ct ‖ tag(16)
//
// One random 256-bit message key encrypts the plaintext JSON
// (AES-256-GCM; AAD binds vault + source device), and the key is
// HPKE-wrapped once per recipient under purpose `source-message`.
//
// This is the reference reader for the decider (the only Go component that
// must open a message: it evaluates the SMS against the delegation policy
// and delivers the plaintext to the CLI). Owners open the same envelope on
// iOS; the Android collector seals it.
import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// MessageWrappedKeySize is the HPKE ciphertext of one 32-byte message
	// key (32-byte ct + 16-byte tag). It is an ordinary HPKE wrap like
	// every other in §3.7 — no nonce prefix.
	MessageWrappedKeySize = 32 + 16
	messageIDFieldSize    = 32
	messageEncHeaderSize  = 2
)

// MessageRecord is one parsed recipient record of a message envelope.
type MessageRecord struct {
	DeviceID string
	Enc      []byte
	Wrapped  []byte
}

// SplitMessageEnvelope separates the envelope into its recipient records
// and the trailing body blob. Structural only — nothing is decrypted.
func SplitMessageEnvelope(envelope []byte) (records []MessageRecord, body []byte, err error) {
	if len(envelope) < 1 {
		return nil, nil, errors.New("crypto: message envelope truncated")
	}
	n := int(envelope[0])
	if n < 1 {
		return nil, nil, errors.New("crypto: message envelope has no recipients")
	}
	p := 1
	for i := 0; i < n; i++ {
		if p+messageEncHeaderSize > len(envelope) {
			return nil, nil, errors.New("crypto: message envelope truncated")
		}
		idLen := int(envelope[p])<<8 | int(envelope[p+1])
		p += messageEncHeaderSize
		if idLen != messageIDFieldSize || p+idLen+messageEncHeaderSize > len(envelope) {
			return nil, nil, errors.New("crypto: message envelope record truncated")
		}
		deviceID := string(envelope[p : p+idLen])
		p += idLen
		if !validHexID(deviceID) {
			return nil, nil, errors.New("crypto: message envelope has a malformed device_id")
		}
		encLen := int(envelope[p])<<8 | int(envelope[p+1])
		p += messageEncHeaderSize
		if encLen == 0 || p+encLen+MessageWrappedKeySize > len(envelope) {
			return nil, nil, errors.New("crypto: message envelope record truncated")
		}
		enc := append([]byte{}, envelope[p:p+encLen]...)
		p += encLen
		wrapped := append([]byte{}, envelope[p:p+MessageWrappedKeySize]...)
		p += MessageWrappedKeySize
		records = append(records, MessageRecord{DeviceID: deviceID, Enc: enc, Wrapped: wrapped})
	}
	body = envelope[p:]
	if len(body) == 0 {
		return nil, nil, errors.New("crypto: message envelope has no body")
	}
	return records, body, nil
}

// MessageBodyAAD builds "keyref v1" US "message" US vault_id US
// source_device_id — the audit AAD shape with the reporting (source)
// device, since the source seals before the server mints a message_id.
func MessageBodyAAD(vaultID, sourceDeviceID string) ([]byte, error) {
	if !validHexID(vaultID) || !validHexID(sourceDeviceID) {
		return nil, errors.New("crypto: aad ids must be 32 lowercase hex characters")
	}
	b := make([]byte, 0, 64)
	b = append(b, domainPrefix...)
	b = append(b, unitSep())
	b = append(b, "message"...)
	b = append(b, unitSep())
	b = append(b, vaultID...)
	b = append(b, unitSep())
	b = append(b, sourceDeviceID...)
	return b, nil
}

// OpenMessageKey opens the record addressed to recipientDeviceID and
// returns the 32-byte message key. `unwrap` receives the §3.7 HPKE info
// and the record's enc/ct; callers pass their own private-key primitive.
func OpenMessageKey(envelope []byte, vaultID, recipientDeviceID string,
	unwrap func(info, enc, ct []byte) ([]byte, error)) (key []byte, err error) {
	records, _, err := SplitMessageEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	var mine *MessageRecord
	for i := range records {
		if records[i].DeviceID == recipientDeviceID {
			mine = &records[i]
			break
		}
	}
	if mine == nil {
		// Not a recipient (a device that paired after the message landed):
		// the 24-hour TTL heals the gap (design §14.3).
		return nil, fmt.Errorf("crypto: message is not sealed to device %s", recipientDeviceID)
	}
	info, err := Info(PurposeSourceMessage, vaultID, recipientDeviceID)
	if err != nil {
		return nil, err
	}
	key, err = unwrap(info, mine.Enc, mine.Wrapped)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		WipeKey(key)
		return nil, errors.New("crypto: message key is not 32 bytes")
	}
	return key, nil
}

// OpenMessage decrypts one message for recipientDeviceID and returns the
// §3.9 plaintext JSON.
func OpenMessage(envelope []byte, vaultID, sourceDeviceID, recipientDeviceID string,
	unwrap func(info, enc, ct []byte) ([]byte, error)) ([]byte, error) {
	_, body, err := SplitMessageEnvelope(envelope)
	if err != nil {
		return nil, err
	}
	key, err := OpenMessageKey(envelope, vaultID, recipientDeviceID, unwrap)
	if err != nil {
		return nil, err
	}
	defer WipeKey(key)
	aad, err := MessageBodyAAD(vaultID, sourceDeviceID)
	if err != nil {
		return nil, err
	}
	return OpenBlob(key, aad, body)
}

// SealMessageKey HPKE-wraps one message key to a recipient (owner P-256 or
// decider X25519) and returns the KEM encapsulation and the wrapped key —
// the two halves a §6.30 backfill submits.
func SealMessageKey(vaultID, recipientDeviceID string, recipientPublicKey, messageKey []byte) (enc, wrapped []byte, err error) {
	if len(messageKey) != 32 {
		return nil, nil, errors.New("crypto: message key must be 32 bytes")
	}
	kem, err := kemForPublicKey(recipientPublicKey)
	if err != nil {
		return nil, nil, err
	}
	info, err := Info(PurposeSourceMessage, vaultID, recipientDeviceID)
	if err != nil {
		return nil, nil, err
	}
	enc, wrapped, err = WrapKey(kem, recipientPublicKey, info, messageKey)
	if err != nil {
		return nil, nil, err
	}
	if len(wrapped) != MessageWrappedKeySize {
		return nil, nil, fmt.Errorf("crypto: wrapped message key is %d bytes, want %d", len(wrapped), MessageWrappedKeySize)
	}
	return enc, wrapped, nil
}

// SealMessageRecord is SealMessageKey plus the §3.9 record framing.
func SealMessageRecord(vaultID, recipientDeviceID string, recipientPublicKey, messageKey []byte) ([]byte, error) {
	enc, wrapped, err := SealMessageKey(vaultID, recipientDeviceID, recipientPublicKey, messageKey)
	if err != nil {
		return nil, err
	}
	return EncodeMessageRecord(recipientDeviceID, enc, wrapped)
}

// EncodeMessageRecord assembles one §3.9 record (no separators).
func EncodeMessageRecord(deviceID string, enc, wrapped []byte) ([]byte, error) {
	if !validHexID(deviceID) {
		return nil, errors.New("crypto: record device_id must be 32 lowercase hex characters")
	}
	if len(enc) == 0 || len(enc) > 0xFFFF || len(wrapped) != MessageWrappedKeySize {
		return nil, errors.New("crypto: malformed message wrap")
	}
	out := make([]byte, 0, 2+messageIDFieldSize+2+len(enc)+len(wrapped))
	out = append(out, 0, messageIDFieldSize)
	out = append(out, deviceID...)
	var l [2]byte
	binary.BigEndian.PutUint16(l[:], uint16(len(enc)))
	out = append(out, l[:]...)
	out = append(out, enc...)
	return append(out, wrapped...), nil
}

// kemForPublicKey maps a public-key length to its KEM (§1.4).
func kemForPublicKey(publicKey []byte) (string, error) {
	switch len(publicKey) {
	case 32:
		return KEMX25519, nil
	case 65:
		return KEMP256, nil
	default:
		return "", errors.New("crypto: unknown HPKE public key length")
	}
}
