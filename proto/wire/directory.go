package wire

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

// ParseDirectoryTranscript parses directory transcript bytes (protocol
// §3.3) back into structured form. It exists for exactly two protocol
// roles: the server extracting owner sign keys and device statuses from
// a signed directory (POST /v1/recovery/directory §6.3, PUT /v1/directory
// §6.15), and a client locating its own device record to detect
// revocation (design §8.2). A parse result is never trusted on its own:
// callers must verify the owner signature over the raw transcript bytes
// they parsed.
//
// D3 (protocol §1.5) forbids parsing transcripts by splitting on NUL
// separators, because binary fields may contain 0x00. This parser is a
// grammar-driven sequential reader instead: text fields (hex ids, enum
// words) are read up to the next NUL — which cannot occur inside them —
// and every binary field is read by its exact length derived from the
// grammar (hpke_public_key from hpke_kem, sign_public_key from sign_alg,
// grants_digest is 32 bytes).
//
// The one variable-length binary field, renewal_sign_public_key (empty
// or 32 bytes, protocol §3.3), is resolved by backtracking both
// interpretations and rejecting the parse when both succeed: such a
// transcript is ambiguous and the caller must treat it as invalid
// rather than guess which key the signer meant.
func ParseDirectoryTranscript(b []byte) (*DirectoryTranscript, error) {
	r := &dirReader{b: b}
	if !r.consume(TranscriptPrefix) {
		return nil, fmt.Errorf("%w: missing transcript prefix", ErrInvalidField)
	}
	if !r.consumeSep() {
		return nil, fmt.Errorf("%w: expected separator after prefix", ErrInvalidField)
	}
	if !r.consume("directory") {
		return nil, fmt.Errorf("%w: not a directory transcript", ErrInvalidField)
	}
	if !r.consumeSep() {
		return nil, fmt.Errorf("%w: expected separator after record kind", ErrInvalidField)
	}
	vaultID, err := r.textField()
	if err != nil {
		return nil, err
	}
	if err := requireID("vault_id", string(vaultID)); err != nil {
		return nil, err
	}
	rev, err := r.u64Field()
	if err != nil {
		return nil, err
	}
	out := &DirectoryTranscript{VaultID: string(vaultID), DirectoryRevision: rev}
	if r.atEnd() {
		return out, nil
	}
	for {
		dev, err := r.deviceRecord()
		if err != nil {
			return nil, err
		}
		if err := validateDirectoryDevice(*dev); err != nil {
			return nil, err
		}
		out.Devices = append(out.Devices, *dev)
		if r.atEnd() {
			return out, nil
		}
		if !r.consumeSep() {
			return nil, fmt.Errorf("%w: expected single NUL between directory records", ErrInvalidField)
		}
	}
}

// ActiveOwnerSignPublicKeys returns the sign_public_key of every active
// ios device record. Directories must carry at least one for the
// signature chain to continue.
func (t *DirectoryTranscript) ActiveOwnerSignPublicKeys() [][]byte {
	var keys [][]byte
	for _, d := range t.Devices {
		if d.Kind == DeviceKindIOS && d.Status == DeviceStatusActive {
			keys = append(keys, d.SignPublicKey)
		}
	}
	return keys
}

// Device looks up a record by device id.
func (t *DirectoryTranscript) Device(deviceID string) (DirectoryDevice, bool) {
	for _, d := range t.Devices {
		if d.DeviceID == deviceID {
			return d, true
		}
	}
	return DirectoryDevice{}, false
}

// EmptyGrantsDigest is the grants digest of a device with no grants:
// SHA-256 over the empty concatenation (protocol §3.3).
func EmptyGrantsDigest() []byte {
	sum := sha256.Sum256(nil)
	return sum[:]
}

type dirReader struct {
	b   []byte
	pos int
}

func (r *dirReader) atEnd() bool { return r.pos >= len(r.b) }

func (r *dirReader) consume(lit string) bool {
	if r.pos+len(lit) > len(r.b) {
		return false
	}
	if !bytes.Equal(r.b[r.pos:r.pos+len(lit)], []byte(lit)) {
		return false
	}
	r.pos += len(lit)
	return true
}

func (r *dirReader) consumeSep() bool { return r.consume("\x00") }

// textField reads a hex/enum field up to the next NUL. Text fields never
// contain 0x00, so scanning for the separator is unambiguous for them.
func (r *dirReader) textField() ([]byte, error) {
	i := bytes.IndexByte(r.b[r.pos:], 0x00)
	if i < 0 {
		return nil, fmt.Errorf("%w: unterminated text field", ErrInvalidField)
	}
	out := r.b[r.pos : r.pos+i]
	r.pos += i + 1
	return out, nil
}

func (r *dirReader) u64Field() (uint64, error) {
	if r.pos+8 > len(r.b) {
		return 0, fmt.Errorf("%w: truncated u64 field", ErrInvalidField)
	}
	v := binary.BigEndian.Uint64(r.b[r.pos : r.pos+8])
	r.pos += 8
	if !r.consumeSep() {
		return 0, fmt.Errorf("%w: expected separator after u64 field", ErrInvalidField)
	}
	return v, nil
}

func (r *dirReader) fixedBytes(n int) ([]byte, bool) {
	if r.pos+n > len(r.b) {
		return nil, false
	}
	out := r.b[r.pos : r.pos+n]
	r.pos += n
	return out, true
}

// deviceRecord reads one device record. The record tail
// (renewal_sign_public_key NUL grants_digest NUL-or-EOF) is parsed with
// backtracking because the renewal key is either empty or 32 raw bytes
// with no length prefix.
func (r *dirReader) deviceRecord() (*DirectoryDevice, error) {
	mark := r.pos
	fail := func(err error) (*DirectoryDevice, error) {
		r.pos = mark
		return nil, err
	}

	deviceID, err := r.textField()
	if err != nil {
		return fail(err)
	}
	kind, err := r.textField()
	if err != nil {
		return fail(err)
	}
	status, err := r.textField()
	if err != nil {
		return fail(err)
	}
	kem, err := r.textField()
	if err != nil {
		return fail(err)
	}
	kemSize := kemKeySize(string(kem))
	if kemSize < 0 {
		return fail(fmt.Errorf("%w: invalid hpke_kem", ErrInvalidField))
	}
	hpkeKey, ok := r.fixedBytes(kemSize)
	if !ok {
		return fail(fmt.Errorf("%w: truncated hpke_public_key", ErrInvalidField))
	}
	if !r.consumeSep() {
		return fail(fmt.Errorf("%w: expected separator after hpke_public_key", ErrInvalidField))
	}
	signAlg, err := r.textField()
	if err != nil {
		return fail(err)
	}
	sigSize := signKeySize(string(signAlg))
	if sigSize < 0 {
		return fail(fmt.Errorf("%w: invalid sign_alg", ErrInvalidField))
	}
	signKey, ok := r.fixedBytes(sigSize)
	if !ok {
		return fail(fmt.Errorf("%w: truncated sign_public_key", ErrInvalidField))
	}
	if !r.consumeSep() {
		return fail(fmt.Errorf("%w: expected separator after sign_public_key", ErrInvalidField))
	}

	tail := r.b[r.pos:]
	renewal, digest, role, tailLen, tailOK := parseRecordTail(tail)
	if !tailOK {
		return fail(fmt.Errorf("%w: invalid record tail (renewal key / grants digest / receiver role)", ErrInvalidField))
	}
	r.pos += tailLen

	return &DirectoryDevice{
		DeviceID:             string(deviceID),
		Kind:                 string(kind),
		Status:               string(status),
		HPKEKEM:              string(kem),
		HPKEPublicKey:        append([]byte{}, hpkeKey...),
		SignAlg:              string(signAlg),
		SignPublicKey:        append([]byte{}, signKey...),
		RenewalSignPublicKey: append([]byte{}, renewal...),
		GrantsDigest:         append([]byte{}, digest...),
		ReceiverRole:         role,
	}, nil
}

// parseRecordTail parses `renewal? NUL digest(32) role(1)` from the
// remaining transcript bytes, trying both the empty-renewal and the
// 32-byte-renewal interpretations. After the digest comes exactly one
// receiver_role byte (design v0.8 §14.4: 0 none, 1 primary, 2 inbox),
// and the record must then end cleanly or be followed by the single NUL
// separator. The interpretation is accepted only when it is the unique
// one that parses to a clean end: anything ambiguous is rejected.
func parseRecordTail(tail []byte) (renewal, digest []byte, role uint8, consumed int, ok bool) {
	emptyLen := 1 + SizeDigest + 1
	presentLen := SizeEd25519Key + 1 + SizeDigest + 1
	emptyOK := len(tail) >= emptyLen &&
		tail[0] == 0x00 &&
		tailEndsRecord(tail[emptyLen:])
	presentOK := len(tail) >= presentLen &&
		tail[SizeEd25519Key] == 0x00 &&
		tailEndsRecord(tail[presentLen:])
	switch {
	case emptyOK && presentOK:
		return nil, nil, 0, 0, false // ambiguous: reject rather than guess
	case emptyOK:
		return nil, tail[1 : 1+SizeDigest], tail[1+SizeDigest], emptyLen, true
	case presentOK:
		return tail[:SizeEd25519Key], tail[SizeEd25519Key+1 : SizeEd25519Key+1+SizeDigest], tail[presentLen-1], presentLen, true
	default:
		return nil, nil, 0, 0, false
	}
}

// tailEndsRecord reports whether the bytes after a digest cleanly end the
// transcript or introduce the next record with a single NUL separator.
func tailEndsRecord(rest []byte) bool {
	return len(rest) == 0 || rest[0] == 0x00
}
