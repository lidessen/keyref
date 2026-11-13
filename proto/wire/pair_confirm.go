package wire

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// PairConfirmMACLabel prefixes the HMAC message of the pairing
// confirmation MAC (protocol §3.13, v2 D). The MAC is the one proof the
// paired device holds that the completion it polled was produced by the
// device that scanned its QR code: the secret c never leaves the QR
// payload, so a server that merely saw pair/register cannot produce it.
const PairConfirmMACLabel = "keyref v1 pair-confirm"

// BuildPairConfirmMAC computes the pairing confirmation MAC (protocol
// §3.13, v2 D), issued by the owner at pair completion and re-computed by
// the paired device from its own secret before it pins the owner key:
//
//	HMAC-SHA256(key = c,
//	    msg = "keyref v1 pair-confirm" NUL kind NUL pair_transcript)
//
// kind is the device kind being admitted (cli | source | decider) and
// pairTranscript is the §3.4 pair transcript bytes. Issuer and verifier
// share this one function so the byte layout cannot drift.
func BuildPairConfirmMAC(c []byte, kind string, pairTranscript []byte) ([]byte, error) {
	if len(c) != SizePairConfirmKey {
		return nil, fmt.Errorf("%w: pairing secret must be %d bytes", ErrInvalidField, SizePairConfirmKey)
	}
	switch kind {
	case DeviceKindCLI, DeviceKindSource, DeviceKindDecider:
	default:
		return nil, fmt.Errorf("%w: unknown device kind %q", ErrInvalidField, kind)
	}
	m := hmac.New(sha256.New, c)
	m.Write([]byte(PairConfirmMACLabel))
	m.Write([]byte{fieldSep})
	m.Write([]byte(kind))
	m.Write([]byte{fieldSep})
	m.Write(pairTranscript)
	return m.Sum(nil), nil
}

// VerifyPairConfirmMAC recomputes the pairing confirmation MAC from the
// verifier's own secret and compares in constant time. Any input problem
// (wrong secret size, unknown kind) is a mismatch, never a panic: the
// paired device treats the whole completion as untrusted until this
// passes, and aborts the pairing before it pins the owner key or writes
// any local state (protocol §3.13, v2 D).
func VerifyPairConfirmMAC(mac, c []byte, kind string, pairTranscript []byte) bool {
	want, err := BuildPairConfirmMAC(c, kind, pairTranscript)
	if err != nil {
		return false
	}
	return hmac.Equal(want, mac)
}