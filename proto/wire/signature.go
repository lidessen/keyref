package wire

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
)

// EncodeP256PublicKey returns the SEC1 uncompressed encoding of a P-256
// public key: 0x04 || X || Y, 65 bytes (protocol §1.4).
func EncodeP256PublicKey(pub *ecdsa.PublicKey) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: key must be P-256", ErrInvalidField)
	}
	out := make([]byte, SizeP256Key)
	out[0] = 0x04
	pub.X.FillBytes(out[1:33])
	pub.Y.FillBytes(out[33:65])
	return out, nil
}

// SignOwnerECDSA signs transcript with an owner's P-256 key: SHA-256
// then ECDSA, ASN.1 DER encoding (protocol §1.4). Production owners sign
// inside the Secure Enclave; this function serves tests and the software
// owner used by the e2e suite (protocol §11.2).
func SignOwnerECDSA(transcript []byte, priv *ecdsa.PrivateKey) ([]byte, error) {
	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w: owner signing key must be P-256", ErrInvalidField)
	}
	digest := sha256.Sum256(transcript)
	return ecdsa.SignASN1(rand.Reader, priv, digest[:])
}

// SignEd25519 signs transcript with a CLI device key or with the
// recovery signing authority (both Ed25519, protocol §1.4 and §3.8).
func SignEd25519(transcript []byte, priv ed25519.PrivateKey) ([]byte, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: ed25519 private key must be %d bytes", ErrInvalidField, ed25519.PrivateKeySize)
	}
	return ed25519.Sign(priv, transcript), nil
}

// VerifyDeviceSignature checks signature over transcript under the given
// algorithm identifier and public key encoding (protocol §1.4): Ed25519
// with a raw 32-byte key, or ECDSA P-256 with SHA-256 and ASN.1 DER
// signatures over a 65-byte uncompressed SEC1 point.
//
// A nil error means the signature covers exactly these transcript bytes.
func VerifyDeviceSignature(transcript, signature []byte, signAlg string, publicKey []byte) error {
	switch signAlg {
	case SignAlgEd25519:
		if len(publicKey) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: ed25519 public key must be %d bytes", ErrInvalidField, ed25519.PublicKeySize)
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), transcript, signature) {
			return ErrBadSignature
		}
		return nil
	case SignAlgECDSAP256:
		if len(publicKey) != SizeP256Key || publicKey[0] != 0x04 {
			return fmt.Errorf("%w: P-256 public key must be a %d-byte uncompressed point", ErrInvalidField, SizeP256Key)
		}
		// Decode the SEC1 point and reject points off the curve before
		// handing the coordinates to the ECDSA verifier
		// (elliptic.Unmarshal is deprecated; decode the coordinates here).
		x := new(big.Int).SetBytes(publicKey[1:33])
		y := new(big.Int).SetBytes(publicKey[33:65])
		curve := elliptic.P256()
		if !curve.IsOnCurve(x, y) {
			return fmt.Errorf("%w: invalid P-256 public key point", ErrInvalidField)
		}
		pub := ecdsa.PublicKey{Curve: curve, X: x, Y: y}
		digest := sha256.Sum256(transcript)
		if !ecdsa.VerifyASN1(&pub, digest[:], signature) {
			return ErrBadSignature
		}
		return nil
	default:
		return fmt.Errorf("%w: unknown sign_alg", ErrInvalidField)
	}
}

// VerifyOwnerSignature verifies a signature by an owner device
// (ECDSA P-256, ASN.1 DER) such as item, grant, directory and pair
// transcripts.
func VerifyOwnerSignature(transcript, signature, ownerSignPublicKey []byte) error {
	return VerifyDeviceSignature(transcript, signature, SignAlgECDSAP256, ownerSignPublicKey)
}

// VerifyCLISignature verifies a signature by a CLI device (Ed25519),
// such as pair-register and session transcripts and approval request
// ciphertexts.
func VerifyCLISignature(transcript, signature, cliSignPublicKey []byte) error {
	return VerifyDeviceSignature(transcript, signature, SignAlgEd25519, cliSignPublicKey)
}

// VerifyRecoverySignature verifies a signature by the recovery signing
// authority derived from the recovery code (Ed25519, protocol §3.8). It
// is used only to re-anchor the device directory during takeover
// (design §8.5).
func VerifyRecoverySignature(transcript, signature, recoverySignPub []byte) error {
	return VerifyDeviceSignature(transcript, signature, SignAlgEd25519, recoverySignPub)
}
