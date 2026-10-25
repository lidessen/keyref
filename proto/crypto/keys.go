package crypto

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/lidessen/keyref/proto/wire"
)

// SizeKey32 is the byte length of symmetric keys (meta key, item key,
// VMK) and of Ed25519 / X25519 public keys (docs/protocol.md §1.4).
const SizeKey32 = 32

// DeviceKeys is a CLI device identity: an X25519 HPKE key pair for
// receiving grants and one-time wraps, and an Ed25519 signing key pair
// for pair-register, session and approval-request signatures
// (design.md §3, §8).
type DeviceKeys struct {
	HPKEKEM     string // always wire.KEMX25519 for CLI devices
	HPKEPublic  []byte // raw 32 bytes
	HPKEPrivate []byte // circl-scheme-marshaled
	SignAlg     string // always wire.SignAlgEd25519 for CLI devices
	SignPublic  []byte // raw 32 bytes
	SignPrivate ed25519.PrivateKey
}

// GenerateDeviceKeys generates a fresh CLI device identity.
func GenerateDeviceKeys() (*DeviceKeys, error) {
	hpub, hpriv, err := GenerateHPKEKeyPair(wire.KEMX25519)
	if err != nil {
		return nil, err
	}
	spub, spriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: ed25519 keygen failed: %w", err)
	}
	return &DeviceKeys{
		HPKEKEM:     wire.KEMX25519,
		HPKEPublic:  hpub,
		HPKEPrivate: hpriv,
		SignAlg:     wire.SignAlgEd25519,
		SignPublic:  spub,
		SignPrivate: spriv,
	}, nil
}

// GenerateOwnerKeys generates a software P-256 owner identity for tests
// and the e2e software owner (docs/protocol.md §11.2). Production owners
// keep the signing key inside the Secure Enclave (design §9.2).
func GenerateOwnerKeys() (signPrivate *ecdsa.PrivateKey, signPublicSEC1 []byte, hpkePrivate []byte, hpkePublic []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("crypto: p256 keygen failed: %w", err)
	}
	pub, err := wire.EncodeP256PublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	hpub, hpriv, err := GenerateHPKEKeyPair(wire.KEMP256)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return priv, pub, hpriv, hpub, nil
}

// errors for key decoding.
var (
	ErrKeyEncoding = errors.New("crypto: invalid key encoding")
)
