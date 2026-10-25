package crypto

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/cloudflare/circl/hpke"
)

// KEM identifiers as carried in JSON and the devices table
// (docs/protocol.md §1.4).
const (
	KEMX25519 = "X25519"
	KEMP256   = "P-256"
)

// ErrHPKE wraps HPKE unwrap failures without echoing any key material.
var ErrHPKE = errors.New("crypto: hpke wrap/unwrap failed")

func kemID(name string) (hpke.KEM, error) {
	switch name {
	case KEMX25519:
		return hpke.KEM_X25519_HKDF_SHA256, nil
	case KEMP256:
		return hpke.KEM_P256_HKDF_SHA256, nil
	}
	return 0, fmt.Errorf("crypto: unknown hpke_kem %q", name)
}

// suite returns the fixed RFC 9180 Base suite DHKEM + HKDF-SHA256 +
// AES-256-GCM (docs/protocol.md §1.4).
func suite(k hpke.KEM) hpke.Suite {
	return hpke.NewSuite(k, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES256GCM)
}

// GenerateHPKEKeyPair generates a KEM key pair for kemName and returns
// the raw encoded public key (32 bytes for X25519, 65 bytes SEC1 for
// P-256, §1.4) and the scheme-marshaled private key.
func GenerateHPKEKeyPair(kemName string) (publicKey, privateKey []byte, err error) {
	k, err := kemID(kemName)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := k.Scheme().GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: kem keygen failed: %w", err)
	}
	publicKey, err = pub.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: kem public key encode failed: %w", err)
	}
	privateKey, err = priv.MarshalBinary()
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: kem private key encode failed: %w", err)
	}
	return publicKey, privateKey, nil
}

// PublicKeyOf returns the raw encoded public key belonging to a
// scheme-marshaled private key, so callers can re-derive the device
// public key from keyring storage without trusting a second copy.
func PublicKeyOf(kemName string, privateKey []byte) ([]byte, error) {
	k, err := kemID(kemName)
	if err != nil {
		return nil, err
	}
	priv, err := k.Scheme().UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, ErrHPKE
	}
	pub, err := priv.Public().MarshalBinary()
	if err != nil {
		return nil, ErrHPKE
	}
	return pub, nil
}

// WrapKey seals a 32-byte key to recipientPublicKey with HPKE Base mode.
// It returns the KEM encapsulation enc (32 bytes for X25519, 65 for P-256)
// and the ciphertext ct ‖ tag. The HPKE AAD is always empty; all binding
// lives in info (docs/protocol.md §1.5, §3.7 — build info with Info or
// OneTimeItemKeyInfo).
func WrapKey(kemName string, recipientPublicKey, info, plaintext []byte) (enc, ct []byte, err error) {
	k, err := kemID(kemName)
	if err != nil {
		return nil, nil, err
	}
	pub, err := k.Scheme().UnmarshalBinaryPublicKey(recipientPublicKey)
	if err != nil {
		return nil, nil, ErrHPKE
	}
	sender, err := suite(k).NewSender(pub, info)
	if err != nil {
		return nil, nil, ErrHPKE
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, nil, ErrHPKE
	}
	ct, err = sealer.Seal(plaintext, nil)
	if err != nil {
		return nil, nil, ErrHPKE
	}
	return enc, ct, nil
}

// UnwrapKey opens a WrapKey envelope with the scheme-marshaled private
// key. It returns ErrHPKE on any mismatch of key, info or ciphertext —
// including the one-time binding of approval-driven wraps (§3.7, D4).
//
// The returned plaintext is a fresh slice on the ordinary Go heap: the
// CLI copies it into guarded memory and wipes the intermediate
// immediately (design §12.2); circl does not offer an open-into API.
func UnwrapKey(kemName string, privateKey, info, enc, ct []byte) ([]byte, error) {
	k, err := kemID(kemName)
	if err != nil {
		return nil, err
	}
	priv, err := k.Scheme().UnmarshalBinaryPrivateKey(privateKey)
	if err != nil {
		return nil, ErrHPKE
	}
	receiver, err := suite(k).NewReceiver(priv, info)
	if err != nil {
		return nil, ErrHPKE
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		return nil, ErrHPKE
	}
	pt, err := opener.Open(ct, nil)
	if err != nil {
		return nil, ErrHPKE
	}
	return pt, nil
}
