// Package device manages the CLI device identity: an X25519 HPKE key
// pair and an Ed25519 signing key pair, generated at `keyref pair` time
// and persisted in the operating-system keyring (design.md §6.5, §8.1).
// Private keys never touch the filesystem cache.
package device

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/lidessen/keyref/proto/crypto"

	"github.com/lidessen/keyref/cli/internal/keyring"
)

// Keyring service and user names for the two device private keys.
const (
	Service  = "keyref"
	UserHPKE = "device-hpke-x25519"
	UserSign = "device-sign-ed25519"
)

// Identity is the loaded CLI device identity. The HPKE private key stays
// in its marshaled form and is handed to proto/crypto per use; the
// Ed25519 private key is an in-memory seed copy from the keyring.
type Identity struct {
	HPKEPublic  []byte // raw 32 bytes (protocol §1.4)
	HPKEPrivate []byte // circl-scheme-marshaled
	SignPublic  []byte // raw 32 bytes
	SignPrivate ed25519.PrivateKey
}

// FingerprintFormat is the human-checkable grouping of the fingerprint
// (docs/protocol.md §9.1): first 8 bytes of SHA-256 of the raw signing
// public key as uppercase hex grouped in fours, A1B2-C3D4-E5F6-7890.
var fingerprintRe = regexp.MustCompile(`^[0-9A-F]{4}(-[0-9A-F]{4}){3}$`)

// LoadOrCreate returns the device identity from the keyring, generating
// and persisting a fresh one on first run (keyref pair).
func LoadOrCreate(st keyring.SecretStore) (*Identity, error) {
	hb64, hpkeErr := st.Get(Service, UserHPKE)
	sb64, signErr := st.Get(Service, UserSign)
	if hpkeErr == nil && signErr == nil {
		id, err := decodeIdentity(hb64, sb64)
		if err != nil {
			return nil, err
		}
		return id, nil
	}
	if !errors.Is(hpkeErr, keyring.ErrNotFound) || !errors.Is(signErr, keyring.ErrNotFound) {
		// A real keyring failure must not silently regenerate the keys.
		return nil, fmt.Errorf("device: load keys: hpke: %v; sign: %v", hpkeErr, signErr)
	}
	keys, err := crypto.GenerateDeviceKeys()
	if err != nil {
		return nil, err
	}
	if err := st.Set(Service, UserHPKE, base64.StdEncoding.EncodeToString(keys.HPKEPrivate)); err != nil {
		return nil, fmt.Errorf("device: store hpke key: %w", err)
	}
	if err := st.Set(Service, UserSign, base64.StdEncoding.EncodeToString(keys.SignPrivate)); err != nil {
		// Do not leave a half-written identity behind.
		_ = st.Delete(Service, UserHPKE)
		return nil, fmt.Errorf("device: store sign key: %w", err)
	}
	return &Identity{
		HPKEPublic:  keys.HPKEPublic,
		HPKEPrivate: keys.HPKEPrivate,
		SignPublic:  keys.SignPublic,
		SignPrivate: keys.SignPrivate,
	}, nil
}

// Delete removes the stored device keys (unpair / local wipe).
func Delete(st keyring.SecretStore) error {
	hErr := st.Delete(Service, UserHPKE)
	sErr := st.Delete(Service, UserSign)
	if hErr != nil && !errors.Is(hErr, keyring.ErrNotFound) {
		return hErr
	}
	if sErr != nil && !errors.Is(sErr, keyring.ErrNotFound) {
		return sErr
	}
	return nil
}

func decodeIdentity(hb64, sb64 string) (*Identity, error) {
	hpriv, err := base64.StdEncoding.DecodeString(hb64)
	if err != nil || len(hpriv) == 0 {
		return nil, fmt.Errorf("device: invalid stored hpke key")
	}
	spriv, err := base64.StdEncoding.DecodeString(sb64)
	if err != nil || len(spriv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("device: invalid stored sign key")
	}
	priv := ed25519.PrivateKey(spriv)
	// The public key is recoverable from the private seed; re-derive
	// both public keys so a corrupted store cannot substitute one half.
	signPub := priv.Public().(ed25519.PublicKey)
	pub, err := crypto.PublicKeyOf(crypto.KEMX25519, hpriv)
	if err != nil {
		return nil, fmt.Errorf("device: invalid stored hpke key")
	}
	return &Identity{
		HPKEPublic:  pub,
		HPKEPrivate: hpriv,
		SignPublic:  []byte(signPub),
		SignPrivate: priv,
	}, nil
}

// Fingerprint returns the pairing fingerprint of this device
// (docs/protocol.md §9.1): SHA-256 of the raw signing public key, first
// 8 bytes, uppercase hex grouped in fours with dashes.
func (id *Identity) Fingerprint() string {
	sum := sha256.Sum256(id.SignPublic)
	h := strings.ToUpper(hex.EncodeToString(sum[:8]))
	var b strings.Builder
	for i := 0; i < 4; i++ {
		if i > 0 {
			b.WriteByte('-')
		}
		b.WriteString(h[i*4 : (i+1)*4])
	}
	return b.String()
}
