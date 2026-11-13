// Package localvault resolves a local source's master key and opens the
// vault. The key comes from the OS keyring (written by `keyref init`),
// or from KEYREF_LOCAL_MASTER for headless use; keyref itself never
// writes the key to a file.
//
// The keyring entry is bound to the vault, not to the source name:
// its account is `local-master-<store id>`, where the store id is the
// random id inside the vault file (design §17.4, issue #2). Two data
// directories — or a source removed and re-added under the same name —
// can therefore never overwrite each other's key.
package localvault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"

	keycrypto "github.com/lidessen/keyref/proto/crypto"

	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/source"
	"github.com/lidessen/keyref/cli/local"
)

// EnvMaster carries the master key as the standard base64 encoding of
// 32 random bytes. It wins over the keyring, so a headless caller never
// needs one.
const EnvMaster = "KEYREF_LOCAL_MASTER"

const (
	keyringService = "keyref"
	keyringPrefix  = "local-master-"
)

// ErrKey means no usable master key was found for the vault.
var ErrKey = errors.New("local master key unavailable")

// ErrKeyExists means the keyring already holds a key for the vault's
// store id. init never replaces an existing entry.
var ErrKeyExists = errors.New("a master key already exists for this vault")

// Key returns the 32-byte master key for an existing vault at
// vaultPath. An explicitly set but malformed environment variable is an
// error, never a silent fall back to a different key. The caller wipes
// the returned slice.
func Key(ks keyring.SecretStore, vaultPath string, lookup func(string) (string, bool)) ([]byte, error) {
	if encoded, present := lookup(EnvMaster); present {
		key, err := decode(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: %s must be the standard base64 encoding of 32 random bytes", ErrKey, EnvMaster)
		}
		return key, nil
	}
	id, err := local.ReadStoreID(vaultPath)
	if err != nil {
		return nil, fmt.Errorf("%w: could not read the vault's store id", ErrKey)
	}
	encoded, err := ks.Get(keyringService, keyringPrefix+id)
	if err != nil {
		return nil, fmt.Errorf("%w: no keyring entry for this vault; set %s", ErrKey, EnvMaster)
	}
	key, err := decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: the keyring entry for this vault is malformed", ErrKey)
	}
	return key, nil
}

// Create provisions a new local vault at spec.Path. A fresh master key
// is generated — or taken from KEYREF_LOCAL_MASTER, which is never
// copied into the keyring — the vault file is created exclusively, and
// the key is then written to the OS keyring under the vault's store id.
// The keyring entry is never overwritten; if writing it fails, the
// fresh vault file is removed again. The master key is wiped before
// Create returns: the store derives its own keys.
func Create(ks keyring.SecretStore, spec source.Spec, lookup func(string) (string, bool)) (*local.Store, error) {
	key, fromEnv, err := provisionKey(lookup)
	if err != nil {
		return nil, err
	}
	defer keycrypto.WipeKey(key)
	vault, err := local.Create(spec.Path, key)
	if err != nil {
		return nil, err
	}
	if !fromEnv {
		if err := storeKey(ks, vault.StoreID(), key); err != nil {
			_ = vault.Close()
			_ = os.Remove(spec.Path)
			return nil, err
		}
	}
	return vault, nil
}

// provisionKey returns the master key for a new vault. The bool reports
// whether it came from the environment (and must not be stored).
func provisionKey(lookup func(string) (string, bool)) ([]byte, bool, error) {
	if encoded, present := lookup(EnvMaster); present {
		key, err := decode(encoded)
		if err != nil {
			return nil, true, fmt.Errorf("%w: %s must be the standard base64 encoding of 32 random bytes", ErrKey, EnvMaster)
		}
		return key, true, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, false, fmt.Errorf("%w: %v", ErrKey, err)
	}
	return key, false, nil
}

// storeKey writes a new vault's key under its store id. An existing
// entry is an error, never a replacement (issue #2).
func storeKey(ks keyring.SecretStore, storeID string, key []byte) error {
	user := keyringPrefix + storeID
	if _, err := ks.Get(keyringService, user); err == nil {
		return fmt.Errorf("%w; refusing to overwrite it", ErrKeyExists)
	}
	if err := ks.Set(keyringService, user, base64.StdEncoding.EncodeToString(key)); err != nil {
		return fmt.Errorf("%w: could not store the key in the OS keyring (%v); set %s instead", ErrKey, err, EnvMaster)
	}
	return nil
}

// Open opens an existing local vault. It never creates one.
func Open(spec source.Spec, key []byte) (*local.Store, error) {
	return local.Open(spec.Path, key)
}

func decode(encoded string) ([]byte, error) {
	if len(encoded) != base64.StdEncoding.EncodedLen(32) {
		return nil, ErrKey
	}
	key := make([]byte, base64.StdEncoding.DecodedLen(len(encoded)))
	n, err := base64.StdEncoding.Strict().Decode(key, []byte(encoded))
	if err != nil || n != 32 {
		return nil, ErrKey
	}
	return key[:n], nil
}
