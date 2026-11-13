// Package localvault resolves a local source's master key and opens the
// vault. The key comes from the OS keyring (written by `keyref init`),
// or from KEYREF_LOCAL_MASTER for headless use; keyref itself never
// writes the key to a file.
package localvault

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

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
	keyringUser    = "local-master-"
)

// ErrKey means no usable master key was found for the source.
var ErrKey = errors.New("local master key unavailable")

// Key returns the 32-byte master key. An explicitly set but malformed
// environment variable is an error, never a silent fall back to a
// different key. The caller wipes the returned slice.
func Key(ks keyring.SecretStore, sourceName string, lookup func(string) (string, bool)) ([]byte, error) {
	if encoded, present := lookup(EnvMaster); present {
		key, err := decode(encoded)
		if err != nil {
			return nil, fmt.Errorf("%w: %s must be the standard base64 encoding of 32 random bytes", ErrKey, EnvMaster)
		}
		return key, nil
	}
	encoded, err := ks.Get(keyringService, keyringUser+sourceName)
	if err != nil {
		return nil, fmt.Errorf("%w: run `keyref init`, or set %s", ErrKey, EnvMaster)
	}
	key, err := decode(encoded)
	if err != nil {
		return nil, fmt.Errorf("%w: the keyring entry for source %q is malformed", ErrKey, sourceName)
	}
	return key, nil
}

// Provision returns the key for `keyref init`. An environment-provided
// key is used as-is and never copied into the keyring; otherwise a fresh
// key is generated and stored there.
func Provision(ks keyring.SecretStore, sourceName string, lookup func(string) (string, bool)) ([]byte, error) {
	if _, present := lookup(EnvMaster); present {
		return Key(ks, sourceName, lookup)
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKey, err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := ks.Set(keyringService, keyringUser+sourceName, encoded); err != nil {
		return nil, fmt.Errorf("%w: could not store the key in the OS keyring (%v); set %s instead", ErrKey, err, EnvMaster)
	}
	return key, nil
}

// Open opens an existing local vault. It never creates one.
func Open(spec source.Spec, key []byte) (*local.Store, error) {
	return local.Open(spec.Path, key)
}

// Create exclusively creates a new local vault, never overwriting one.
func Create(spec source.Spec, key []byte) (*local.Store, error) {
	return local.Create(spec.Path, key)
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
