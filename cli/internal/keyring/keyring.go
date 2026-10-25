// Package keyring abstracts secret storage for the CLI device private
// keys (design.md §6.5, §8.1). Production uses the operating-system
// keyring via zalando/go-keyring; tests and e2e runs inject a directory
// store so no Keychain or Secret Service is required
// (docs/protocol.md §11.4).
package keyring

import (
	"errors"

	"github.com/zalando/go-keyring"
)

// ErrNotFound reports that no secret exists for the (service, user) pair.
var ErrNotFound = errors.New("keyring: secret not found")

// SecretStore is the pluggable secret-storage interface
// (docs/protocol.md §11.4). Secrets are opaque strings; callers encode
// binary key material (for example as base64) before storing it.
type SecretStore interface {
	Set(service, user, secret string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

// OSKeyring is the production SecretStore backed by the operating-system
// keyring: macOS Keychain via /usr/bin/security, Linux Secret Service via
// D-Bus. Neither path requires CGO (docs/protocol.md §4).
type OSKeyring struct{}

// NewOSKeyring returns the operating-system keyring store.
func NewOSKeyring() *OSKeyring { return &OSKeyring{} }

// Set stores secret for (service, user).
func (OSKeyring) Set(service, user, secret string) error { return keyring.Set(service, user, secret) }

// Get returns the secret stored for (service, user), ErrNotFound if none.
func (OSKeyring) Get(service, user string) (string, error) {
	v, err := keyring.Get(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", ErrNotFound
	}
	return v, err
}

// Delete removes the secret stored for (service, user), ErrNotFound if none.
func (OSKeyring) Delete(service, user string) error {
	err := keyring.Delete(service, user)
	if errors.Is(err, keyring.ErrNotFound) {
		return ErrNotFound
	}
	return err
}
