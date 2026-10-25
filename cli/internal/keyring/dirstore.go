package keyring

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// DirStore is a filesystem SecretStore used by tests and e2e runs
// (docs/protocol.md §11.4). Secrets live in a 0700 directory as 0600
// files whose names are the SHA-256 of service and user, so secret
// material never influences a path and path traversal is impossible.
//
// It is not a production store: anything running as the same user can
// read it. That boundary is B1/B2 in the threat model (design §4.2).
type DirStore struct {
	root string
}

// NewDirStore creates (or reuses) the secret directory at root with mode
// 0700, matching the CLI data-directory permission of design §6.5.
func NewDirStore(root string) (*DirStore, error) {
	if root == "" {
		return nil, errors.New("keyring: dir store requires a root directory")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, fmt.Errorf("keyring: create dir store: %w", err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, fmt.Errorf("keyring: chmod dir store: %w", err)
	}
	return &DirStore{root: root}, nil
}

func (d *DirStore) path(service, user string) string {
	h := sha256.Sum256([]byte(service + "\x00" + user))
	return filepath.Join(d.root, hex.EncodeToString(h[:]))
}

// Set stores secret for (service, user) as a 0600 file.
func (d *DirStore) Set(service, user, secret string) error {
	p := d.path(service, user)
	if err := os.WriteFile(p, []byte(secret), 0o600); err != nil {
		return fmt.Errorf("keyring: dir store write: %w", err)
	}
	return os.Chmod(p, 0o600)
}

// Get returns the secret stored for (service, user), ErrNotFound if none.
func (d *DirStore) Get(service, user string) (string, error) {
	b, err := os.ReadFile(d.path(service, user))
	if errors.Is(err, os.ErrNotExist) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("keyring: dir store read: %w", err)
	}
	return string(b), nil
}

// Delete removes the secret stored for (service, user), ErrNotFound if
// none.
func (d *DirStore) Delete(service, user string) error {
	err := os.Remove(d.path(service, user))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("keyring: dir store delete: %w", err)
	}
	return nil
}

// Root returns the directory backing the store (test helper).
func (d *DirStore) Root() string { return d.root }

// ensure interface satisfaction.
var _ SecretStore = (*DirStore)(nil)
var _ SecretStore = (*OSKeyring)(nil)
