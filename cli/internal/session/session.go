// Package session implements the challenge→token login of
// docs/protocol.md §6.7 and caches the bearer token in the local store.
// Tokens live in cache.sqlite (0600) — they are session credentials,
// not key material (design.md §8.2: a stolen token without the keyring
// key cannot decrypt anything).
package session

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/store"
)

// KV keys inside cache.sqlite (shared with the pairing/sync layers).
const (
	KVToken     = "session_token"
	KVExpiresAt = "session_expires_at"
	KVDeviceID  = "device_id"
	KVVaultID   = "vault_id"
	KVLocked    = "locked"
)

// ErrLocked reports the persisted lock flag (`keyref lock`): the CLI
// refuses to use the keyring to unwrap anything until `keyref unlock`.
var ErrLocked = errors.New("session: locked")

// ErrNotPaired reports a missing device id (never paired or unpaired).
var ErrNotPaired = errors.New("session: device not paired")

// Manager issues and caches bearer tokens for one device identity.
type Manager struct {
	st *store.Store
	cl *client.Client
	id *device.Identity
}

// New returns a session manager. Wire the client's token source to
// TokenSource after construction.
func New(st *store.Store, cl *client.Client, id *device.Identity) *Manager {
	return &Manager{st: st, cl: cl, id: id}
}

// TokenSource adapts Token to the client's bearer-token hook.
func (m *Manager) TokenSource() func() (string, error) { return m.Token }

// DeviceID returns the paired device id from the local store.
func (m *Manager) DeviceID() (string, error) {
	v, ok, err := m.st.GetKV(KVDeviceID)
	if err != nil {
		return "", err
	}
	if !ok || len(v) == 0 {
		return "", ErrNotPaired
	}
	return string(v), nil
}

// VaultID returns the paired vault id from the local store.
func (m *Manager) VaultID() (string, error) {
	v, ok, err := m.st.GetKV(KVVaultID)
	if err != nil {
		return "", err
	}
	if !ok || len(v) == 0 {
		return "", ErrNotPaired
	}
	return string(v), nil
}

// Token returns a live bearer token, running the two-step challenge
// flow when the cached one is missing or about to expire.
func (m *Manager) Token() (string, error) {
	if tok, ok, _ := m.st.GetKV(KVToken); ok {
		var expires int64
		if raw, ok2, _ := m.st.GetKV(KVExpiresAt); ok2 {
			expires, _ = strconv.ParseInt(string(raw), 10, 64)
		}
		if string(tok) != "" && time.Now().Add(5*time.Minute).UnixMilli() < expires {
			return string(tok), nil
		}
	}
	deviceID, err := m.DeviceID()
	if err != nil {
		return "", err
	}
	challenge, _, err := m.cl.SessionChallenge(deviceID)
	if err != nil {
		return "", fmt.Errorf("session: challenge: %w", err)
	}
	if len(challenge) != wire.SizeChallenge {
		return "", fmt.Errorf("session: malformed challenge")
	}
	tb, err := wire.BuildSessionTranscript(deviceID, challenge)
	if err != nil {
		return "", err
	}
	sig, err := wire.SignEd25519(tb, m.id.SignPrivate)
	if err != nil {
		return "", err
	}
	tok, expiresAt, err := m.cl.SessionToken(deviceID, challenge, sig)
	if err != nil {
		return "", fmt.Errorf("session: token: %w", err)
	}
	if err := m.st.SetKV(KVToken, []byte(tok)); err != nil {
		return "", err
	}
	if err := m.st.SetKV(KVExpiresAt, []byte(strconv.FormatInt(expiresAt, 10))); err != nil {
		return "", err
	}
	return tok, nil
}
