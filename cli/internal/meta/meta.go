// Package meta renders the agent-facing view of items: ref, name,
// description, type, masked value, sensitivity, injectable
// (design.md §12.2). It decrypts META ONLY — list and get never touch
// the secret ciphertext (design.md §15), and the masked string comes
// pre-computed from the meta plaintext.
package meta

import (
	"errors"
	"fmt"
	"sort"

	"github.com/lidessen/keyref/cli/internal/cache"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/itemcrypt"
)

// ErrUnknownRef maps to exit code 11 (design.md §7.6).
var ErrUnknownRef = errors.New("meta: unknown ref or no view grant")

// ErrNoViewGrant reports an item that exists but has no view grant for
// this device — same user-facing outcome as unknown ref.
var ErrNoViewGrant = errors.New("meta: no view grant for item")

// Entry is one row of list/get output. There is deliberately no value
// field (design.md §12.2, §15).
type Entry struct {
	Ref         string `json:"ref"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Type        string `json:"type"`
	Masked      string `json:"masked"`
	Sensitivity string `json:"sensitivity"`
	Injectable  bool   `json:"injectable"`
}

// Items returns the decrypted meta of every cached, non-tombstoned
// item that has a view grant. Unwrapping failures are reported as
// errors (fail closed, design.md §4.4).
func Items(st *cache.Store, id *device.Identity) ([]Entry, error) {
	grants, err := st.Grants()
	if err != nil {
		return nil, err
	}
	viewByItem := map[string]bool{}
	for _, g := range grants {
		if g.Kind == "view" && len(g.WrappedKey) > 0 {
			viewByItem[g.ItemID] = true
		}
	}
	// Cached item ids.
	ids, err := st.ItemIDs()
	if err != nil {
		return nil, err
	}
	var out []Entry
	for _, itemID := range ids {
		it, ok, err := st.GetItem(itemID)
		if err != nil {
			return nil, err
		}
		if !ok || it.Tombstone {
			continue
		}
		if !viewByItem[itemID] {
			continue
		}
		m, err := decryptMeta(st, id, itemID)
		if err != nil {
			return nil, err
		}
		out = append(out, Entry{
			Ref:         m.Ref,
			Name:        m.Name,
			Description: m.Description,
			Type:        m.Type,
			Masked:      m.Masked,
			Sensitivity: m.Policy.Sensitivity,
			Injectable:  m.Injectable,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out, nil
}

// Lookup returns the entry for one ref.
func Lookup(st *cache.Store, id *device.Identity, ref string) (*Entry, error) {
	entries, err := Items(st, id)
	if err != nil {
		return nil, err
	}
	for i := range entries {
		if entries[i].Ref == ref {
			return &entries[i], nil
		}
	}
	return nil, ErrUnknownRef
}

func decryptMeta(st *cache.Store, id *device.Identity, itemID string) (*itemcrypt.Meta, error) {
	grants, err := st.Grants()
	if err != nil {
		return nil, err
	}
	vaultID, err := vaultIDOf(st)
	if err != nil {
		return nil, err
	}
	ownerPub, err := OwnerSignPub(st)
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if g.ItemID != itemID || g.Kind != "view" || len(g.WrappedKey) == 0 {
			continue
		}
		key, err := itemcrypt.UnwrapGrantKey(vaultID, &g, id.HPKEPrivate, ownerPub)
		if err != nil {
			return nil, fmt.Errorf("meta: unwrap meta key: %w", err)
		}
		it, ok, err := st.GetItem(itemID)
		if err != nil {
			key.Destroy()
			return nil, err
		}
		if !ok {
			key.Destroy()
			return nil, ErrUnknownRef
		}
		m, err := itemcrypt.DecryptMeta(key, it.MetaCiphertext, vaultID, itemID)
		key.Destroy()
		if err != nil {
			return nil, err
		}
		return m, nil
	}
	return nil, ErrNoViewGrant
}

func vaultIDOf(st *cache.Store) (string, error) {
	v, ok, err := st.GetKV("vault_id")
	if err != nil || !ok || len(v) == 0 {
		return "", errors.New("meta: not paired")
	}
	return string(v), nil
}

func OwnerSignPub(st *cache.Store) ([]byte, error) {
	v, ok, err := st.GetKV("owner_sign_public_key")
	if err != nil {
		return nil, err
	}
	if !ok || len(v) == 0 {
		return nil, errors.New("meta: not paired")
	}
	return v, nil
}
