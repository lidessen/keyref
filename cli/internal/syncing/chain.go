package syncing

import (
	"fmt"
	"io"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/audit"
	"github.com/lidessen/keyref/cli/internal/pair"
	"github.com/lidessen/keyref/cli/internal/store"
)

// Warn receives one line per row skipped by the v2 F verification
// (protocol.md §8.3). It is nil by default; main points it at
// stderr so the skip is visible without failing the sync.
var Warn io.Writer

func warnSkipped(entity, id string, err error) {
	if Warn == nil {
		return
	}
	fmt.Fprintf(Warn, "keyref: sync skipped %s %s: %v\n", entity, id, err)
}

// ownerKey is one signing identity a client accepts for owner-authored
// rows (v2 F): an active iOS device from the saved directory.
type ownerKey struct {
	DeviceID string
	SignAlg  string
	Pub      []byte
}

// ownerChain is the v2 F trust set: the pinned owner key (the pairing
// trust anchor) plus the active iOS signing keys of the currently saved
// directory. Once a directory is saved, owner rows are accepted only
// under one of ITS active keys; with no saved directory at all the pinned
// key is the only owner identity the client knows. A saved directory with
// no active iOS device is a dead vault: everything fails closed rather
// than falling back to the pin (which may name a revoked owner).
type ownerChain struct {
	pinned       []byte
	savedPresent bool
	saved        []ownerKey
}

// loadOwnerChain builds the chain from local state. A saved directory
// that does not parse contributes no keys and still counts as present,
// so verification fails closed instead of falling back to the pin.
func loadOwnerChain(st *store.Store) (*ownerChain, error) {
	pinned, err := OwnerSignPub(st)
	if err != nil {
		return nil, err
	}
	c := &ownerChain{pinned: pinned}
	raw, ok, err := st.GetKV(pair.KVDirectorySigned)
	if err != nil {
		return nil, err
	}
	if ok && len(raw) > 0 {
		c.reloadSaved(raw)
	}
	return c, nil
}

// reloadSaved replaces the saved directory's active owner keys with the
// ones listed in signed. Callers pass bytes they have just verified.
func (c *ownerChain) reloadSaved(signed []byte) {
	c.savedPresent = true
	c.saved = nil
	recs, err := audit.ParseDirectory(signed)
	if err != nil {
		return
	}
	for _, d := range recs {
		if d.Kind == wire.DeviceKindIOS && d.Status == wire.DeviceStatusActive {
			c.saved = append(c.saved, ownerKey{
				DeviceID: d.DeviceID,
				SignAlg:  d.SignAlg,
				Pub:      d.SignPublicKey,
			})
		}
	}
}

// verifyItem accepts a delivered item row iff its signature verifies
// under the active owner device named by writer_device_id (v2 F). With
// no saved directory the pinned key is the only owner identity known.
func (c *ownerChain) verifyItem(it *wire.ItemData) error {
	if !c.savedPresent {
		return it.VerifyItemSignature(wire.SignAlgECDSAP256, c.pinned)
	}
	if len(c.saved) == 0 {
		return fmt.Errorf("%w: item %s: the saved directory lists no active owner device",
			ErrTampered, it.ItemID)
	}
	for _, k := range c.saved {
		if k.DeviceID == it.WriterDeviceID {
			return it.VerifyItemSignature(k.SignAlg, k.Pub)
		}
	}
	return fmt.Errorf("%w: item %s: writer %s is not an active owner device",
		ErrTampered, it.ItemID, it.WriterDeviceID)
}

// verifyGrant accepts a grant row iff its signature verifies under some
// active owner device (v2 F); grants carry no writer id.
func (c *ownerChain) verifyGrant(g *wire.GrantData, vaultID string) error {
	if !c.savedPresent {
		return g.VerifyOwnerSignature(vaultID, c.pinned)
	}
	if len(c.saved) == 0 {
		return fmt.Errorf("%w: grant %s: the saved directory lists no active owner device",
			ErrTampered, g.ItemID)
	}
	tb, err := wire.BuildGrantTranscript(g.Transcript(vaultID))
	if err != nil {
		return err
	}
	var lastErr error
	for _, k := range c.saved {
		if err := wire.VerifyDeviceSignature(tb, g.Signature, k.SignAlg, k.Pub); err == nil {
			return nil
		} else {
			lastErr = err
		}
	}
	return fmt.Errorf("%w: grant %s: %v", ErrTampered, g.ItemID, lastErr)
}

// verifyDirectory accepts a new directory iff its signature verifies
// under an active iOS device of the currently saved directory; before
// any saved directory the pinned key is the only anchor (v2 F).
func (c *ownerChain) verifyDirectory(signed, sig []byte) error {
	if !c.savedPresent {
		return wire.VerifyOwnerSignature(signed, sig, c.pinned)
	}
	for _, k := range c.saved {
		if wire.VerifyDeviceSignature(signed, sig, k.SignAlg, k.Pub) == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: directory", ErrTampered)
}

// VerifyStoredDirectory re-verifies the locally saved directory under the
// v2 F trust set (defense in depth at call sites that extract owner keys
// from it). The pinned key is tried first; a directory signed by another
// owner device is accepted under that device's key from the saved
// directory itself. The saved directory is the only directory kept
// locally, so this check cannot be fully non-circular — it is the exact
// limitation §F documents (a client that missed the directory version
// that introduced the current signer must pair again).
func VerifyStoredDirectory(st *store.Store, signed, sig []byte) error {
	c, err := loadOwnerChain(st)
	if err != nil {
		return err
	}
	if wire.VerifyOwnerSignature(signed, sig, c.pinned) == nil {
		return nil
	}
	for _, k := range c.saved {
		if wire.VerifyDeviceSignature(signed, sig, k.SignAlg, k.Pub) == nil {
			return nil
		}
	}
	return fmt.Errorf("%w: directory", ErrTampered)
}
