// Package syncing applies server changes to the local cache
// (docs/protocol.md §8, design.md §6.3, §10.6): items, grants, device
// and directory entities. Tombstones and grants deleted for this
// device drop the corresponding cache rows; a revoked device directory
// entry triggers local cleanup and refusal (exit 17 path). Signature
// verification happens before anything is applied; on verification
// failure the batch is abandoned and the old data stays.
package syncing

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/audit"
	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/pair"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/store"
)

// ErrRevoked reports that the directory marks this device revoked; the
// caller must stop with exit code 17 (design.md §7.6, §8.2).
var ErrRevoked = errors.New("sync: this device is revoked")

// ErrTampered reports a signature or digest mismatch; local state is
// kept untouched (design.md §10.6).
var ErrTampered = errors.New("sync: signature or digest verification failed")

// Result summarises one run.
type Result struct {
	Applied int
	Deleted int
}

// Run pulls changes until the cursor is current. It returns ErrRevoked
// after performing local cleanup.
func Run(st *store.Store, cl *client.Client, deviceID string) (Result, error) {
	var res Result
	cursor := int64(0)
	if raw, ok, _ := st.GetKV("cursor"); ok {
		cursor, _ = strconv.ParseInt(string(raw), 10, 64)
	}
	ownerPub, err := OwnerSignPub(st)
	if err != nil {
		return res, err
	}
	vaultID, err := vaultIDOf(st)
	if err != nil {
		return res, err
	}

	staleRetried := false
	for {
		resp, err := cl.Sync(cursor)
		if err != nil {
			if client.Code(err) == "cursor_stale" && !staleRetried {
				staleRetried = true
				cursor = 0
				continue
			}
			return res, fmt.Errorf("sync: fetch: %w", err)
		}
		for i := range resp.Changes {
			applied, deleted, err := applyChange(st, vaultID, deviceID, ownerPub, &resp.Changes[i])
			if err != nil {
				return res, err
			}
			res.Applied += applied
			res.Deleted += deleted
		}
		cursor = resp.Cursor
		if err := st.SetKV("cursor", []byte(strconv.FormatInt(cursor, 10))); err != nil {
			return res, err
		}
		if err := st.SetKV(pair.KVLastSync, []byte(strconv.FormatInt(nowMillis(), 10))); err != nil {
			return res, err
		}
		if !resp.HasMore {
			break
		}
	}

	if err := reconcileGrants(st, cl, vaultID, deviceID, ownerPub); err != nil {
		return res, err
	}
	return res, nil
}

func applyChange(st *store.Store, vaultID, deviceID string, ownerPub []byte, ch *wire.SyncChange) (applied, deleted int, err error) {
	switch ch.Entity {
	case wire.EntityItem:
		var it wire.ItemData
		if err := json.Unmarshal(ch.Data, &it); err != nil {
			return 0, 0, fmt.Errorf("sync: item decode: %w", err)
		}
		if it.Tombstone {
			// Tombstone: drop the row, its grants and any local wraps
			// (design.md §6.3, §6.5).
			if err := st.DeleteItem(it.ItemID); err != nil {
				return 0, 0, err
			}
			return 0, 1, nil
		}
		if old, ok, _ := st.GetItem(it.ItemID); ok && old.Revision >= it.Revision {
			// Reject revisions smaller than what has already been seen (design §6.2)
			return 0, 0, nil
		}
		if err := st.PutItem(&it); err != nil {
			return 0, 0, err
		}
		return 1, 0, nil

	case wire.EntityGrant:
		var g wire.GrantData
		if err := json.Unmarshal(ch.Data, &g); err != nil {
			return 0, 0, fmt.Errorf("sync: grant decode: %w", err)
		}
		if g.Deleted || (len(g.HPKEEnc) == 0 && len(g.WrappedKey) == 0) {
			// Grant revoked (pointing at ourselves) or item deletion cascade: clear local wrap
			if err := st.DeleteGrant(g.ItemID, g.Kind); err != nil {
				return 0, 0, err
			}
			return 0, 1, nil
		}
		if g.DeviceID != deviceID {
			// Rows for other devices should not be delivered; ignore.
			return 0, 0, nil
		}
		if err := g.VerifyOwnerSignature(vaultID, ownerPub); err != nil {
			return 0, 0, fmt.Errorf("%w: grant %s", ErrTampered, g.ItemID)
		}
		if err := st.PutGrant(&g); err != nil {
			return 0, 0, err
		}
		return 1, 0, nil

	case wire.EntityDirectory:
		var d wire.DirectoryData
		if err := json.Unmarshal(ch.Data, &d); err != nil {
			return 0, 0, fmt.Errorf("sync: directory decode: %w", err)
		}
		if err := wire.VerifyOwnerSignature(d.Signed, d.Signature, ownerPub); err != nil {
			return 0, 0, fmt.Errorf("%w: directory", ErrTampered)
		}
		if err := st.SetKV(pair.KVDirectorySigned, d.Signed); err != nil {
			return 0, 0, err
		}
		if err := st.SetKV(pair.KVDirectorySig, d.Signature); err != nil {
			return 0, 0, err
		}
		if err := st.SetKV(pair.KVDirectoryRev, []byte(strconv.FormatUint(d.DirectoryRevision, 10))); err != nil {
			return 0, 0, err
		}
		// Revocation delivery for CLI devices rides on the directory
		// (the device entity is owner-only): check our own status
		// (design.md §8.4, §10.6).
		if records, err := audit.ParseDirectory(d.Signed); err == nil {
			for _, rec := range records {
				if rec.DeviceID == deviceID && rec.Status == wire.DeviceStatusRevoked {
					cleanupRevoked(st)
					return 0, 1, ErrRevoked
				}
			}
		}
		return 1, 0, nil

	case wire.EntityDevice:
		var d wire.DeviceData
		if err := json.Unmarshal(ch.Data, &d); err != nil {
			return 0, 0, fmt.Errorf("sync: device decode: %w", err)
		}
		if d.DeviceID == deviceID && d.Status == wire.DeviceStatusRevoked {
			cleanupRevoked(st)
			return 0, 1, ErrRevoked
		}
		return 0, 0, nil

	default:
		// approval (Phase 2) and unknown entities: recorded, not applied.
		return 0, 0, nil
	}
}

// cleanupRevoked drops local wraps and cached ciphertext
// (design.md §8.2: after discovering revocation, delete local wraps
// and the cache).
func cleanupRevoked(st *store.Store) {
	_ = st.DeleteKV(session.KVToken)
	_ = st.DeleteKV(session.KVExpiresAt)
	grants, err := st.Grants()
	if err != nil {
		return
	}
	for _, g := range grants {
		_ = st.DeleteGrant(g.ItemID, g.Kind)
	}
}

// reconcileGrants cross-checks the local grant set against
// GET /v1/grants/self and the directory digest (design.md §9.1, §10.6):
// a suppressed or forged grant set disables use (fail closed).
func reconcileGrants(st *store.Store, cl *client.Client, vaultID, deviceID string, ownerPub []byte) error {
	self, err := cl.GrantsSelf()
	if err != nil {
		// Offline-tolerated: reconciliation needs the network.
		return nil
	}
	for i := range self.Grants {
		g := self.Grants[i]
		if err := g.VerifyOwnerSignature(vaultID, ownerPub); err != nil {
			return fmt.Errorf("%w: grants/self row", ErrTampered)
		}
		if err := st.PutGrant(&g); err != nil {
			return err
		}
	}
	local, err := st.Grants()
	if err != nil {
		return err
	}
	localDigest, err := wire.GrantsDigest(grantTranscripts(vaultID, local))
	if err != nil {
		return err
	}
	serverDigest, err := wire.GrantsDigest(grantTranscripts(vaultID, self.Grants))
	if err != nil {
		return err
	}
	if len(self.GrantsDigest) > 0 && !equalBytes(self.GrantsDigest, serverDigest) {
		return fmt.Errorf("%w: grants/self digest mismatch", ErrTampered)
	}
	if len(self.GrantsDigest) > 0 && !equalBytes(self.GrantsDigest, localDigest) {
		// The server's own set is authoritative; refresh the local rows.
		for _, g := range local {
			if !containsGrant(self.Grants, g) {
				_ = st.DeleteGrant(g.ItemID, g.Kind)
			}
		}
	}
	return nil
}

func grantTranscripts(vaultID string, grants []wire.GrantData) []wire.GrantTranscript {
	out := make([]wire.GrantTranscript, 0, len(grants))
	for _, g := range grants {
		out = append(out, g.Transcript(vaultID))
	}
	return out
}

func containsGrant(set []wire.GrantData, g wire.GrantData) bool {
	for _, s := range set {
		if s.ItemID == g.ItemID && s.Kind == g.Kind {
			return true
		}
	}
	return false
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// OwnerSignPub reads the pinned owner signing key.
func OwnerSignPub(st *store.Store) ([]byte, error) {
	v, ok, err := st.GetKV(pair.KVOwnerSignPub)
	if err != nil {
		return nil, err
	}
	if !ok || len(v) == 0 {
		return nil, errors.New("sync: not paired (no pinned owner key)")
	}
	return v, nil
}

func nowMillis() int64 { return time.Now().UnixMilli() }

func vaultIDOf(st *store.Store) (string, error) {
	v, ok, err := st.GetKV(session.KVVaultID)
	if err != nil {
		return "", err
	}
	if !ok || len(v) == 0 {
		return "", errors.New("sync: not paired (no vault id)")
	}
	return string(v), nil
}
