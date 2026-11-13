// Package syncing applies server changes to the local cache
// (docs/protocol.md §8, design.md §6.3, §10.6): items, grants, device
// and directory entities. Tombstones and grants deleted for this
// device drop the corresponding cache rows; a revoked device directory
// entry triggers local cleanup and refusal (exit 17 path). Signature
// verification follows the v2 F owner key chain: item rows are verified
// under the key of the device named by writer_device_id, grant rows
// under any active owner key, and a new directory under the previously
// saved directory's active owner keys. A failed row is skipped with a
// one-line warning; a failed directory aborts the sync and the old data
// stays.
package syncing

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
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
	chain, err := loadOwnerChain(st)
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
			applied, deleted, err := applyChange(st, vaultID, deviceID, chain, &resp.Changes[i])
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

	if err := reconcileGrants(st, cl, vaultID, deviceID, chain); err != nil {
		return res, err
	}
	return res, nil
}

func applyChange(st *store.Store, vaultID, deviceID string, chain *ownerChain, ch *wire.SyncChange) (applied, deleted int, err error) {
	switch ch.Entity {
	case wire.EntityItem:
		var it wire.ItemData
		if err := json.Unmarshal(ch.Data, &it); err != nil {
			return 0, 0, fmt.Errorf("sync: item decode: %w", err)
		}
		// Every item row — live or tombstone — must carry a writer
		// signature that verifies under an active owner device (v2 E/F).
		// A failed row is not applied; the previous local state stays.
		if err := chain.verifyItem(&it); err != nil {
			warnSkipped("item", it.ItemID, err)
			return 0, 0, nil
		}
		if it.Tombstone {
			// Tombstone: drop the row, its grants and any local wraps
			// (design.md §6.3, §6.5). A stale tombstone replay must not
			// delete a newer local row, and the floor must survive the
			// deletion so this or an older revision stays rejected
			// (design §6.2).
			if floor, ok, _ := st.ItemRevisionFloor(vaultID, it.ItemID); ok && it.Revision <= floor {
				return 0, 0, nil
			}
			if err := st.DeleteItem(it.ItemID); err != nil {
				return 0, 0, err
			}
			if err := st.RaiseItemRevisionFloor(vaultID, it.ItemID, it.Revision); err != nil {
				return 0, 0, err
			}
			return 0, 1, nil
		}
		if old, ok, _ := st.GetItem(it.ItemID); ok && old.Revision >= it.Revision {
			// Reject revisions smaller than what has already been seen (design §6.2)
			return 0, 0, nil
		}
		// Tombstone-rollback replay guard: after a tombstone the row is
		// gone, so the live-row check above misses; the per-item floor
		// survives deletion and rejects anything not strictly newer.
		// A replayed stale row is dropped silently (same semantics as an
		// expired grant, §8.4).
		if floor, ok, _ := st.ItemRevisionFloor(vaultID, it.ItemID); ok && it.Revision <= floor {
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
		// Every grant row — live, revoked or item-cascade deletion — must
		// verify under an active owner key (v2 F); otherwise a malicious
		// server could revoke local capabilities without an owner.
		if err := chain.verifyGrant(&g, vaultID); err != nil {
			warnSkipped("grant", g.ItemID+"/"+g.Kind, err)
			return 0, 0, nil
		}
		if g.DeviceID != deviceID {
			// Rows for other devices should not be delivered; ignore.
			return 0, 0, nil
		}
		if g.Deleted || (len(g.HPKEEnc) == 0 && len(g.WrappedKey) == 0) {
			// Grant revoked (pointing at ourselves) or item deletion cascade: clear local wrap.
			// The revision floor survives (PutGrant on the deletion form raises it), so a
			// replayed live row at or below the deletion revision cannot resurrect the grant.
			if err := st.PutGrant(&g); err != nil {
				// The deletion form must never be rejected by the floor
				// (floor <= this revision is fine — we only refuse to
				// move backwards). Surface real storage errors.
				if !strings.Contains(err.Error(), "not above floor") {
					return 0, 0, err
				}
			}
			if err := st.DeleteGrant(g.ItemID, g.Kind); err != nil {
				return 0, 0, err
			}
			return 0, 1, nil
		}
		// Anti-resurrection replay guard: a correctly signed but stale
		// live row (revision at or below the deletion watermark) is
		// dropped silently, matching the semantics of an already-expired
		// grant (design.md §8.4: 撤销的送达不依赖行删除).
		if floor, ok, _ := st.GrantRevisionFloor(vaultID, g.ItemID, g.Kind); ok && g.Revision <= floor {
			return 0, 0, nil
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
		// A directory that does not verify under the saved directory's
		// active owner keys aborts the sync (v2 F); a tampered directory
		// must never be stored.
		if err := chain.verifyDirectory(d.Signed, d.Signature); err != nil {
			return 0, 0, err
		}
		// Revision monotonicity: a correctly signed but stale directory
		// (e.g. replayed by a malicious server to hide a revocation) is
		// dropped; only strictly newer revisions are applied.
		if prev, ok, _ := st.GetKV(pair.KVDirectoryRev); ok {
			if prevRev, perr := strconv.ParseUint(string(prev), 10, 64); perr == nil && d.DirectoryRevision <= prevRev {
				return 0, 0, nil
			}
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
		// Later rows in this batch verify against the new directory.
		chain.reloadSaved(d.Signed)
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
// a suppressed or forged grant set disables use (fail closed). Unlike a
// sync row, a grants/self row that fails the v2 F verification aborts
// the reconciliation: the digest comparison below trusts the delivered
// set, so accepting an unverified set would let a malicious server
// suppress capabilities by forging one row.
func reconcileGrants(st *store.Store, cl *client.Client, vaultID, deviceID string, chain *ownerChain) error {
	self, err := cl.GrantsSelf()
	if err != nil {
		// Offline-tolerated: reconciliation needs the network.
		return nil
	}
	for i := range self.Grants {
		g := self.Grants[i]
		if err := chain.verifyGrant(&g, vaultID); err != nil {
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
