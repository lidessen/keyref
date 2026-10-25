package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/store"
)

// syncPageSize is the incremental page ceiling (protocol §8.1).
const syncPageSize = 100

// handleSync implements GET /v1/sync (protocol §6.8, §8). Two modes:
//
//   - cursor=0 bootstraps from the current visible state as a batch of
//     synthetic changes and jumps the cursor to the log end (§8.1, no
//     history replay);
//   - cursor>0 streams the vault's log entries after that position.
//
// Revoked devices keep access to this endpoint but see only the
// directory, item tombstones and their own grant deletions (§8.4
// delivery semantics); every other endpoint rejects them.
func (s *Server) handleSync(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, true) // sync serves revoked devices too
	if !ok {
		return
	}
	cursorRaw := r.URL.Query().Get("cursor")
	cursor, err := strconv.ParseInt(cursorRaw, 10, 64)
	if err != nil || cursor < 0 {
		writeError(w, "invalid_field")
		return
	}

	if cursor == 0 {
		s.handleSyncBootstrap(w, r, ac)
		return
	}

	// Retention window: a cursor inside the cleaned range is stale and
	// the client must re-bootstrap with cursor=0 (§8.1).
	minSeq, err := s.st.MinChangeSeq(r.Context())
	if err != nil {
		writeError(w, "internal")
		return
	}
	if minSeq == nil || cursor < *minSeq {
		writeError(w, "cursor_stale")
		return
	}

	rows, err := s.st.ListChanges(r.Context(), ac.vault.ID, cursor, syncPageSize+1)
	if err != nil {
		writeError(w, "internal")
		return
	}
	hasMore := len(rows) > syncPageSize
	if hasMore {
		rows = rows[:syncPageSize]
	}
	changes := make([]wire.SyncChange, 0, len(rows))
	newCursor := cursor
	for _, row := range rows {
		newCursor = row.Seq
		if ch, ok := s.renderChange(r, ac, row); ok {
			changes = append(changes, ch)
		}
	}
	if len(rows) == 0 {
		// Nothing new; report the current log end so clients converge.
		if maxSeq, err := s.st.MaxChangeSeq(r.Context()); err == nil && maxSeq > cursor {
			newCursor = maxSeq
		}
	}
	writeJSON(w, http.StatusOK, wire.SyncResponse{
		Cursor:  newCursor,
		HasMore: hasMore,
		Changes: changes,
	})
}

func (s *Server) handleSyncBootstrap(w http.ResponseWriter, r *http.Request, ac *authCtx) {
	// Read the log end BEFORE reading the vault row for the directory
	// payload: a directory update that commits after MaxChangeSeq gets a
	// seq above the returned cursor and is delivered next round, while
	// anything committed before it is reflected in the (freshly read)
	// vault row below. The cursor must never skip past a committed
	// change whose content was not delivered (design §10.6).
	endSeq, err := s.st.MaxChangeSeq(r.Context())
	if err != nil {
		writeError(w, "internal")
		return
	}
	freshVault, err := s.st.GetVault(r.Context(), ac.vault.ID)
	if err != nil {
		writeError(w, "internal")
		return
	}
	ac.vault = freshVault
	now := s.cfg.Now().UnixMilli()
	changes := []wire.SyncChange{}

	addChange := func(entity, entityID string, data any) {
		raw, err := json.Marshal(data)
		if err != nil {
			return
		}
		changes = append(changes, wire.SyncChange{
			Seq: endSeq, Entity: entity, EntityID: entityID, CreatedAt: now, Data: raw,
		})
	}

	// The current directory is visible to every device, revoked or not.
	addChange(wire.EntityDirectory, "directory:"+ac.vault.ID, wire.DirectoryData{
		DirectoryRevision: uint64(ac.vault.DirectoryRevision),
		Signed:            ac.vault.DirectorySigned,
		Signature:         ac.vault.DirectorySignature,
	})

	// Revocation strips owner privileges first (design §10.6): a revoked
	// iOS device gets exactly the revoked view — directory, its own grant
	// deletions and tombstones of items it held — never the owner's full
	// item and grant rows.
	revoked := ac.device.Status == wire.DeviceStatusRevoked
	isOwner := ac.device.Kind == wire.DeviceKindIOS && !revoked

	// Grants.
	grants, err := s.st.ListGrantsByDevice(r.Context(), ac.vault.ID, ac.device.ID, true)
	if err != nil {
		writeError(w, "internal")
		return
	}
	if isOwner {
		grants, err = s.st.ListGrantsByVault(r.Context(), ac.vault.ID, true)
		if err != nil {
			writeError(w, "internal")
			return
		}
	}
	anyGrantItem := map[string]bool{}    // items this device ever held
	activeGrantItem := map[string]bool{} // items with a live grant
	for i := range grants {
		g := &grants[i]
		deleted := len(g.HPKEEnc) == 0
		anyGrantItem[g.ItemID] = true
		if !deleted {
			activeGrantItem[g.ItemID] = true
		}
		if revoked && !deleted {
			continue // revoked devices see only their grant deletations
		}
		addChange(wire.EntityGrant, "grant:"+g.DeviceID+":"+g.ItemID+":"+g.Kind, grantWireData(g))
	}

	// Items. Tombstone rows are always fetched: non-owner devices
	// receive the tombstones of items they held grants for (design
	// §10.6), which live in tombstone rows.
	items, err := s.st.ListItemsByVault(r.Context(), ac.vault.ID, true)
	if err != nil {
		writeError(w, "internal")
		return
	}
	for i := range items {
		it := &items[i]
		if isOwner {
			addChange(wire.EntityItem, "item:"+it.ItemID, itemWireData(it, true, true, true))
			continue
		}
		if revoked {
			// Tombstones of items this device once held grants for.
			if !it.Tombstone || !anyGrantItem[it.ItemID] {
				continue
			}
			addChange(wire.EntityItem, "item:"+it.ItemID, itemWireData(it, false, false, false))
			continue
		}
		visible := activeGrantItem[it.ItemID] || (it.Tombstone && anyGrantItem[it.ItemID])
		if visible {
			addChange(wire.EntityItem, "item:"+it.ItemID, s.cliItemData(r, ac, it))
		}
	}

	writeJSON(w, http.StatusOK, wire.SyncResponse{Cursor: endSeq, HasMore: false, Changes: changes})
}

// cliItemData renders an item for an active CLI device, honoring its
// view/use grants.
func (s *Server) cliItemData(r *http.Request, ac *authCtx, it *store.Item) wire.ItemData {
	var hasView, hasUse bool
	for _, kind := range []string{wire.GrantKindView, wire.GrantKindUse} {
		g, err := s.st.GetGrant(r.Context(), ac.vault.ID, ac.device.ID, it.ItemID, kind)
		if err == nil && len(g.HPKEEnc) > 0 {
			if kind == wire.GrantKindView {
				hasView = true
			} else {
				hasUse = true
			}
		}
	}
	return itemWireData(it, false, hasView, hasUse)
}

// renderChange materializes one log row for this caller, applying the
// §10.6 visibility rules. A false return means "not visible to this
// device" — the cursor still advances past it.
func (s *Server) renderChange(r *http.Request, ac *authCtx, row store.ChangeRow) (wire.SyncChange, bool) {
	kind, parts, err := wire.ParseEntityID(row.EntityID)
	if err != nil || kind != row.Entity {
		return wire.SyncChange{}, false // malformed rows are skipped, not fatal
	}
	// Revocation strips owner privileges first (design §10.6): a revoked
	// iOS device falls through to the same restricted view as a revoked
	// CLI device.
	revoked := ac.device.Status == wire.DeviceStatusRevoked
	isOwner := ac.device.Kind == wire.DeviceKindIOS && !revoked

	switch kind {
	case wire.EntityDirectory:
		// Re-read the vault: the row may have been updated after the
		// authorize-time snapshot, and the delivered directory content
		// must match the log position (design §10.6).
		vault, err := s.st.GetVault(r.Context(), ac.vault.ID)
		if err != nil {
			return wire.SyncChange{}, false
		}
		return wire.SyncChange{
			Seq: row.Seq, Entity: row.Entity, EntityID: row.EntityID, CreatedAt: row.CreatedAt,
			Data: marshalJSON(wire.DirectoryData{
				DirectoryRevision: uint64(vault.DirectoryRevision),
				Signed:            vault.DirectorySigned,
				Signature:         vault.DirectorySignature,
			}),
		}, true

	case wire.EntityItem:
		if len(parts) != 1 {
			return wire.SyncChange{}, false
		}
		item, err := s.st.GetItem(r.Context(), ac.vault.ID, parts[0])
		if errors.Is(err, store.ErrNotFound) {
			return wire.SyncChange{}, false
		} else if err != nil {
			return wire.SyncChange{}, false
		}
		if isOwner {
			return s.change(row, itemWireData(item, true, true, true)), true
		}
		var hasGrant, activeGrant bool
		for _, k := range []string{wire.GrantKindView, wire.GrantKindUse} {
			g, err := s.st.GetGrant(r.Context(), ac.vault.ID, ac.device.ID, item.ItemID, k)
			if err == nil {
				hasGrant = true
				if len(g.HPKEEnc) > 0 {
					activeGrant = true
				}
			}
		}
		if revoked {
			// Only tombstones, and only of items this device held.
			if !item.Tombstone || !hasGrant {
				return wire.SyncChange{}, false
			}
			return s.change(row, itemWireData(item, false, false, false)), true
		}
		if item.Tombstone {
			if !hasGrant {
				return wire.SyncChange{}, false
			}
			return s.change(row, itemWireData(item, false, false, false)), true
		}
		if !activeGrant {
			return wire.SyncChange{}, false
		}
		return s.change(row, s.cliItemData(r, ac, item)), true

	case wire.EntityGrant:
		if len(parts) != 3 {
			return wire.SyncChange{}, false
		}
		g, err := s.st.GetGrant(r.Context(), ac.vault.ID, parts[0], parts[1], parts[2])
		if errors.Is(err, store.ErrNotFound) {
			return wire.SyncChange{}, false
		} else if err != nil {
			return wire.SyncChange{}, false
		}
		deleted := len(g.HPKEEnc) == 0
		if isOwner {
			return s.change(row, grantWireData(g)), true
		}
		if g.DeviceID != ac.device.ID {
			return wire.SyncChange{}, false
		}
		if revoked && !deleted {
			return wire.SyncChange{}, false // revoked: deletions only
		}
		return s.change(row, grantWireData(g)), true

	case wire.EntityDevice:
		if revoked || !isOwner {
			return wire.SyncChange{}, false // CLI devices learn statuses via the directory
		}
		dev, err := s.st.GetDevice(r.Context(), parts[0])
		if err != nil || dev.VaultID != ac.vault.ID {
			return wire.SyncChange{}, false
		}
		revokedAt := (*int64)(nil)
		if dev.RevokedAt.Valid {
			v := dev.RevokedAt.Int64
			revokedAt = &v
		}
		return s.change(row, wire.DeviceData{
			DeviceID: dev.ID, Kind: dev.Kind, Status: dev.Status, Label: dev.Label,
			CreatedAt: dev.CreatedAt, RevokedAt: revokedAt,
		}), true

	default:
		// Approvals are Phase 2; nothing else exists in the log.
		return wire.SyncChange{}, false
	}
}

func (s *Server) change(row store.ChangeRow, data any) wire.SyncChange {
	return wire.SyncChange{
		Seq: row.Seq, Entity: row.Entity, EntityID: row.EntityID,
		CreatedAt: row.CreatedAt, Data: marshalJSON(data),
	}
}

func marshalJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
