package api

import (
	"errors"
	"net/http"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/quotas"
	"github.com/lidessen/keyref/server/internal/store"
)

// handleGetItem implements GET /v1/items/:item_id (protocol §6.9): the
// current revision on demand, filtered by the caller's grants — CLI
// devices see meta with a view grant, and never the vault_wrapped_*
// columns (§8.3).
//
// Secret-ciphertext visibility: the contract text says CLI devices
// receive secret_ciphertext with a use grant; the approval flow
// (design §8.3, protocol §7.1) additionally requires a CLI holding ONLY
// a view grant to carry the secret ciphertext, which its one-time item
// key then decrypts. The server therefore delivers secret_ciphertext on
// a view grant as well: the ciphertext is inert without the item key,
// which approval items never receive long-term (design §15).
func (s *Server) handleGetItem(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	itemID := r.PathValue("item_id")
	if !wire.ValidID(itemID) {
		writeError(w, "invalid_field")
		return
	}
	item, err := s.st.GetItem(r.Context(), ac.vault.ID, itemID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, "not_found")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	if ac.device.Kind == wire.DeviceKindIOS {
		writeJSON(w, http.StatusOK, itemWireData(item, true, true, true))
		return
	}
	var hasView, hasUse bool
	for _, kind := range []string{wire.GrantKindView, wire.GrantKindUse} {
		g, err := s.st.GetGrant(r.Context(), ac.vault.ID, ac.device.ID, itemID, kind)
		if err == nil && len(g.HPKEEnc) > 0 {
			if kind == wire.GrantKindView {
				hasView = true
			} else {
				hasUse = true
			}
		} else if err != nil && !errors.Is(err, store.ErrNotFound) {
			writeError(w, "internal")
			return
		}
	}
	if !hasView && !hasUse {
		writeError(w, "forbidden")
		return
	}
	writeJSON(w, http.StatusOK, itemWireData(item, false, hasView, hasUse))
}

// itemWireData renders an item row per §8.3. CLI devices never receive
// vault_wrapped_*; meta follows the view grant and the secret
// ciphertext follows any grant — see handleGetItem for why view alone
// carries the secret ciphertext (the approval flow).
func itemWireData(it *store.Item, forOwner, hasView, hasUse bool) wire.ItemData {
	d := wire.ItemData{
		VaultID:        it.VaultID,
		ItemID:         it.ItemID,
		Revision:       uint64(it.Revision),
		Tombstone:      it.Tombstone,
		WriterDeviceID: it.WriterDeviceID,
		Signature:      it.Signature,
		UpdatedAt:      it.UpdatedAt,
	}
	if forOwner || hasView {
		d.MetaCiphertext = it.MetaCiphertext
	}
	if forOwner || hasView || hasUse {
		d.SecretCiphertext = it.SecretCiphertext
	}
	if forOwner {
		d.VaultWrappedMetaKey = it.VaultWrappedMetaKey
		d.VaultWrappedItemKey = it.VaultWrappedItemKey
	}
	return d
}

// handlePutItem implements PUT /v1/items/:item_id (protocol §6.10): the
// revision must be exactly the stored value plus one, and the signature
// must verify under the caller's owner key over the §3.1 transcript
// rebuilt from the request fields. Item updates append the item change
// only — synthetic grant changes belong to grant writes (design §6.3).
func (s *Server) handlePutItem(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	if code := s.gateWrite(ac, false); code != "" {
		writeError(w, code)
		return
	}
	itemID := r.PathValue("item_id")
	if !wire.ValidID(itemID) {
		writeError(w, "invalid_field")
		return
	}
	var req wire.PutItemRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if req.Revision < 1 || req.Tombstone {
		// Deletion goes through DELETE (§6.11); PUT writes live rows.
		writeError(w, "invalid_field")
		return
	}
	if !wire.ValidID(req.WriterDeviceID) {
		writeError(w, "invalid_field")
		return
	}
	writer, err := s.st.GetDevice(r.Context(), req.WriterDeviceID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && (writer.VaultID != ac.vault.ID || writer.Kind != wire.DeviceKindIOS || writer.Status != wire.DeviceStatusActive)) {
		writeError(w, "invalid_field")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}

	// The signature covers the transcript rebuilt from the submitted
	// fields (protocol §1.5/D3), then the revision rule applies.
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID:             ac.vault.ID,
		ItemID:              itemID,
		Revision:            req.Revision,
		MetaCiphertext:      req.MetaCiphertext,
		SecretCiphertext:    req.SecretCiphertext,
		VaultWrappedMetaKey: req.VaultWrappedMetaKey,
		VaultWrappedItemKey: req.VaultWrappedItemKey,
		WriterDeviceID:      req.WriterDeviceID,
	})
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if err := wire.VerifyOwnerSignature(tb, req.Signature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}

	current, err := s.st.GetItem(r.Context(), ac.vault.ID, itemID)
	if errors.Is(err, store.ErrNotFound) {
		current = nil
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	want := uint64(1) // a fresh item starts at revision 1 (design §6.2)
	if current != nil {
		want = uint64(current.Revision) + 1
	}
	if req.Revision != want {
		writeError(w, "revision_conflict")
		return
	}

	// Plan ceilings: live item count and metered storage bytes
	// (design §10.5) — hosted only.
	if s.cfg.EnforceQuotas {
		now := s.cfg.Now()
		plan := quotas.EffectivePlan(ac.vault, now.UnixMilli())
		if plan != quotas.PlanUnlimited {
			limits := s.quota.LimitsFor(plan)
			if current == nil && limits.Items != nil {
				n, err := s.st.CountLiveItems(r.Context(), ac.vault.ID)
				if err == nil && n >= *limits.Items {
					writeError(w, "quota_exceeded")
					return
				}
			}
			if limits.StorageBytes != nil {
				used, err := s.st.VaultStorageBytes(r.Context(), ac.vault.ID)
				newBytes := int64(len(req.MetaCiphertext) + len(req.SecretCiphertext) +
					len(req.VaultWrappedMetaKey) + len(req.VaultWrappedItemKey))
				if current != nil {
					newBytes -= int64(len(current.MetaCiphertext) + len(current.SecretCiphertext) +
						len(current.VaultWrappedMetaKey) + len(current.VaultWrappedItemKey))
				}
				if err == nil && used+newBytes > *limits.StorageBytes {
					writeError(w, "quota_exceeded")
					return
				}
			}
		}
	}

	item := &store.Item{
		VaultID:             ac.vault.ID,
		ItemID:              itemID,
		Revision:            int64(req.Revision),
		Tombstone:           false,
		MetaCiphertext:      req.MetaCiphertext,
		SecretCiphertext:    req.SecretCiphertext,
		VaultWrappedMetaKey: req.VaultWrappedMetaKey,
		VaultWrappedItemKey: req.VaultWrappedItemKey,
		WriterDeviceID:      req.WriterDeviceID,
		Signature:           req.Signature,
		UpdatedAt:           s.cfg.Now().UnixMilli(),
	}
	if err := s.st.PutItem(r.Context(), item); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.PutItemResponse{Revision: req.Revision, UpdatedAt: item.UpdatedAt})
}

// handleDeleteItem implements DELETE /v1/items/:item_id (protocol
// §6.11). The tombstone signature covers the §3.1 transcript with four
// zero-length ciphertext fields; the cascade removes the item's grants
// (converted to deletion rows) with per-device change entries and the
// item change (design §6.3). Deletion is always allowed over quota and
// from frozen vaults (§10.5 item 7).
func (s *Server) handleDeleteItem(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	itemID := r.PathValue("item_id")
	if !wire.ValidID(itemID) {
		writeError(w, "invalid_field")
		return
	}
	var req wire.DeleteItemRequest
	if r.ContentLength != 0 {
		if err := decode(r, &req); err != nil {
			writeDecodeError(w, err)
			return
		}
	}
	if req.Revision < 1 {
		writeError(w, "invalid_field")
		return
	}
	current, err := s.st.GetItem(r.Context(), ac.vault.ID, itemID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, "not_found")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID:        ac.vault.ID,
		ItemID:         itemID,
		Revision:       req.Revision,
		WriterDeviceID: ac.device.ID,
	})
	if err != nil {
		writeError(w, "internal")
		return
	}
	if err := wire.VerifyOwnerSignature(tb, req.Signature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}
	if req.Revision != uint64(current.Revision)+1 {
		writeError(w, "revision_conflict")
		return
	}
	if err := s.st.TombstoneItem(r.Context(), ac.vault.ID, itemID, int64(req.Revision),
		ac.device.ID, req.Signature, s.cfg.Now().UnixMilli()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
