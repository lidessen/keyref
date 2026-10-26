package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/store"
)

// handlePutGrants implements PUT /v1/grants (protocol §6.12). Each row
// carries its own §3.2 signature and a revision strictly greater than
// the stored one. Writing a grant also appends the synthetic item change
// so the freshly granted device pulls the item's current revision
// (design §6.3, §10.6).
func (s *Server) handlePutGrants(w http.ResponseWriter, r *http.Request) {
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
	var req wire.PutGrantsRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if len(req.Grants) == 0 {
		writeError(w, "invalid_field")
		return
	}

	grants := make([]store.Grant, 0, len(req.Grants))
	for i := range req.Grants {
		g := &req.Grants[i]
		if err := g.Validate(); err != nil {
			writeError(w, "invalid_field")
			return
		}
		if len(g.HPKEEnc) == 0 {
			// The deletion form travels only through DELETE /v1/grants.
			writeError(w, "invalid_field")
			return
		}
		dev, err := s.st.GetDevice(r.Context(), g.DeviceID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && dev.VaultID != ac.vault.ID) {
			writeError(w, "invalid_field")
			return
		} else if err != nil {
			writeError(w, "internal")
			return
		}
		item, err := s.st.GetItem(r.Context(), ac.vault.ID, g.ItemID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && item.Tombstone) {
			writeError(w, "invalid_field")
			return
		} else if err != nil {
			writeError(w, "internal")
			return
		}
		// Storage-class invariant (design §6.6, v0.7): local items (SQL
		// NULL secret_ciphertext) take view grants only — a use grant
		// would promise an item key the server row does not back.
		if g.Kind == wire.GrantKindUse && len(item.SecretCiphertext) == 0 {
			writeError(w, "local_item_grant_conflict")
			return
		}
		if err := g.VerifyOwnerSignature(ac.vault.ID, ac.device.SignPublicKey); err != nil {
			writeError(w, "bad_signature")
			return
		}
		stored, err := s.st.GetGrant(r.Context(), ac.vault.ID, g.DeviceID, g.ItemID, g.Kind)
		if errors.Is(err, store.ErrNotFound) {
			stored = nil
		} else if err != nil {
			writeError(w, "internal")
			return
		}
		if stored != nil && g.Revision <= uint64(stored.Revision) {
			writeError(w, "revision_conflict") // strictly increasing (§6.12)
			return
		}
		grants = append(grants, store.Grant{
			VaultID: ac.vault.ID, DeviceID: g.DeviceID, ItemID: g.ItemID, Kind: g.Kind,
			HPKEEnc: g.HPKEEnc, WrappedKey: g.WrappedKey,
			ExpiresAt: expiresOrNull(g.ExpiresAt), Revision: int64(g.Revision),
			Signature: g.Signature,
		})
	}
	if err := s.st.PutGrants(r.Context(), grants, s.cfg.Now().UnixMilli()); err != nil {
		writeStoreError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, wire.PutGrantsResponse{Applied: len(grants)})
}

// handleDeleteGrant implements DELETE /v1/grants (protocol §6.13). The
// owner signs the §3.2 deletion-form transcript; the stored row becomes
// a deletion row and the change is visible to that device even after it
// is revoked (delivery semantics, design §8.4). Grant deletion is always
// allowed over quota (§10.5 item 7).
func (s *Server) handleDeleteGrant(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	var req wire.DeleteGrantRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if !wire.ValidID(req.DeviceID) || !wire.ValidID(req.ItemID) || req.Revision < 1 {
		writeError(w, "invalid_field")
		return
	}
	if err := checkGrantKind(req.Kind); err != nil {
		writeError(w, "invalid_field")
		return
	}
	// Deletion transcript: expires_at 0, empty enc and wrapped key.
	tb, err := wire.BuildGrantTranscript(wire.GrantTranscript{
		VaultID:  ac.vault.ID,
		DeviceID: req.DeviceID,
		ItemID:   req.ItemID,
		Kind:     req.Kind,
		Revision: req.Revision,
	})
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if err := wire.VerifyOwnerSignature(tb, req.Signature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}
	stored, err := s.st.GetGrant(r.Context(), ac.vault.ID, req.DeviceID, req.ItemID, req.Kind)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, "not_found")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	if req.Revision <= uint64(stored.Revision) {
		writeError(w, "revision_conflict")
		return
	}
	if err := s.st.DeleteGrant(r.Context(), ac.vault.ID, req.DeviceID, req.ItemID, req.Kind,
		int64(req.Revision), req.Signature, s.cfg.Now().UnixMilli()); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func checkGrantKind(kind string) error {
	if kind != wire.GrantKindView && kind != wire.GrantKindUse {
		return errInvalidField
	}
	return nil
}

// handleGrantsSelf implements GET /v1/grants/self (protocol §6.14): a
// CLI device's own grants plus the digest it must reconcile against the
// directory's grants_digest (design §9.1, §10.6).
func (s *Server) handleGrantsSelf(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if ac.device.Kind != wire.DeviceKindCLI {
		writeError(w, "forbidden")
		return
	}
	rows, err := s.st.ListGrantsByDevice(r.Context(), ac.vault.ID, ac.device.ID, false)
	if err != nil {
		writeError(w, "internal")
		return
	}
	out := make([]wire.GrantData, 0, len(rows))
	transcripts := make([]wire.GrantTranscript, 0, len(rows))
	for i := range rows {
		g := &rows[i]
		out = append(out, grantWireData(g))
		transcripts = append(transcripts, wire.GrantTranscript{
			VaultID: g.VaultID, DeviceID: g.DeviceID, ItemID: g.ItemID, Kind: g.Kind,
			Revision: uint64(g.Revision), ExpiresAt: uint64(expiresWire(g.ExpiresAt)),
			HPKEEnc: g.HPKEEnc, WrappedKey: g.WrappedKey,
		})
	}
	digest, err := wire.GrantsDigest(transcripts)
	if err != nil {
		writeError(w, "internal")
		return
	}
	writeJSON(w, http.StatusOK, wire.GrantsSelfResponse{
		Grants:            out,
		GrantsDigest:      digest,
		DirectoryRevision: uint64(ac.vault.DirectoryRevision),
	})
}

// grantWireData renders a grant row per §8.3; deletion rows carry
// deleted=true and empty crypto fields.
func grantWireData(g *store.Grant) wire.GrantData {
	return wire.GrantData{
		DeviceID:   g.DeviceID,
		ItemID:     g.ItemID,
		Kind:       g.Kind,
		HPKEEnc:    g.HPKEEnc,
		WrappedKey: g.WrappedKey,
		ExpiresAt:  expiresWire(g.ExpiresAt),
		Revision:   uint64(g.Revision),
		Signature:  g.Signature,
		Deleted:    len(g.HPKEEnc) == 0,
	}
}

func expiresWire(n sql.NullInt64) int64 {
	if !n.Valid {
		return 0
	}
	return n.Int64
}
