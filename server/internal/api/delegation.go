package api

import (
	"net/http"

	"github.com/lidessen/keyref/proto/wire"
)

// Auto-approval delegation (design v0.8 §14.8, protocol v1.2 §6.31).
// The delegation policy is an owner-signed §3.10 transcript the server
// only verifies and serves — it never parses the policy bytes. The
// policy JSON being plaintext is the feature's single new plaintext
// surface, recorded in design §6.4.

// handlePutDelegation implements PUT /v1/delegation (protocol §6.31):
// the owner installs (or revokes, via an empty {"v":1} policy) the
// auto-approval delegation. The signature must verify under an active
// owner key of the CURRENT directory — the same rule as directory
// updates (§6.15) — and the revision must strictly increase.
func (s *Server) handlePutDelegation(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	if state := s.gateWrite(ac, false); state != "" {
		writeError(w, state)
		return
	}
	var req wire.DelegationPutRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if req.DelegationRevision < 1 || len(req.DelegationSigned) == 0 || len(req.Signature) == 0 {
		writeError(w, "invalid_field")
		return
	}
	curRev, _, _, err := s.st.GetDelegation(r.Context(), ac.vault.ID)
	if err != nil {
		writeError(w, "internal")
		return
	}
	if int64(req.DelegationRevision) <= curRev {
		writeError(w, "revision_conflict")
		return
	}
	// Verify the §3.10 transcript shape and the owner signature under
	// the CALLING owner's key (which the directory already pinned — the
	// same trust anchor §6.15 uses for directory updates).
	parsed, err := wire.ParseDelegationTranscript(req.DelegationSigned, ac.vault.ID)
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if parsed.DelegationRevision != uint64(req.DelegationRevision) {
		writeError(w, "invalid_field") // structured fields must match the bytes
		return
	}
	if err := wire.VerifyOwnerSignature(req.DelegationSigned, req.Signature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}
	if err := s.st.SetDelegation(r.Context(), ac.vault.ID, int64(req.DelegationRevision),
		req.DelegationSigned, req.Signature); err != nil {
		writeStoreError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleGetDelegation implements GET /v1/delegation (protocol §6.31):
// any active device may read it — the decider must fetch the policy to
// evaluate approvals, and the owner's other devices render its state.
func (s *Server) handleGetDelegation(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	rev, signed, signature, err := s.st.GetDelegation(r.Context(), ac.vault.ID)
	if err != nil {
		writeError(w, "internal")
		return
	}
	resp := wire.DelegationGetResponse{DelegationRevision: uint64(rev)}
	if rev > 0 {
		resp.DelegationSigned = signed
		resp.Signature = signature
	}
	writeJSON(w, http.StatusOK, resp)
}

// delegationView is the store shape of the two vault columns.
type delegationView struct {
	Revision int64
	Signed   []byte
}
