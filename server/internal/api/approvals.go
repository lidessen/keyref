package api

import (
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/store"
)

// Approval flow (design §8.3, protocol §6.19–§6.22). The server is the
// courier: it verifies the CLI's Ed25519 request signature, stores the
// encrypted request, hands the owner the pending queue, applies the
// owner's decision (with the one-time wrap) and gives the initiating CLI
// its wrap exactly once. Every blob stays opaque to this process.

// MaxApprovalWindowMs bounds expires_at − now on a new approval request
// (protocol §6.19: "expires_at − now ≤ 120000", the CLI --timeout).
const MaxApprovalWindowMs = 120_000

// ApprovalWrapTTLMs is the 60-second one-time-wrap window the server
// stamps when the owner approves (protocol §6.21: expires_at = now +
// 60000).
const ApprovalWrapTTLMs = 60_000

// MaxPendingApprovals is the per-vault pending ceiling (design §8.3,
// §10.5).
const MaxPendingApprovals = 10

// handleApprovalCreate implements POST /v1/approvals (protocol §6.19).
// Only an active CLI device may submit; the request signature must
// verify under that device's current public key BEFORE the row is
// stored (§7.1 flow: "验不过返回 403 才落库").
func (s *Server) handleApprovalCreate(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if ac.device.Kind != wire.DeviceKindCLI {
		writeError(w, "forbidden")
		return
	}
	if state := s.gateWrite(ac, false); state != "" {
		writeError(w, state)
		return
	}
	var req wire.ApprovalCreateRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if !wire.ValidID(req.ItemID) {
		writeError(w, "invalid_field")
		return
	}
	now := s.cfg.Now()
	nowMs := now.UnixMilli()
	if req.ExpiresAt <= nowMs || req.ExpiresAt-nowMs > MaxApprovalWindowMs {
		writeError(w, "invalid_field")
		return
	}
	it, err := s.st.GetItem(r.Context(), ac.vault.ID, req.ItemID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && it.Tombstone) {
		writeError(w, "not_found")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	if err := wire.VerifyCLISignature(req.RequestCiphertext, req.RequestSignature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}
	pending, err := s.st.CountApprovalsByStatus(r.Context(), ac.vault.ID, wire.ApprovalStatusPending)
	if err != nil {
		writeError(w, "internal")
		return
	}
	if pending >= MaxPendingApprovals {
		writeError(w, "quota_exceeded")
		return
	}
	a := &store.Approval{
		ID:                hex.EncodeToString(randomBytes(16)),
		VaultID:           ac.vault.ID,
		CLIDeviceID:       ac.device.ID,
		ItemID:            req.ItemID,
		RequestCiphertext: req.RequestCiphertext,
		RequestSignature:  req.RequestSignature,
		Status:            wire.ApprovalStatusPending,
		ExpiresAt:         req.ExpiresAt,
		CreatedAt:         nowMs,
	}
	if err := s.st.InsertApproval(r.Context(), a); err != nil {
		writeError(w, "internal")
		return
	}
	s.appendApprovalChange(r, ac.vault.ID, a.ID, nowMs)
	// Best-effort APNs wake-up for the owner devices (design §8.3
	// Phase 2). Runs after the row and its change are durable; failures
	// are logged inside and never reach the approval creator.
	s.pushApprovalCreated(ac.vault.ID, a.ID)
	writeJSON(w, http.StatusCreated, wire.ApprovalCreateResponse{
		ApprovalID: a.ID, ExpiresAt: a.ExpiresAt,
	})
}

// handleApprovalList implements GET /v1/approvals (protocol §6.20), the
// owner's pending queue. The status filter defaults to pending; "all"
// disables filtering.
func (s *Server) handleApprovalList(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	status := r.URL.Query().Get("status")
	switch status {
	case "", wire.ApprovalStatusPending:
		status = wire.ApprovalStatusPending
	case "all",
		wire.ApprovalStatusApproved, wire.ApprovalStatusDenied,
		wire.ApprovalStatusExpired, wire.ApprovalStatusConsumed:
	default:
		writeError(w, "invalid_field")
		return
	}
	rows, err := s.st.ListApprovals(r.Context(), ac.vault.ID, status)
	if err != nil {
		writeError(w, "internal")
		return
	}
	out := wire.ApprovalListResponse{Approvals: make([]wire.ApprovalRow, 0, len(rows))}
	for i := range rows {
		a := &rows[i]
		out.Approvals = append(out.Approvals, wire.ApprovalRow{
			ApprovalID:        a.ID,
			CLIDeviceID:       a.CLIDeviceID,
			ItemID:            a.ItemID,
			RequestCiphertext: a.RequestCiphertext,
			RequestSignature:  a.RequestSignature,
			CreatedAt:         a.CreatedAt,
			ExpiresAt:         a.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleApprovalDecision implements POST /v1/approvals/:approval_id/decision
// (protocol §6.21). An approved decision must carry the one-time wrap
// and stamps the 60-second pickup window; both paths require the row to
// still be pending.
func (s *Server) handleApprovalDecision(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	approvalID := r.PathValue("approval_id")
	if !wire.ValidID(approvalID) {
		writeError(w, "not_found")
		return
	}
	var req wire.ApprovalDecisionRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	switch req.Decision {
	case wire.ApprovalStatusApproved:
		if len(req.OneTimeEnc) == 0 || len(req.OneTimeWrappedKey) == 0 {
			writeError(w, "invalid_field")
			return
		}
	case wire.ApprovalStatusDenied:
		if len(req.OneTimeEnc) != 0 || len(req.OneTimeWrappedKey) != 0 {
			writeError(w, "invalid_field")
			return
		}
	default:
		writeError(w, "invalid_field")
		return
	}
	now := s.cfg.Now().UnixMilli()
	expiresAt := now + ApprovalWrapTTLMs
	var wrap []byte
	var err error
	if req.Decision == wire.ApprovalStatusApproved {
		wrap, err = store.PackOneTimeWrap(req.OneTimeEnc, req.OneTimeWrappedKey)
		if err != nil {
			writeError(w, "invalid_field")
			return
		}
	}
	err = s.st.DecideApproval(r.Context(), ac.vault.ID, approvalID,
		req.Decision == wire.ApprovalStatusApproved, wrap, expiresAt, now)
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeError(w, "not_found")
	case errors.Is(err, store.ErrApprovalNotPending):
		writeError(w, "approval_not_pending")
	case err != nil:
		writeError(w, "internal")
	default:
		// DecideApproval already appended the approval change atomically.
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusNoContent)
	}
}

// handleApprovalPoll implements GET /v1/approvals/:approval_id
// (protocol §6.22) — the initiating CLI's poll. The route is wrapped by
// approvalPollingFloor, so this handler performs its own authorization:
// approval polling must NOT count against the daily request budget
// (design §5, §8.3), which authorize() would do under enforced quotas.
func (s *Server) handleApprovalPoll(w http.ResponseWriter, r *http.Request) {
	approvalID := r.PathValue("approval_id")
	if !wire.ValidID(approvalID) {
		writeError(w, "not_found")
		return
	}
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, "unauthorized")
		return
	}
	dev, err := s.st.LookupSession(r.Context(), token, s.cfg.Now().UnixMilli())
	if err != nil || dev.Status != wire.DeviceStatusActive {
		writeError(w, "unauthorized")
		return
	}
	a, err := s.st.GetApproval(r.Context(), dev.VaultID, approvalID)
	if errors.Is(err, store.ErrNotFound) || (err == nil && a.CLIDeviceID != dev.ID) {
		// Foreign approvals do not exist for this caller.
		writeError(w, "not_found")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	now := s.cfg.Now()
	nowMs := now.UnixMilli()
	resp := wire.ApprovalPollResponse{ApprovalID: a.ID, Status: a.Status}
	switch a.Status {
	case wire.ApprovalStatusPending:
		if a.ExpiresAt < nowMs {
			// ExpireApproval flips the row and appends the change.
			if err := s.st.ExpireApproval(r.Context(), dev.VaultID, a.ID, nowMs); err == nil {
				resp.Status = wire.ApprovalStatusExpired
			}
		}
	case wire.ApprovalStatusApproved:
		// ConsumeApprovalWrap is atomic: the first poll takes the wrap and
		// flips the row to consumed; an approved row past its 60-second
		// pickup window is marked expired instead (protocol §6.22). Both
		// outcomes append the approval change inside the transaction.
		enc, wrapped, expiresAt, cerr := s.st.ConsumeApprovalWrap(r.Context(), dev.VaultID, a.ID, nowMs)
		switch {
		case errors.Is(cerr, store.ErrApprovalExpired):
			resp.Status = wire.ApprovalStatusExpired
		case errors.Is(cerr, store.ErrApprovalNotPending):
			resp.Status = wire.ApprovalStatusConsumed
		case cerr != nil:
			writeError(w, "internal")
			return
		default:
			resp.Status = wire.ApprovalStatusApproved
			resp.OneTimeEnc = enc
			resp.OneTimeWrappedKey = wrapped
			resp.ExpiresAt = expiresAt
		}
	default:
		// denied / expired / consumed: reported as-is, never re-served.
	}
	writeJSON(w, http.StatusOK, resp)
}

// appendApprovalChange records the D8 approval status change so sync
// carries approval state transitions (design §10.6).
func (s *Server) appendApprovalChange(r *http.Request, vaultID, approvalID string, nowMs int64) {
	eid, err := wire.EntityIDApproval(approvalID)
	if err != nil {
		return
	}
	_, _ = s.st.AppendChange(r.Context(), vaultID, wire.EntityApproval, eid, nowMs)
}

// approvalWireData renders the sync "approval" entity data (protocol
// §8.3: a status summary, no ciphertext).
func approvalWireData(a *store.Approval) wire.ApprovalStatusData {
	return wire.ApprovalStatusData{ApprovalID: a.ID, Status: a.Status}
}
