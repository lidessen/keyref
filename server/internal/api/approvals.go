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
	// Subject resolution (protocol D16): exactly one of item_id /
	// message_id; a message subject must carry the request's one-time
	// public key as plaintext for the decider (design v0.8 §14.8).
	subject, err := req.Subject()
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	// The request's one-time public key is a signed field for both
	// subjects (protocol v2 A): the decider never decrypts the request,
	// so this is the only authenticated source for the key it wraps the
	// SMS plaintext to.
	if len(req.CLIEphemeralPublicKey) != wire.SizeX25519Key {
		writeError(w, "invalid_field")
		return
	}
	var msg *store.Message
	if req.MessageID != "" {
		msg, err = s.st.GetMessage(r.Context(), ac.vault.ID, req.MessageID)
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, "not_found")
			return
		} else if err != nil {
			writeError(w, "internal")
			return
		}
	} else if !wire.ValidID(req.ItemID) {
		writeError(w, "invalid_field")
		return
	}
	now := s.cfg.Now()
	nowMs := now.UnixMilli()
	if req.ExpiresAt <= nowMs || req.ExpiresAt-nowMs > MaxApprovalWindowMs {
		writeError(w, "invalid_field")
		return
	}
	if req.MessageID == "" {
		it, err := s.st.GetItem(r.Context(), ac.vault.ID, req.ItemID)
		if errors.Is(err, store.ErrNotFound) || (err == nil && it.Tombstone) {
			writeError(w, "not_found")
			return
		} else if err != nil {
			writeError(w, "internal")
			return
		}
	} else {
		// Expired messages are swept lazily; an explicit check keeps the
		// inbox contract exact (design §14.5: unknown/expired → not_found).
		if msg.Status != wire.MessageStatusActive || msg.ExpiresAt <= nowMs {
			writeError(w, "not_found")
			return
		}
	}
	// The signature covers the subject, the expiry and the one-time
	// public key as well as a digest of the ciphertext (protocol §3.11).
	subjectKind, subjectIDForSignature := wire.EntityItem, req.ItemID
	if req.MessageID != "" {
		subjectKind, subjectIDForSignature = wire.EntityMessage, req.MessageID
	}
	tb, err := wire.BuildApprovalRequestTranscript(wire.ApprovalRequestTranscript{
		VaultID:               ac.vault.ID,
		CLIDeviceID:           ac.device.ID,
		SubjectKind:           subjectKind,
		SubjectID:             subjectIDForSignature,
		ExpiresAt:             uint64(req.ExpiresAt),
		CLIEphemeralPublicKey: req.CLIEphemeralPublicKey,
		RequestCiphertext:     req.RequestCiphertext,
	})
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if err := wire.VerifyCLISignature(tb, req.RequestSignature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}
	// Abandoned approvals (CLI never polled) must not hold the ceiling or
	// the one-live-approval-per-message rule below.
	if err := s.st.ExpirePendingApprovals(r.Context(), ac.vault.ID, nowMs); err != nil {
		writeError(w, "internal")
		return
	}
	// One live approval per MESSAGE subject (design §14.3: a message
	// cannot be double-spent through two concurrent approvals). Items
	// keep the v1.1 semantics — several pending approvals per item are
	// legitimate (one per exec attempt).
	if req.MessageID != "" {
		pendingForSubject, err := s.st.CountPendingBySubject(r.Context(), ac.vault.ID, subject)
		if err != nil {
			writeError(w, "internal")
			return
		}
		if pendingForSubject > 0 {
			writeError(w, "approval_not_pending")
			return
		}
	}
	subjectID := req.ItemID
	if req.MessageID != "" {
		subjectID = req.MessageID
	}
	a := &store.Approval{
		ID:                    hex.EncodeToString(randomBytes(16)),
		VaultID:               ac.vault.ID,
		CLIDeviceID:           ac.device.ID,
		ItemID:                subjectID,
		Subject:               subject,
		CLIEphemeralPublicKey: req.CLIEphemeralPublicKey,
		RequestCiphertext:     req.RequestCiphertext,
		RequestSignature:      req.RequestSignature,
		Status:                wire.ApprovalStatusPending,
		ExpiresAt:             req.ExpiresAt,
		CreatedAt:             nowMs,
	}
	// Count + insert + change append are one transaction, so concurrent
	// creates cannot exceed the per-vault ceiling.
	if err := s.st.InsertApprovalCapped(r.Context(), a, MaxPendingApprovals, nowMs); errors.Is(err, store.ErrApprovalCapReached) {
		writeError(w, "quota_exceeded")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	// Best-effort APNs wake-up for the owner devices (design §8.3
	// Phase 2). Runs after the row and its change are durable; failures
	// are logged inside and never reach the approval creator.
	s.pushApprovalCreated(ac.vault.ID, a.ID)
	writeJSON(w, http.StatusCreated, wire.ApprovalCreateResponse{
		ApprovalID: a.ID, ExpiresAt: a.ExpiresAt,
	})
}

// handleApprovalList implements GET /v1/approvals (protocol §6.20): the
// owner's pending queue. The status filter defaults to pending; "all"
// disables filtering. A decider sees ONLY message-subject rows, and
// only while pending — it evaluates them under the owner-signed
// delegation policy (design v0.8 §14.8).
func (s *Server) handleApprovalList(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
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
	decider := ac.device.Kind == wire.DeviceKindDecider
	switch {
	case ac.device.Kind == wire.DeviceKindIOS:
	case decider:
		// A decider's queue is pending message subjects only; statuses
		// beyond pending are the owner's audit view, not its business.
		if status != wire.ApprovalStatusPending {
			writeError(w, "forbidden")
			return
		}
	default:
		writeError(w, "forbidden")
		return
	}
	if err := s.st.ExpirePendingApprovals(r.Context(), ac.vault.ID, s.cfg.Now().UnixMilli()); err != nil {
		writeError(w, "internal")
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
		if decider && !a.IsMessageSubject() {
			continue
		}
		row := wire.ApprovalRow{
			ApprovalID:            a.ID,
			CLIDeviceID:           a.CLIDeviceID,
			ItemID:                a.ItemID,
			RequestCiphertext:     a.RequestCiphertext,
			RequestSignature:      a.RequestSignature,
			CreatedAt:             a.CreatedAt,
			ExpiresAt:             a.ExpiresAt,
			CLIEphemeralPublicKey: a.CLIEphemeralPublicKey,
		}
		if a.IsMessageSubject() {
			row.ItemID = ""
			row.MessageID = a.SubjectID()
		}
		out.Approvals = append(out.Approvals, row)
	}
	writeJSON(w, http.StatusOK, out)
}

// handleApprovalDecision implements POST /v1/approvals/:approval_id/decision
// (protocol §6.21). An approved decision must carry the one-time wrap
// and stamps the 60-second pickup window; both paths require the row to
// still be pending. The owner decides any subject; a DECIDER may only
// decide message subjects — the server enforces the boundary that
// keeps item approvals human-only (design v0.8 §14.8).
func (s *Server) handleApprovalDecision(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	approvalID := r.PathValue("approval_id")
	if !wire.ValidID(approvalID) {
		writeError(w, "not_found")
		return
	}
	// Kind authorization comes before existence (protocol §1.3: a CLI
	// decision is 403 forbidden regardless of the row).
	switch ac.device.Kind {
	case wire.DeviceKindIOS:
	case wire.DeviceKindDecider:
	default:
		writeError(w, "forbidden")
		return
	}
	a, err := s.st.GetApproval(r.Context(), ac.vault.ID, approvalID)
	if errors.Is(err, store.ErrNotFound) {
		writeError(w, "not_found")
		return
	} else if err != nil {
		writeError(w, "internal")
		return
	}
	if ac.device.Kind == wire.DeviceKindDecider && !a.IsMessageSubject() {
		// The boundary that keeps item approvals human-only is
		// server-enforced, not left to configuration (design v0.8 §14.8).
		writeError(w, "forbidden")
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
	if req.Decision == wire.ApprovalStatusApproved {
		wrap, err = store.PackOneTimeWrap(req.OneTimeEnc, req.OneTimeWrappedKey)
		if err != nil {
			writeError(w, "invalid_field")
			return
		}
	}
	// The decision must be signed by the device that submitted it
	// (protocol §3.12, v2 B). HPKE base mode authenticates nothing, so
	// this signature is what stops the server from handing the CLI a wrap
	// it fabricated.
	if len(req.DecisionSignature) == 0 {
		writeError(w, "invalid_field")
		return
	}
	dtb, err := wire.BuildApprovalDecisionTranscript(wire.ApprovalDecisionTranscript{
		VaultID:           ac.vault.ID,
		ApprovalID:        approvalID,
		DecisionDeviceID:  ac.device.ID,
		Decision:          req.Decision,
		RequestCiphertext: a.RequestCiphertext,
		OneTimeEnc:        req.OneTimeEnc,
		OneTimeWrappedKey: req.OneTimeWrappedKey,
	})
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if err := wire.VerifyDeviceSignature(dtb, req.DecisionSignature, ac.device.SignAlg, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}
	approved := req.Decision == wire.ApprovalStatusApproved
	// The deciding device is whoever signed this decision — the owner
	// (kind=ios) or the delegated decider (kind=decider). It is stored on
	// the row and echoed by the poll so the CLI can name it in the audit
	// event (design v0.8 §14.5/§14.8, protocol §6.22).
	if a.IsMessageSubject() {
		// Decision + one-way consumed stamp commit together (design
		// §14.3): a second approval can never deliver the same code.
		err = s.st.DecideApprovalForMessage(r.Context(), ac.vault.ID, approvalID, a.SubjectID(), ac.device.ID,
			approved, wrap, req.DecisionSignature, expiresAt, now)
	} else {
		err = s.st.DecideApproval(r.Context(), ac.vault.ID, approvalID, ac.device.ID,
			approved, wrap, req.DecisionSignature, expiresAt, now)
	}
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
	// DecisionDeviceID is empty (→ omitted, protocol §6.22) until a
	// decision has been accepted; pending and never-decided rows carry
	// nothing.
	resp := wire.ApprovalPollResponse{ApprovalID: a.ID, Status: a.Status,
		DecisionDeviceID: a.DecisionDeviceID, DecisionSignature: a.DecisionSignature}
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
