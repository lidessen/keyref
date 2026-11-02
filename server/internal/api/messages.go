package api

import (
	"encoding/hex"
	"errors"
	"net/http"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/quotas"
	"github.com/lidessen/keyref/server/internal/store"
)

// SMS verification-code inbox (design v0.8 §14, protocol v1.2
// §5.28–§5.32). The server is the courier again: a source device uploads
// the encrypted envelope, the owner and the delegated decider read it,
// and nothing here ever sees the plaintext body.

// MessageTTLMs is the fixed server-stamped lifetime of a message
// (design §14.3: 24 hours, not client-extendable).
const MessageTTLMs = int64(24*60*60) * 1000

// MaxMessagePage is the page ceiling of GET /v1/messages (protocol
// §6.29), matching the audit page size.
const MaxMessagePage = 200

// MaxMessageUploadsPerDevicePerDay bounds one source device's uploads
// on hosted deployments (design §14.7): a compromised collector can
// only fill its own budget, never the vault's shared request pool.
const MaxMessageUploadsPerDevicePerDay = 100

// handlePostMessages implements POST /v1/messages (protocol §6.28).
// Only an active source device may submit; the §3.9 upload transcript
// signature must verify before the row is stored (same flow as
// approvals: 验不过返回 403 才落库).
func (s *Server) handlePostMessages(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if ac.device.Kind != wire.DeviceKindSource {
		writeError(w, "forbidden")
		return
	}
	if state := s.gateWrite(ac, false); state != "" {
		writeError(w, state)
		return
	}
	var req wire.MessageCreateRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if len(req.Envelope) == 0 || req.ReceivedAt < 0 {
		writeError(w, "invalid_field")
		return
	}
	now := s.cfg.Now()
	nowMs := now.UnixMilli()

	// Hosted ceilings (design §14.7): the per-device pending cap keeps
	// the inbox bounded, the daily counter keeps a runaway collector
	// inside its own budget. Self-hosted deployments skip both.
	if s.cfg.EnforceQuotas {
		plan := quotas.EffectivePlan(ac.vault, nowMs)
		if limits := s.quota.LimitsFor(plan); limits.MessagesPending != nil {
			active, err := s.st.CountActiveMessagesByDevice(r.Context(), ac.vault.ID, ac.device.ID)
			if err != nil {
				writeError(w, "internal")
				return
			}
			if active >= *limits.MessagesPending {
				writeError(w, "quota_exceeded")
				return
			}
		}
		day := now.UTC().Format("2006-01-02")
		uploads, err := s.st.CountMessageUploads(r.Context(), ac.device.ID, day)
		if err != nil {
			writeError(w, "internal")
			return
		}
		if uploads >= MaxMessageUploadsPerDevicePerDay {
			writeError(w, "quota_exceeded")
			return
		}
	}

	// Verify the source signature over the §3.9 transcript BEFORE the
	// row is durable.
	tb, err := wire.BuildMessageUploadTranscript(wire.MessageUploadTranscript{
		VaultID:        ac.vault.ID,
		SourceDeviceID: ac.device.ID,
		ReceivedAt:     uint64(req.ReceivedAt),
		Envelope:       req.Envelope,
	})
	if err != nil {
		writeError(w, "invalid_field")
		return
	}
	if err := wire.VerifyCLISignature(tb, req.RequestSignature, ac.device.SignPublicKey); err != nil {
		writeError(w, "bad_signature")
		return
	}

	m := &store.Message{
		VaultID:          ac.vault.ID,
		MessageID:        hex.EncodeToString(randomBytes(16)),
		SourceDeviceID:   ac.device.ID,
		Status:           wire.MessageStatusActive,
		Envelope:         req.Envelope,
		RequestSignature: req.RequestSignature,
		ReceivedAt:       req.ReceivedAt,
		CreatedAt:        nowMs,
		ExpiresAt:        nowMs + MessageTTLMs,
	}
	if err := s.st.InsertMessage(r.Context(), m); err != nil {
		writeError(w, "internal")
		return
	}
	if s.cfg.EnforceQuotas {
		day := now.UTC().Format("2006-01-02")
		if err := s.st.AddMessageUploads(r.Context(), ac.device.ID, day, 1); err != nil {
			writeError(w, "internal")
			return
		}
	}
	// Best-effort APNs wake-up; the payload carries no content (design
	// §14.4 — the lock screen is a semi-public surface).
	s.pushMessageCreated(ac.vault.ID, m.MessageID)
	writeJSON(w, http.StatusCreated, wire.MessageCreateResponse{
		MessageID: m.MessageID, ExpiresAt: m.ExpiresAt,
	})
}

// handleGetMessages implements GET /v1/messages (protocol §6.29): the
// owner's and the decider's inbox read. The sweep of expired rows is
// opportunistic here — the same lazy-cleanup class as audit retention.
func (s *Server) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	switch ac.device.Kind {
	case wire.DeviceKindIOS, wire.DeviceKindDecider:
	default:
		writeError(w, "forbidden")
		return
	}
	var since int64
	if raw := r.URL.Query().Get("since"); raw != "" {
		var neg bool
		for i := 0; i < len(raw); i++ {
			if raw[i] < '0' || raw[i] > '9' {
				neg = true
				break
			}
		}
		if neg || len(raw) > 18 {
			writeError(w, "invalid_field")
			return
		}
		for i := 0; i < len(raw); i++ {
			since = since*10 + int64(raw[i]-'0')
		}
	}
	now := s.cfg.Now()
	nowMs := now.UnixMilli()
	// Lazy TTL sweep (§14.3): same cleanup class as audit retention.
	if err := s.st.DeleteExpiredMessages(r.Context(), ac.vault.ID, nowMs); err != nil {
		writeError(w, "internal")
		return
	}
	rows, err := s.st.ListMessagesSince(r.Context(), ac.vault.ID, since, nowMs, MaxMessagePage+1)
	if err != nil {
		writeError(w, "internal")
		return
	}
	hasMore := len(rows) > MaxMessagePage
	if hasMore {
		rows = rows[:MaxMessagePage]
	}
	out := wire.MessageListResponse{Messages: make([]wire.MessageRow, 0, len(rows))}
	for i := range rows {
		m := &rows[i]
		out.Messages = append(out.Messages, wire.MessageRow{
			MessageID:      m.MessageID,
			SourceDeviceID: m.SourceDeviceID,
			Status:         m.Status,
			Envelope:       m.Envelope,
			ReceivedAt:     m.ReceivedAt,
			CreatedAt:      m.CreatedAt,
			ExpiresAt:      m.ExpiresAt,
		})
		if m.CreatedAt > out.Cursor {
			out.Cursor = m.CreatedAt
		}
	}
	out.HasMore = hasMore
	writeJSON(w, http.StatusOK, out)
}

// handleMessageWraps implements PUT /v1/messages/:message_id/wraps
// (protocol §6.30, D17): the owner backfills decider wraps for
// messages that predate the delegation. Envelope records are opaque;
// the server only orders and dedups by device_id.
func (s *Server) handleMessageWraps(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	messageID := r.PathValue("message_id")
	if !wire.ValidID(messageID) {
		writeError(w, "not_found")
		return
	}
	if state := s.gateWrite(ac, false); state != "" {
		writeError(w, state)
		return
	}
	var req wire.MessageWrapsRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if len(req.Wraps) == 0 {
		writeError(w, "invalid_field")
		return
	}
	records := make([][]byte, 0, len(req.Wraps))
	for i := range req.Wraps {
		wrap := &req.Wraps[i]
		if !wire.ValidID(wrap.DeviceID) {
			writeError(w, "invalid_field")
			return
		}
		rec, err := buildEnvelopeRecord(wrap.DeviceID, wrap.HPKEEnc, wrap.WrappedKey)
		if err != nil {
			writeError(w, "invalid_field")
			return
		}
		records = append(records, rec)
	}
	now := s.cfg.Now().UnixMilli()
	err := s.st.AppendMessageWraps(r.Context(), ac.vault.ID, messageID, records, now)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case errors.Is(err, store.ErrNotFound):
		writeError(w, "not_found")
	case errors.Is(err, store.ErrDuplicateEnvelopeTarget):
		writeError(w, "revision_conflict") // already wrapped for this decider (§6.30)
	default:
		writeError(w, "internal")
	}
}

// buildEnvelopeRecord assembles one §3.9 envelope record:
// u16be(id_len) ‖ device_id ‖ u16be(enc_len) ‖ enc ‖ wrapped(48B: HPKE ct).
func buildEnvelopeRecord(deviceID string, enc, wrapped []byte) ([]byte, error) {
	if len(enc) == 0 || len(enc) > 0xFFFF || len(wrapped) != wire.SizeMessageWrappedKey {
		return nil, errInvalidField
	}
	id := []byte(deviceID)
	out := make([]byte, 0, 2+len(id)+2+len(enc)+len(wrapped))
	out = append(out, byte(len(id)>>8), byte(len(id)))
	out = append(out, id...)
	out = append(out, byte(len(enc)>>8), byte(len(enc)))
	out = append(out, enc...)
	return append(out, wrapped...), nil
}

// handleMessageDelete implements DELETE /v1/messages/:message_id
// (protocol §6.31) — the inbox's manual delete (design §14.4).
func (s *Server) handleMessageDelete(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	messageID := r.PathValue("message_id")
	if !wire.ValidID(messageID) {
		writeError(w, "not_found")
		return
	}
	err := s.st.DeleteMessage(r.Context(), ac.vault.ID, messageID)
	switch {
	case err == nil:
		w.WriteHeader(http.StatusNoContent)
	case err == store.ErrNotFound:
		writeError(w, "not_found")
	default:
		writeError(w, "internal")
	}
}
