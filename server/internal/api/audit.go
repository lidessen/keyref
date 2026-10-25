package api

import (
	"net/http"
	"strconv"
	"syscall"
	"time"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/quotas"
)

// auditPageSize is the GET /v1/audit page ceiling (protocol §6.24).
const auditPageSize = 200

// handlePostAudit implements POST /v1/audit (protocol §6.23). The
// ciphertext envelope stays opaque; retention trimming follows the
// vault's plan on hosted deployments (design §10.5).
func (s *Server) handlePostAudit(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if code := s.gateWrite(ac, false); code != "" {
		writeError(w, code)
		return
	}
	var req wire.AuditRequest
	if err := decode(r, &req); err != nil {
		writeDecodeError(w, err)
		return
	}
	if len(req.Ciphertext) == 0 {
		writeError(w, "invalid_field")
		return
	}
	now := s.cfg.Now()
	if s.cfg.EnforceQuotas {
		plan := quotas.EffectivePlan(ac.vault, now.UnixMilli())
		if plan != quotas.PlanUnlimited {
			limits := s.quota.LimitsFor(plan)
			if limits.StorageBytes != nil {
				used, err := s.st.VaultStorageBytes(r.Context(), ac.vault.ID)
				if err == nil && used+int64(len(req.Ciphertext)) > *limits.StorageBytes {
					writeError(w, "quota_exceeded")
					return
				}
			}
		}
	}
	seq, err := s.st.AppendAuditEvent(r.Context(), ac.vault.ID, ac.device.ID, req.Ciphertext, now.UnixMilli())
	if err != nil {
		writeError(w, "internal")
		return
	}
	if s.cfg.EnforceQuotas {
		plan := quotas.EffectivePlan(ac.vault, now.UnixMilli())
		if plan != quotas.PlanUnlimited {
			limits := s.quota.LimitsFor(plan)
			if limits.AuditMaxEvents != nil || limits.AuditRetentionDays != nil {
				keep := int64(1 << 30)
				olderThan := int64(0)
				if limits.AuditMaxEvents != nil {
					keep = *limits.AuditMaxEvents
				}
				if limits.AuditRetentionDays != nil {
					olderThan = now.Add(-time.Duration(*limits.AuditRetentionDays) * 24 * time.Hour).UnixMilli()
				}
				_ = s.st.TrimAuditEvents(r.Context(), ac.vault.ID, keep, olderThan)
			}
		}
	}
	writeJSON(w, http.StatusCreated, wire.AuditResponse{Seq: seq})
}

// handleGetAudit implements GET /v1/audit (protocol §6.24), owner only.
func (s *Server) handleGetAudit(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	cursorRaw := r.URL.Query().Get("cursor")
	cursor, err := strconv.ParseInt(cursorRaw, 10, 64)
	if err != nil || cursor < 0 {
		writeError(w, "invalid_field")
		return
	}
	events, more, err := s.st.ListAuditEvents(r.Context(), ac.vault.ID, cursor, auditPageSize)
	if err != nil {
		writeError(w, "internal")
		return
	}
	out := make([]wire.AuditEvent, 0, len(events))
	newCursor := cursor
	for _, e := range events {
		newCursor = e.Seq
		out = append(out, wire.AuditEvent{
			Seq: e.Seq, DeviceID: e.DeviceID, CreatedAt: e.CreatedAt, Ciphertext: e.Ciphertext,
		})
	}
	if len(events) == 0 {
		newCursor = cursor
	}
	writeJSON(w, http.StatusOK, wire.AuditPageResponse{Events: out, Cursor: newCursor, HasMore: more})
}

// handleAccount implements GET /v1/account (protocol §6.25), owner only.
// Self-hosted deployments report plan "unlimited" with null limits
// (§6.25).
func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	ac, ok := s.authorize(w, r, false)
	if !ok {
		return
	}
	if !s.requireOwner(w, ac) {
		return
	}
	now := s.cfg.Now()
	plan := quotas.PlanUnlimited
	var limits *wire.PlanLimits = &wire.PlanLimits{}
	if s.cfg.EnforceQuotas {
		plan = quotas.EffectivePlan(ac.vault, now.UnixMilli())
		limits = s.quota.LimitsFor(plan)
	} else if ac.vault.Plan != quotas.PlanUnlimited {
		plan = quotas.EffectivePlan(ac.vault, now.UnixMilli())
		limits = s.quota.LimitsFor(plan)
	}
	items, _ := s.st.CountLiveItems(r.Context(), ac.vault.ID)
	devices, _ := s.st.CountActiveDevices(r.Context(), ac.vault.ID, "")
	storage, _ := s.st.VaultStorageBytes(r.Context(), ac.vault.ID)
	auditCount, _ := s.st.CountAuditEvents(r.Context(), ac.vault.ID)
	requests, _ := s.st.GetUsage(r.Context(), ac.vault.ID, now.UTC().Format("2006-01-02"))
	var planExpires *int64
	if ac.vault.PlanExpiresAt.Valid {
		v := ac.vault.PlanExpiresAt.Int64
		planExpires = &v
	}
	writeJSON(w, http.StatusOK, wire.AccountResponse{
		Plan:          plan,
		PlanExpiresAt: planExpires,
		Limits:        limits,
		Usage: wire.AccountUsage{
			Items: items, DevicesActive: devices, StorageBytes: storage,
			AuditEvents: auditCount, RequestsToday: requests,
		},
	})
}

// handleHealthz implements GET /v1/healthz (protocol §10.2): liveness
// plus the degraded state surface for external probes (database
// writability, disk usage, hosted budget water level). It never reports
// vault-level data.
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	var reasons []string
	dbWritable := s.st.HealthzWriteProbe(r.Context()) == nil
	if !dbWritable {
		reasons = append(reasons, "db_not_writable")
	}
	if diskUsageHigh(s.cfg.DataDir) {
		reasons = append(reasons, "disk_usage")
	}
	if s.cfg.EnforceQuotas {
		reasons = append(reasons, s.quota.DegradedReasons(r.Context(), s.cfg.Now())...)
	}
	status := "ok"
	if len(reasons) > 0 {
		status = "degraded"
	}
	tlsMode := "plain"
	if s.cfg.Origin != "" && len(s.cfg.Origin) >= 8 && s.cfg.Origin[:8] == "https://" {
		tlsMode = "acme"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":      status,
		"version":     s.cfg.Version,
		"commit":      s.cfg.Commit,
		"started_at":  s.cfg.StartedAt,
		"db_writable": dbWritable,
		"tls":         map[string]any{"mode": tlsMode, "status": "ok"},
		"quotas": map[string]any{
			"enforced": s.cfg.EnforceQuotas,
			"degraded": s.cfg.EnforceQuotas && status == "degraded",
		},
		"reasons": reasons,
	})
}

// diskUsageHigh reports whether the volume holding dir is at least half
// full (design §10.5: expose disk >= 50% on healthz).
func diskUsageHigh(dir string) bool {
	if dir == "" {
		return false
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(dir, &st); err != nil {
		return false
	}
	if st.Blocks == 0 {
		return false
	}
	used := 1 - float64(st.Bavail)/float64(st.Blocks)
	return used >= 0.50
}
