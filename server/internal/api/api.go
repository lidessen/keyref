// Package api implements the /v1 HTTP surface of keyref-server
// (docs/protocol.md §5–§8). The server is a dumb encrypted store plus
// signature checks (design §10.1): it never decrypts, never sees refs or
// names, and error bodies carry fixed error codes only — request fields
// are never echoed (design §11, §15).
package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/apns"
	"github.com/lidessen/keyref/server/internal/pow"
	"github.com/lidessen/keyref/server/internal/quotas"
	"github.com/lidessen/keyref/server/internal/store"
)

// Body size ceilings enforced before parsing (protocol §1.2).
const (
	MaxItemBodyBytes  = 256 << 10 // 256 KiB
	MaxAuditBodyBytes = 4 << 10   // 4 KiB
	MaxApprovalBytes  = 8 << 10   // 8 KiB
	MaxDefaultBody    = 1 << 20   // 1 MiB ceiling for every other endpoint
)

// Approval polling floor (protocol §1.3, §6.22): approval polls are the
// one request class that is neither daily-quota-counted nor
// per-minute-windowed — the floor is their only rate limit.
const ApprovalPollMinInterval = 2 * time.Second

// Session and challenge lifetimes (protocol §6.5, §6.7).
const (
	SessionTTL   = 12 * time.Hour
	ChallengeTTL = 60 * time.Second
)

// Unauthenticated-endpoint rate limits not pinned by the contract
// (values chosen here; see the segment report).
const (
	PairRegisterPerIPPerMinute = 10
	RecoveryPerKeyPerMinute    = 10
)

// Config carries the deployment settings the API layer needs.
type Config struct {
	EnforceQuotas bool // KEYREF_ENFORCE_QUOTAS=1 (design §12.3)
	Version       string
	Commit        string
	Origin        string // fixed public origin; empty means derive per request
	DataDir       string // for the disk-usage healthz check
	StartedAt     int64
	Now           func() time.Time // injectable clock for tests

	// Push is the optional APNs provider (design §8.3 Phase 2, §12.3).
	// nil — the default for deployments without KEYREF_APN_* variables —
	// disables push notifications; everything else is unaffected.
	Push apns.Provider
}

// Server holds the HTTP API state.
type Server struct {
	st    *store.Store
	quota *quotas.Manager
	pow   *pow.Issuer
	cfg   Config

	mu          sync.Mutex
	sessionChal map[string]pendingChallenge // device_id → outstanding session challenge
	deleteChal  map[string]pendingChallenge // vault_id → outstanding delete challenge
	perMinute   map[string]*rateWindow      // limiter key → request timestamps in window
	pollLast    map[string]time.Time        // approval polling floor keys
}

// rateWindow holds one limiter key's events together with the window
// they expire in. The window travels with the entry so the periodic
// sweep (pruneRateWindows) can age out keys it does not recognize —
// several key spaces are minted from client-supplied input
// (rec-vault:<id> before the vault row is read, §6.2), so the map must
// stay bounded without trusting keys to be revisited.
type rateWindow struct {
	window int64
	events []int64
}

// rateWindowPruneThreshold is the map size at which stale keys are
// swept. Steady state stays at roughly this many entries regardless of
// how many distinct keys unauthenticated callers mint.
const rateWindowPruneThreshold = 4096

type pendingChallenge struct {
	challenge []byte
	expires   time.Time
}

// New builds the API server around an opened store.
func New(st *store.Store, quota *quotas.Manager, po *pow.Issuer, cfg Config) *Server {
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.StartedAt == 0 {
		cfg.StartedAt = cfg.Now().UnixMilli()
	}
	return &Server{
		st:          st,
		quota:       quota,
		pow:         po,
		cfg:         cfg,
		sessionChal: map[string]pendingChallenge{},
		deleteChal:  map[string]pendingChallenge{},
		perMinute:   map[string]*rateWindow{},
		pollLast:    map[string]time.Time{},
	}
}

// Handler returns the fully routed HTTP handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /v1/healthz", s.handleHealthz)

	mux.HandleFunc("POST /v1/vaults", s.handleCreateVault)
	mux.HandleFunc("GET /v1/vaults/{vault_id}/recovery", s.handleGetRecoveryMaterials)
	mux.HandleFunc("POST /v1/recovery/directory", s.handleRecoveryTakeover)
	mux.HandleFunc("PUT /v1/vault/recovery", s.handlePutVaultRecovery)
	mux.HandleFunc("DELETE /v1/vaults/{vault_id}", s.handleDeleteVault)

	mux.HandleFunc("POST /v1/session", s.handleSession)

	mux.HandleFunc("GET /v1/sync", s.handleSync)
	mux.HandleFunc("GET /v1/items/{item_id}", s.handleGetItem)
	mux.HandleFunc("PUT /v1/items/{item_id}", s.handlePutItem)
	mux.HandleFunc("DELETE /v1/items/{item_id}", s.handleDeleteItem)
	mux.HandleFunc("PUT /v1/grants", s.handlePutGrants)
	mux.HandleFunc("DELETE /v1/grants", s.handleDeleteGrant)
	mux.HandleFunc("GET /v1/grants/self", s.handleGrantsSelf)
	mux.HandleFunc("PUT /v1/directory", s.handlePutDirectory)

	mux.HandleFunc("POST /v1/pair/register", s.handlePairRegister)
	mux.HandleFunc("POST /v1/pair/complete", s.handlePairComplete)
	mux.HandleFunc("GET /v1/pair/status", s.handlePairStatus)

	mux.HandleFunc("POST /v1/audit", s.handlePostAudit)
	mux.HandleFunc("GET /v1/audit", s.handleGetAudit)
	mux.HandleFunc("GET /v1/account", s.handleAccount)

	// Approval flow (design §8.3, protocol §6.19–§6.22): the polling
	// floor guards GET /v1/approvals/:id, whose handler performs its own
	// authorization because approval polling must not count against the
	// daily request budget.
	mux.HandleFunc("POST /v1/approvals", s.handleApprovalCreate)
	mux.HandleFunc("GET /v1/approvals/{approval_id}", s.approvalPollingFloor(s.handleApprovalPoll))
	mux.HandleFunc("POST /v1/approvals/{approval_id}/decision", s.handleApprovalDecision)
	mux.HandleFunc("GET /v1/approvals", s.handleApprovalList)

	// Push token registration (design §8.3 Phase 2): an active iOS
	// device registers the APNs token approval pushes are sent to.
	mux.HandleFunc("PUT /v1/devices/push-token", s.handlePutPushToken)

	mux.HandleFunc("POST /v1/billing/apple", notImplemented)

	mux.HandleFunc("/v1/", notImplemented)
	mux.HandleFunc("/", notImplemented)

	return s.middleware(mux)
}

func notImplemented(w http.ResponseWriter, r *http.Request) {
	writeError(w, "not_found")
}

// middleware wraps the mux with panic recovery and the per-route body
// ceilings of protocol §1.2 (enforced before any parsing).
func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("api: panic method=%s path=%s: %v", r.Method, redactPath(r), rec)
				writeError(w, "internal")
			}
		}()
		limit := s.bodyLimit(r)
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) bodyLimit(r *http.Request) int64 {
	p := r.URL.Path
	switch {
	case strings.HasPrefix(p, "/v1/items/") && (r.Method == http.MethodPut || r.Method == http.MethodDelete):
		return MaxItemBodyBytes
	case p == "/v1/audit" && r.Method == http.MethodPost:
		return MaxAuditBodyBytes
	case strings.HasPrefix(p, "/v1/approvals"):
		return MaxApprovalBytes
	default:
		return MaxDefaultBody
	}
}

// redactPath strips query strings for logging; ids may appear in paths,
// names and refs never do (they are encrypted, design §15).
func redactPath(r *http.Request) string { return r.URL.Path }

// ---------------------------------------------------------------------------
// error responses (protocol §1.3)

var errorStatus = map[string]int{
	"invalid_json":              400,
	"invalid_field":             400,
	"unauthorized":              401,
	"pow_required":              401,
	"delete_challenge_required": 401,
	"forbidden":                 403,
	"device_revoked":            403,
	"bad_signature":             403,
	"vault_frozen":              403,
	"not_found":                 404,
	"revision_conflict":         409,
	"cursor_stale":              409,
	"approval_not_pending":      409,
	"pair_expired":              410,
	"body_too_large":            413,
	"rate_limited":              429,
	"quota_exceeded":            429,
	"internal":                  500,
}

func writeError(w http.ResponseWriter, code string, extra ...map[string]any) {
	status, ok := errorStatus[code]
	if !ok {
		status = 500
		code = "internal"
	}
	body := map[string]any{"error": code}
	if len(extra) > 0 {
		for k, v := range extra[0] {
			body[k] = v
		}
	}
	b, err := json.Marshal(body)
	if err != nil {
		http.Error(w, `{"error":"internal"}`, 500)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(b)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		writeError(w, "internal")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(b)
}

// decode parses a JSON request body strictly: unknown fields are
// rejected, trailing garbage is rejected, syntax errors map to
// invalid_json and everything else to invalid_field (protocol §1.2).
func decode(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			return errTooLarge
		}
		var synErr *json.SyntaxError
		if errors.As(err, &synErr) {
			return errInvalidJSON
		}
		if errors.Is(err, io.EOF) {
			return errInvalidJSON
		}
		// base64/type/unknown-field problems are invalid_field.
		return errInvalidField
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errInvalidJSON
	}
	return nil
}

var (
	errInvalidJSON  = errors.New("invalid_json")
	errInvalidField = errors.New("invalid_field")
	errTooLarge     = errors.New("body_too_large")
)

// writeStoreError maps store-layer sentinel errors onto the wire error
// codes (protocol §1.3): revision guards that fired at commit time are
// revision_conflict, absent rows are not_found.
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrRevisionConflict):
		writeError(w, "revision_conflict")
	case errors.Is(err, store.ErrNotFound):
		writeError(w, "not_found")
	default:
		writeError(w, "internal")
	}
}

func writeDecodeError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, errTooLarge):
		writeError(w, "body_too_large")
	case errors.Is(err, errInvalidJSON):
		writeError(w, "invalid_json")
	case errors.Is(err, errInvalidField):
		writeError(w, "invalid_field")
	default:
		writeError(w, "invalid_field")
	}
}

// ---------------------------------------------------------------------------
// authentication and per-vault gating

// authCtx is the resolved caller of a bearer-authenticated request.
type authCtx struct {
	device *store.Device
	vault  *store.Vault
}

// authorize resolves the bearer token to a device row and vault,
// applying the per-minute rate limit and the daily request counter of
// the deployment's quota mode (design §10.5). allowRevoked lets the
// sync endpoint keep serving revoked devices (§8.4 delivery semantics);
// every other endpoint rejects them with device_revoked.
func (s *Server) authorize(w http.ResponseWriter, r *http.Request, allowRevoked bool) (*authCtx, bool) {
	token, ok := bearerToken(r)
	if !ok {
		writeError(w, "unauthorized")
		return nil, false
	}
	now := s.cfg.Now()
	dev, err := s.st.LookupSession(r.Context(), token, now.UnixMilli())
	if err != nil {
		writeError(w, "unauthorized")
		return nil, false
	}
	if dev.Status == wire.DeviceStatusRevoked && !allowRevoked {
		writeError(w, "device_revoked")
		return nil, false
	}
	if dev.Status != wire.DeviceStatusActive && !allowRevoked {
		writeError(w, "unauthorized")
		return nil, false
	}
	vault, err := s.st.GetVault(r.Context(), dev.VaultID)
	if err != nil {
		writeError(w, "unauthorized")
		return nil, false
	}
	ac := &authCtx{device: dev, vault: vault}
	if s.cfg.EnforceQuotas {
		if !s.quotaGate(r.Context(), ac, now) {
			writeError(w, "rate_limited")
			return nil, false
		}
	}
	return ac, true
}

// requireOwner rejects CLI tokens on owner-only endpoints (§11: kind=cli
// calling item writes, grants, directory, recovery or vault deletion →
// 403 forbidden).
func (s *Server) requireOwner(w http.ResponseWriter, ac *authCtx) bool {
	if ac.device.Kind != wire.DeviceKindIOS {
		writeError(w, "forbidden")
		return false
	}
	return true
}

// gateWrite enforces the write-side quota state: frozen vaults are
// read-only (vault_frozen), and once the daily request budget is spent
// only the §10.5-7 allowed set (reads, deletes) keeps working.
func (s *Server) gateWrite(ctx *authCtx, isDelete bool) string {
	if !s.cfg.EnforceQuotas {
		return ""
	}
	now := s.cfg.Now()
	plan := quotas.EffectivePlan(ctx.vault, now.UnixMilli())
	if plan == quotas.PlanUnlimited {
		return ""
	}
	frozen := ctx.vault.FrozenAt.Valid
	if !frozen && s.quota.ShouldFreeze(bgContext(), ctx.vault, now) {
		frozen = true
		_ = s.st.SetVaultFrozen(bgContext(), ctx.vault.ID, now.UnixMilli())
	}
	if frozen && !isDelete {
		return "vault_frozen"
	}
	if !isDelete {
		day := now.UTC().Format("2006-01-02")
		used, err := s.st.GetUsage(bgContext(), ctx.vault.ID, day)
		if err == nil {
			limits := s.quota.LimitsFor(plan)
			if limits.RequestsPerDay != nil && used > *limits.RequestsPerDay {
				return "quota_exceeded"
			}
		}
	}
	return ""
}

// quotaGate applies the per-minute window and increments the daily
// counter. Returns false when the per-minute ceiling is hit.
func (s *Server) quotaGate(ctx context.Context, ac *authCtx, now time.Time) bool {
	plan := quotas.EffectivePlan(ac.vault, now.UnixMilli())
	if plan == quotas.PlanUnlimited {
		return true
	}
	limits := s.quota.LimitsFor(plan)
	maxPerMin := int64(1 << 30)
	if limits.RequestsPerMinute != nil {
		maxPerMin = *limits.RequestsPerMinute
	}
	if !s.windowAllow("vault:"+ac.vault.ID, now.UnixMilli(), maxPerMin, 60_000) {
		return false
	}
	day := now.UTC().Format("2006-01-02")
	_, _ = s.st.IncrementUsage(ctx, ac.vault.ID, day)
	return true
}

// windowAllow applies one sliding window: at most max events per
// windowMs. Keys live at most one window past their last request —
// stale keys are swept whenever the map grows past the prune threshold
// (see pruneRateWindows).
func (s *Server) windowAllow(key string, nowMs, max int64, windowMs int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	w := s.perMinute[key]
	if w == nil {
		w = &rateWindow{window: windowMs}
		s.perMinute[key] = w
	}
	kept := w.events[:0]
	for _, t := range w.events {
		if nowMs-t < w.window {
			kept = append(kept, t)
		}
	}
	w.events = kept
	if int64(len(kept)) >= max {
		s.pruneRateWindows(nowMs)
		return false
	}
	w.events = append(kept, nowMs)
	s.pruneRateWindows(nowMs)
	return true
}

// pruneRateWindows drops limiter keys whose newest event has fallen out
// of the key's own window (an expired key would reject nothing, so
// recreating it on the next hit is equivalent). Called with s.mu held.
// This bounds the map even when unauthenticated callers mint keys from
// client-supplied ids — the same exposure class as the approval polling
// floor (design §10.5: no unauthenticated memory exhaustion).
func (s *Server) pruneRateWindows(nowMs int64) {
	if len(s.perMinute) <= rateWindowPruneThreshold {
		return
	}
	for k, w := range s.perMinute {
		newest := int64(0)
		for _, t := range w.events {
			if t > newest {
				newest = t
			}
		}
		if newest == 0 || nowMs-newest >= w.window {
			delete(s.perMinute, k)
		}
	}
}

// bearerToken extracts and validates the raw 32-byte bearer token
// (protocol §1.1: hex, 64 characters).
func bearerToken(r *http.Request) ([]byte, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return nil, false
	}
	raw := h[len(prefix):]
	if len(raw) != 64 {
		return nil, false
	}
	token, err := hex.DecodeString(raw)
	if err != nil {
		return nil, false
	}
	return token, true
}

// ---------------------------------------------------------------------------
// small shared helpers

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("api: entropy source failed: " + err.Error())
	}
	return b
}

func constantTimeEqual(a, b []byte) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1
}

// origin computes the public origin for session responses (§6.7): the
// configured origin wins, otherwise it is derived from the request.
func (s *Server) origin(r *http.Request) string {
	if s.cfg.Origin != "" {
		return s.cfg.Origin
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// clientIPKey normalizes the remote address into a rate-limit key:
// the /32 for IPv4 and the /64 for IPv6 (design §10.5 item 9).
func clientIPKey(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return "ip:unknown"
	}
	if v4 := ip.To4(); v4 != nil {
		return "ip4:" + v4.String()
	}
	masked := ip.Mask(net.CIDRMask(64, 128))
	return "ip6:" + masked.String()
}

func bgContext() context.Context { return context.Background() }

// approvalPollingFloor rejects approval-polling requests more frequent
// than every 2 seconds (protocol §1.3, §6.22; approval polling does not
// count against the daily request budget). The floor is keyed by the
// AUTHENTICATED device: unauthenticated polls never touch the limiter
// (they fail authorization first), so forging bearer tokens cannot
// mint fresh keys, and stale entries are pruned on every call to keep
// the map bounded.
func (s *Server) approvalPollingFloor(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, ok := bearerToken(r)
		if !ok {
			writeError(w, "unauthorized")
			return
		}
		device, err := s.st.LookupSession(r.Context(), token, s.cfg.Now().UnixMilli())
		if err != nil {
			writeError(w, "unauthorized")
			return
		}
		key := "poll:" + device.ID
		now := s.cfg.Now()
		s.mu.Lock()
		last, exists := s.pollLast[key]
		if !exists || now.Sub(last) >= ApprovalPollMinInterval {
			s.pollLast[key] = now
		}
		// Prune stale entries: anything untouched for minutes is gone.
		if len(s.pollLast) > 1024 {
			for k, t := range s.pollLast {
				if now.Sub(t) > time.Minute {
					delete(s.pollLast, k)
				}
			}
		}
		s.mu.Unlock()
		if exists && now.Sub(last) < ApprovalPollMinInterval {
			writeError(w, "rate_limited")
			return
		}
		next(w, r)
	}
}

// sessionPayload builds the §6.7/§6.3 session response.
func (s *Server) sessionPayload(r *http.Request, token []byte, expiresAt int64, vault *store.Vault) wire.SessionResponse {
	plan := vault.Plan
	if s.cfg.EnforceQuotas {
		plan = quotas.EffectivePlan(vault, s.cfg.Now().UnixMilli())
	} else {
		plan = quotas.PlanUnlimited
	}
	return wire.SessionResponse{
		Token:     hex.EncodeToString(token),
		ExpiresAt: expiresAt,
		Origin:    s.origin(r),
		Plan:      plan,
		Limits:    s.quota.LimitsFor(plan),
	}
}

// issueSession mints a bearer token for the device and returns the raw
// token bytes and its expiry.
func (s *Server) issueSession(ctx context.Context, deviceID string, now time.Time) ([]byte, int64, error) {
	token := randomBytes(32)
	expires := now.Add(SessionTTL).UnixMilli()
	sum := sha256Hex(token)
	err := s.st.InsertSession(ctx, &store.Session{
		TokenHash: sum, DeviceID: deviceID, ExpiresAt: expires,
	})
	if err != nil {
		return nil, 0, err
	}
	return token, expires, nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
