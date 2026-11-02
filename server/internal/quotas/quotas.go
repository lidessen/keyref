// Package quotas holds the hosted plan table, global budget and freeze
// semantics (design §10.5) and the per-vault request counters. All of it
// is inert unless the server was started with KEYREF_ENFORCE_QUOTAS=1:
// self-hosted deployments run as plan "unlimited" and never consult this
// package's limits (design §10.2, §12.3).
package quotas

import (
	"context"
	"time"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/store"
)

// Plan identifiers stored in vaults.plan.
const (
	PlanFree      = "free"
	PlanPlus      = "plus"
	PlanUnlimited = "unlimited"
)

// Limits of one plan (design §10.5 tier table; source/decider device
// and pending-message ceilings added with design v0.8 §14.7).
// Zero-value *int64 fields mean "not enforced" and serialize as null
// (§6.25).
type Limits struct {
	Items              int64
	DevicesIOS         int64
	DevicesCLI         int64
	DevicesSource      int64
	DevicesDecider     int64
	MessagesPending    int64
	StorageBytes       int64
	AuditRetentionDays int64
	AuditMaxEvents     int64
	RequestsPerDay     int64
	RequestsPerMinute  int64
}

// Free and Plus limits exactly as pinned by design §10.5.
var (
	FreeLimits = Limits{
		Items: 20, DevicesIOS: 1, DevicesCLI: 1,
		DevicesSource: 1, DevicesDecider: 1, MessagesPending: 20,
		StorageBytes: 1 << 20, AuditRetentionDays: 7, AuditMaxEvents: 100,
		RequestsPerDay: 500, RequestsPerMinute: 30,
	}
	PlusLimits = Limits{
		Items: 500, DevicesIOS: 3, DevicesCLI: 5,
		DevicesSource: 3, DevicesDecider: 3, MessagesPending: 200,
		StorageBytes: 50 << 20, AuditRetentionDays: 30, AuditMaxEvents: 5000,
		RequestsPerDay: 5000, RequestsPerMinute: 60,
	}
)

// Global budget shared by all free vaults on a hosted deployment
// (design §10.5 item 2).
const (
	GlobalFreeStorageBytes  = int64(2 << 30) // 2 GiB
	GlobalFreeDailyRequests = int64(1_000_000)
)

// BudgetWarnFraction is the usage fraction at which healthz reports
// degraded (design §10.5: 70%).
const BudgetWarnFraction = 0.70

// IdleFreezeDays is the free-tier idle window before a vault is frozen
// (design §10.5 item 8).
const IdleFreezeDays = 180

// RegistrationIPPerDay is the per-IP vault-creation cap (§10.5 item 9).
const RegistrationIPPerDay = int64(3)

// Manager evaluates plan limits against the store. Enforcement callers
// are responsible for honoring the over-quota allowed-operations set
// (reads, deletes, approval decisions — design §10.5 item 7).
type Manager struct {
	Store *store.Store
	// Testing hooks: override the plan tables and caps.
	Free                    Limits
	Plus                    Limits
	GlobalStorageBytes      int64
	GlobalDailyRequests     int64
	RegistrationPerIPPerDay int64
}

func NewManager(s *store.Store) *Manager {
	return &Manager{
		Store:                   s,
		Free:                    FreeLimits,
		Plus:                    PlusLimits,
		GlobalStorageBytes:      GlobalFreeStorageBytes,
		GlobalDailyRequests:     GlobalFreeDailyRequests,
		RegistrationPerIPPerDay: RegistrationIPPerDay,
	}
}

// EffectivePlan resolves the plan a vault is actually running under
// right now: an expired Plus subscription falls back to free (design
// §10.5 item 7). Self-hosted vaults are unlimited.
func EffectivePlan(v *store.Vault, nowMs int64) string {
	switch v.Plan {
	case PlanUnlimited:
		return PlanUnlimited
	case PlanPlus:
		if !v.PlanExpiresAt.Valid || v.PlanExpiresAt.Int64 > nowMs {
			return PlanPlus
		}
		return PlanFree
	default:
		return PlanFree
	}
}

// LimitsFor returns the concrete limits of a plan; unlimited yields all
// fields nil (serialized as nulls, §6.25).
func (m *Manager) LimitsFor(plan string) *wire.PlanLimits {
	var l Limits
	switch plan {
	case PlanPlus:
		l = m.Plus
	case PlanFree:
		l = m.Free
	default:
		return &wire.PlanLimits{}
	}
	ptr := func(v int64) *int64 { return &v }
	return &wire.PlanLimits{
		Items:              ptr(l.Items),
		DevicesIOS:         ptr(l.DevicesIOS),
		DevicesCLI:         ptr(l.DevicesCLI),
		DevicesSource:      ptr(l.DevicesSource),
		DevicesDecider:     ptr(l.DevicesDecider),
		MessagesPending:    ptr(l.MessagesPending),
		StorageBytes:       ptr(l.StorageBytes),
		AuditRetentionDays: ptr(l.AuditRetentionDays),
		AuditMaxEvents:     ptr(l.AuditMaxEvents),
		RequestsPerDay:     ptr(l.RequestsPerDay),
		RequestsPerMinute:  ptr(l.RequestsPerMinute),
	}
}

// ShouldFreeze reports whether a free vault has been idle long enough to
// freeze (lazy evaluation of design §10.5 item 8: no usage counter row
// for 180 days and the vault is older than that).
func (m *Manager) ShouldFreeze(ctx context.Context, v *store.Vault, now time.Time) bool {
	if v.Plan != PlanFree {
		return false
	}
	if v.FrozenAt.Valid {
		return true
	}
	if now.UnixMilli()-v.CreatedAt < int64(IdleFreezeDays)*24*3600*1000 {
		return false
	}
	since := now.AddDate(0, 0, -IdleFreezeDays).UTC().Format("2006-01-02")
	used, err := m.Store.HasUsageSince(ctx, v.ID, since)
	if err != nil {
		return false // fail open on evaluation errors; reads still work
	}
	return !used
}

// BudgetUsage returns the global free-tier storage and today's request
// totals (hosted healthz and the new-vault gate, design §10.5 item 2).
func (m *Manager) BudgetUsage(ctx context.Context, now time.Time) (storageBytes, requestsToday int64, err error) {
	day := now.UTC().Format("2006-01-02")
	vaults, err := m.Store.ListAllVaults(ctx)
	if err != nil {
		return 0, 0, err
	}
	for i := range vaults {
		v := &vaults[i]
		if EffectivePlan(v, now.UnixMilli()) != PlanFree {
			continue
		}
		b, err := m.Store.VaultStorageBytes(ctx, v.ID)
		if err != nil {
			return 0, 0, err
		}
		storageBytes += b
		r, err := m.Store.GetUsage(ctx, v.ID, day)
		if err != nil {
			return 0, 0, err
		}
		requestsToday += r
	}
	return storageBytes, requestsToday, nil
}

// DegradedReasons returns healthz degradation reasons for the global
// budget (design §10.5: expose budget ≥ 70% on /v1/healthz).
func (m *Manager) DegradedReasons(ctx context.Context, now time.Time) []string {
	storageBytes, requests, err := m.BudgetUsage(ctx, now)
	if err != nil {
		return nil
	}
	var reasons []string
	if float64(storageBytes) >= BudgetWarnFraction*float64(m.GlobalStorageBytes) {
		reasons = append(reasons, "budget_usage")
	}
	if float64(requests) >= BudgetWarnFraction*float64(m.GlobalDailyRequests) {
		reasons = append(reasons, "budget_usage")
	}
	return reasons
}
