package api

import (
	"encoding/json"
	"testing"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/quotas"
)

// TestQuotaEnforcedHosted walks the hosted mode (KEYREF_ENFORCE_QUOTAS=1):
// PoW-gated vault creation on plan free, item-count ceiling, the
// over-quota allowed-operations set (reads and deletes keep working),
// per-minute rate limiting, and the daily request budget.
func TestQuotaEnforcedHosted(t *testing.T) {
	e := newTestEnv(t, true)
	owner := e.createVault(t) // includes the PoW round

	// Session and account report plan free with concrete limits (§6.3,
	// §6.25).
	var acct wire.AccountResponse
	if s := e.doOut("GET", "/v1/account", owner.token, nil, &acct); s != 200 {
		t.Fatalf("account: %d", s)
	}
	if acct.Plan != quotas.PlanFree {
		t.Fatalf("hosted plan = %q, want free", acct.Plan)
	}
	if acct.Limits == nil || acct.Limits.Items == nil || *acct.Limits.Items != e.quota.Free.Items {
		t.Fatalf("free limits missing or wrong: %+v", acct.Limits)
	}
	if acct.Limits.RequestsPerDay == nil || *acct.Limits.RequestsPerDay != e.quota.Free.RequestsPerDay {
		t.Fatal("relaxed daily limit not reflected")
	}

	// Item count ceiling: the relaxed test table keeps 20 items.
	limit := e.quota.Free.Items
	for i := int64(0); i < limit; i++ {
		if s := owner.putItem(t, randHexID(t), 1, []byte("m"), []byte("s")); s != 200 {
			t.Fatalf("put item %d: %d", i, s)
		}
	}
	if s, raw := owner.putItemRaw(t); s != 429 {
		t.Fatalf("item over limit: want 429, got %d %s", s, raw)
	}

	// Over quota the allowed set still works: reads and deletes
	// (design §10.5 item 7), but growth writes are refused.
	if s, _ := e.do("GET", "/v1/sync?cursor=0", owner.token, nil); s != 200 {
		t.Fatalf("sync over quota: %d", s)
	}
	overItem := randHexID(t)
	tb, _ := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: owner.vaultID, ItemID: overItem, Revision: 1, WriterDeviceID: owner.deviceID,
	})
	sig, _ := wire.SignOwnerECDSA(tb, owner.signKey)
	if s, raw := e.do("DELETE", "/v1/items/"+overItem, owner.token, wire.DeleteItemRequest{Revision: 1, Signature: sig}); s != 404 {
		t.Fatalf("delete of unknown item over quota: want 404, got %d %s", s, raw)
	}

	// Daily request budget exhausted: writes refused, reads pass (§10.5-7).
	today := e.api.cfg.Now().UTC().Format("2006-01-02")
	e.setUsage(t, owner.vaultID, today, *acct.Limits.RequestsPerDay+10)
	if s, raw := owner.putItemRaw(t); s != 429 {
		t.Fatalf("write over daily budget: want 429, got %d %s", s, raw)
	}
	if s, raw := e.do("GET", "/v1/sync?cursor=0", owner.token, nil); s != 200 {
		t.Fatalf("read over daily budget must pass (§10.5-7): got %d %s", s, raw)
	}

	// Per-minute ceiling: tighten it below the current window usage.
	e.quota.Free.RequestsPerMinute = 1
	if s, raw := e.do("GET", "/v1/sync?cursor=0", owner.token, nil); s != 429 {
		t.Fatalf("per-minute limit: want 429, got %d %s", s, raw)
	}
	e.quota.Free.RequestsPerMinute = 1 << 20

	// Global free-tier budget gate (design §10.5 item 2): with the daily
	// request total over the global cap, new free vaults are refused.
	today = e.api.cfg.Now().UTC().Format("2006-01-02")
	e.setUsage(t, owner.vaultID, today, e.quota.GlobalDailyRequests+1)
	if _, status, raw := e.createVaultStatus(t); status != 429 {
		t.Fatalf("global budget gate: want 429, got %d %s", status, raw)
	} else if code := errCodeOf(raw); code != "quota_exceeded" {
		t.Fatalf("global budget gate code: %s", code)
	}
	e.setUsage(t, owner.vaultID, today, 10) // back under the budget

	// Second vault from the same IP: within the per-IP daily budget of 3.
	if _, status, raw := e.createVaultStatus(t); status != 201 {
		t.Fatalf("second vault: %d %s", status, raw)
	}
}

func errCodeOf(raw []byte) string {
	var e struct {
		Error string `json:"error"`
	}
	json.Unmarshal(raw, &e)
	return e.Error
}

// putItemRaw uploads one item with a random id (for over-quota probes).
func (o *testOwner) putItemRaw(t *testing.T) (int, []byte) {
	t.Helper()
	itemID := randHexID(t)
	meta := make([]byte, 100) // large enough to trip small storage ceilings
	secret := make([]byte, 40)
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: o.vaultID, ItemID: itemID, Revision: 1,
		MetaCiphertext: meta, SecretCiphertext: secret,
		WriterDeviceID: o.deviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(tb, o.signKey)
	if err != nil {
		t.Fatal(err)
	}
	return o.env.do("PUT", "/v1/items/"+itemID, o.token, wire.PutItemRequest{
		Revision: 1, MetaCiphertext: meta, SecretCiphertext: secret,
		WriterDeviceID: o.deviceID, Signature: sig,
	})
}

// TestQuotaStorageAndDevices covers the storage byte ceiling and the CLI
// device ceiling on the hosted plan.
func TestQuotaStorageAndDevices(t *testing.T) {
	e := newTestEnv(t, true)
	owner := e.createVault(t)

	// Shrink the storage ceiling below one item and watch the write fail
	// with quota_exceeded while small writes pass.
	e.quota.Free.StorageBytes = 64
	if s, raw := owner.putItemRaw(t); s != 429 {
		t.Fatalf("storage ceiling: want 429, got %d %s", s, raw)
	}
	e.quota.Free.StorageBytes = 1 << 20
	if s, _ := owner.putItemRaw(t); s != 200 {
		t.Fatalf("small item after ceiling restore: %d", s)
	}

	// CLI device ceiling of 1 on free (design §10.5).
	itemID := randHexID(t)
	if s := owner.putItem(t, itemID, 1, []byte("m"), []byte("s")); s != 200 {
		t.Fatalf("put item: %d", s)
	}
	cli1 := e.registerPair(t)
	owner.completePair(t, cli1, nil)
	e.quota.Free.DevicesCLI = 1
	cli2 := e.registerPair(t)
	g := owner.grant(t, cli2.deviceID, itemID, wire.GrantKindView, 1, 0)
	pairTB, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID: owner.vaultID, OwnerSignPublicKey: owner.signPub,
		Nonce: cli2.nonce, DeviceID: cli2.deviceID,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli2.hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: cli2.signPub,
		Label: "agent-2", Grants: []wire.GrantTranscript{g.Transcript(owner.vaultID)},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := wire.SignOwnerECDSA(pairTB, owner.signKey)
	if s, raw := e.do("POST", "/v1/pair/complete", owner.token, wire.PairCompleteRequest{
		Nonce: cli2.nonce,
		Device: wire.DeviceInput{
			DeviceID: cli2.deviceID, Kind: wire.DeviceKindCLI,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli2.hpkePub,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: cli2.signPub, Label: "agent-2",
		},
		Grants: []wire.GrantData{g}, Signature: sig,
	}); s != 429 {
		t.Fatalf("device ceiling: want 429, got %d %s", s, raw)
	}
}

// TestUnlimitedSelfHosted proves the quota switch really gates the whole
// machinery: the same flows that hit ceilings on hosted pass here.
func TestUnlimitedSelfHosted(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	for i := 0; i < 25; i++ { // past the free item ceiling
		if s := owner.putItem(t, randHexID(t), 1, []byte("m"), []byte("s")); s != 200 {
			t.Fatalf("item %d on unlimited: %d", i, s)
		}
	}
	var sess wire.SessionResponse
	var chal wire.SessionChallengeResponse
	e.doOut("POST", "/v1/session", "", wire.SessionRequest{DeviceID: owner.deviceID}, &chal)
	token := e.openSession(t, owner.deviceID, chal.Challenge, func(tb []byte) ([]byte, error) {
		return wire.SignOwnerECDSA(tb, owner.signKey)
	})
	_ = sess
	// Session payload reports unlimited with null limits (§6.7, §6.25).
	status, raw := e.do("GET", "/v1/account", token, nil)
	if status != 200 {
		t.Fatalf("account: %d", status)
	}
	var acct wire.AccountResponse
	json.Unmarshal(raw, &acct)
	if acct.Plan != quotas.PlanUnlimited {
		t.Fatalf("plan = %q, want unlimited", acct.Plan)
	}
	if acct.Limits == nil || acct.Limits.Items != nil {
		t.Fatalf("unlimited limits must be null: %+v", acct.Limits)
	}
}
