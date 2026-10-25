package api

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/store"
)

// fakeClock drives api.Config.Now for tests that must control the
// approval polling floor and the expiry windows.
type fakeClock struct{ t time.Time }

func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// approvalFixture wires one vault (owner + item) with one paired CLI
// holding a view grant — the shape of an approval item (design §6.1:
// approval entries never get a long-term use grant).
type approvalFixture struct {
	e     *testEnv
	owner *testOwner
	cli   *testCLI
	item  string
	clock *fakeClock
}

func newApprovalFixture(t *testing.T) *approvalFixture {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	item := randHexID(t)
	if s := owner.putItem(t, item, 1, []byte("meta-a"), []byte("secret-a")); s != 200 {
		t.Fatalf("put item: %d", s)
	}
	cli := e.registerPair(t)
	owner.completePair(t, cli, []wire.GrantData{
		owner.grant(t, cli.deviceID, item, wire.GrantKindView, 1, 0),
	})
	cli.session(t)
	clock := &fakeClock{t: time.Now()}
	e.api.cfg.Now = clock.Now
	return &approvalFixture{e: e, owner: owner, cli: cli, item: item, clock: clock}
}

// submit signs a §6.19 approval request with the CLI device key.
func (f *approvalFixture) submit(t *testing.T, ciphertext []byte, expiresAt int64) (int, []byte) {
	t.Helper()
	sig, err := wire.SignEd25519(ciphertext, f.cli.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	return f.e.do("POST", "/v1/approvals", f.cli.token, wire.ApprovalCreateRequest{
		ItemID:            f.item,
		RequestCiphertext: ciphertext,
		RequestSignature:  sig,
		ExpiresAt:         expiresAt,
	})
}

// submitRaw posts the request body as-is (negative signature tests).
func (f *approvalFixture) submitRaw(t *testing.T, req wire.ApprovalCreateRequest) (int, []byte) {
	t.Helper()
	return f.e.do("POST", "/v1/approvals", f.cli.token, req)
}

// pendingList fetches the owner's pending queue.
func (f *approvalFixture) pendingList(t *testing.T) wire.ApprovalListResponse {
	t.Helper()
	var out wire.ApprovalListResponse
	if s := f.e.doOut("GET", "/v1/approvals?status=pending", f.owner.token, nil, &out); s != 200 {
		t.Fatalf("approval list: %d", s)
	}
	return out
}

// poll reads the approval once, advancing the fake clock past the 2s
// floor first.
func (f *approvalFixture) poll(t *testing.T, approvalID string) (int, wire.ApprovalPollResponse) {
	t.Helper()
	f.clock.Advance(ApprovalPollMinInterval + time.Millisecond)
	var out wire.ApprovalPollResponse
	s := f.e.doOut("GET", "/v1/approvals/"+approvalID, f.cli.token, nil, &out)
	return s, out
}

// decision posts an owner decision.
func (f *approvalFixture) decision(t *testing.T, approvalID string, req wire.ApprovalDecisionRequest) int {
	t.Helper()
	return f.e.doOut("POST", "/v1/approvals/"+approvalID+"/decision", f.owner.token, req, nil)
}

// pendingID returns the single pending approval's id (fail unless exactly
// one is pending).
func (f *approvalFixture) pendingID(t *testing.T) string {
	t.Helper()
	list := f.pendingList(t)
	if len(list.Approvals) != 1 {
		t.Fatalf("pending approvals = %d, want 1", len(list.Approvals))
	}
	return list.Approvals[0].ApprovalID
}

func TestApprovalFlowHappyPath(t *testing.T) {
	f := newApprovalFixture(t)

	reqCT := []byte("request-ciphertext-opaque-blob")
	status, raw := f.submit(t, reqCT, f.clock.t.UnixMilli()+60_000)
	if status != 201 {
		t.Fatalf("approval create: %d %s", status, raw)
	}
	var created wire.ApprovalCreateResponse
	if err := json.Unmarshal(raw, &created); err != nil || created.ApprovalID == "" {
		t.Fatalf("approval create response: %v %s", err, raw)
	}
	if !wire.ValidID(created.ApprovalID) {
		t.Fatalf("approval_id is not 32 lowercase hex: %q", created.ApprovalID)
	}
	if created.ExpiresAt != f.clock.t.UnixMilli()+60_000 {
		t.Fatalf("expires_at not echoed: %d", created.ExpiresAt)
	}

	// Owner queue: signature present so the owner verifies BEFORE
	// decrypting (design §8.3 step 3).
	list := f.pendingList(t)
	if len(list.Approvals) != 1 {
		t.Fatalf("pending = %d, want 1", len(list.Approvals))
	}
	row := list.Approvals[0]
	if !bytes.Equal(row.RequestCiphertext, reqCT) || row.CLIDeviceID != f.cli.deviceID || row.ItemID != f.item {
		t.Fatalf("pending row mismatch: %+v", row)
	}
	if err := wire.VerifyCLISignature(row.RequestCiphertext, row.RequestSignature, f.cli.signPub); err != nil {
		t.Fatalf("owner-side CLI signature verification failed: %v", err)
	}

	// Approve with the one-time wrap (owner side, opaque here).
	enc, wrapped := randBytes(t, 32), randBytes(t, 48)
	if s := f.decision(t, created.ApprovalID, wire.ApprovalDecisionRequest{
		Decision: wire.ApprovalStatusApproved, OneTimeEnc: enc, OneTimeWrappedKey: wrapped,
	}); s != 204 {
		t.Fatalf("decision approved: %d", s)
	}

	// First poll takes the wrap atomically...
	s, out := f.poll(t, created.ApprovalID)
	if s != 200 || out.Status != wire.ApprovalStatusApproved {
		t.Fatalf("poll approved: %d %+v", s, out)
	}
	if !bytes.Equal(out.OneTimeEnc, enc) || !bytes.Equal(out.OneTimeWrappedKey, wrapped) {
		t.Fatalf("poll wrap mismatch: %+v", out)
	}
	if out.ExpiresAt == 0 {
		t.Fatal("approved poll must carry the 60s pickup window")
	}

	// ...the second sees consumed, with no wrap bytes again.
	s, out2 := f.poll(t, created.ApprovalID)
	if s != 200 || out2.Status != wire.ApprovalStatusConsumed {
		t.Fatalf("poll consumed: %d %+v", s, out2)
	}
	if len(out2.OneTimeEnc) != 0 || len(out2.OneTimeWrappedKey) != 0 {
		t.Fatalf("consumed poll re-served the wrap: %+v", out2)
	}

	// The decision is no longer applicable.
	s, raw = f.e.do("POST", "/v1/approvals/"+created.ApprovalID+"/decision", f.owner.token,
		wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied})
	if s != 409 || expectError(t, raw, "approval_not_pending") != 0 {
		t.Fatalf("second decision: want 409 approval_not_pending, got %d %s", s, raw)
	}
}

func TestApprovalDenied(t *testing.T) {
	f := newApprovalFixture(t)
	status, raw := f.submit(t, []byte("denied-request"), f.clock.t.UnixMilli()+60_000)
	if status != 201 {
		t.Fatalf("create: %d %s", status, raw)
	}
	var created wire.ApprovalCreateResponse
	json.Unmarshal(raw, &created)
	if s := f.decision(t, created.ApprovalID, wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied}); s != 204 {
		t.Fatalf("deny: %d", s)
	}
	s, out := f.poll(t, created.ApprovalID)
	if s != 200 || out.Status != wire.ApprovalStatusDenied {
		t.Fatalf("poll denied: %d %+v", s, out)
	}
	// A denied row never serves a wrap again.
	if s := f.decision(t, created.ApprovalID, wire.ApprovalDecisionRequest{
		Decision: wire.ApprovalStatusApproved, OneTimeEnc: randBytes(t, 32), OneTimeWrappedKey: randBytes(t, 48),
	}); s != 409 {
		t.Fatalf("decision on denied row: %d", s)
	}
}

func TestApprovalSignatureRequired(t *testing.T) {
	f := newApprovalFixture(t)
	expires := f.clock.t.UnixMilli() + 60_000

	// Garbage signature → 403 bad_signature (§7.1: no unauthenticated
	// approval requests).
	sig, _ := wire.SignEd25519([]byte("other-bytes"), f.cli.signPriv)
	if s, raw := f.submitRaw(t, wire.ApprovalCreateRequest{
		ItemID: f.item, RequestCiphertext: []byte("ct"), RequestSignature: sig, ExpiresAt: expires,
	}); s != 403 || expectError(t, raw, "bad_signature") != 0 {
		t.Fatalf("wrong-signature create: want 403 bad_signature, got %d %s", s, raw)
	}
	// Missing signature field → the same (Ed25519 over ct cannot verify).
	if s, raw := f.submitRaw(t, wire.ApprovalCreateRequest{
		ItemID: f.item, RequestCiphertext: []byte("ct"), ExpiresAt: expires,
	}); s != 403 {
		t.Fatalf("missing signature: want 403, got %d %s", s, raw)
	}

	// The owner (or any non-CLI) cannot submit approvals.
	if s, _ := f.e.do("POST", "/v1/approvals", f.owner.token, wire.ApprovalCreateRequest{
		ItemID: f.item, RequestCiphertext: []byte("ct"), ExpiresAt: expires,
	}); s != 403 {
		t.Fatalf("owner create approval: want 403, got %d", s)
	}

	// The CLI cannot list the owner queue.
	if s, _ := f.e.do("GET", "/v1/approvals?status=pending", f.cli.token, nil); s != 403 {
		t.Fatalf("cli list approvals: want 403, got %d", s)
	}
	// And the CLI cannot decide (owner-only endpoint).
	if s, _ := f.e.do("POST", "/v1/approvals/"+randHexID(t)+"/decision", f.cli.token,
		wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied}); s != 403 {
		t.Fatalf("cli decision: want 403, got %d", s)
	}
}

func TestApprovalCreateValidation(t *testing.T) {
	f := newApprovalFixture(t)
	nowMs := f.clock.t.UnixMilli()

	// expires_at window: past, and beyond the 120 s cap.
	if s, _ := f.submit(t, []byte("ct"), nowMs-1); s != 400 {
		t.Fatalf("past expires_at: want 400, got %d", s)
	}
	if s, _ := f.submit(t, []byte("ct"), nowMs+MaxApprovalWindowMs+1); s != 400 {
		t.Fatalf("oversized window: want 400, got %d", s)
	}

	// Unknown and tombstoned items do not accept approvals.
	if s, _ := f.e.do("POST", "/v1/approvals", f.cli.token, wire.ApprovalCreateRequest{
		ItemID: randHexID(t), RequestCiphertext: []byte("ct"), ExpiresAt: nowMs + 60_000,
	}); s != 404 {
		t.Fatalf("unknown item: want 404, got %d", s)
	}

	// Malformed item_id → invalid_field; a well-formed one creates.
	if s, _ := f.submit(t, []byte("ct"), nowMs+60_000); s != 201 {
		t.Fatalf("valid flow sanity: %d", s)
	}
	f.item = "not-hex"
	if s, _ := f.submit(t, []byte("ct"), nowMs+60_000); s != 400 {
		t.Fatalf("bad item_id: want 400, got %d", s)
	}
}

func TestApprovalPendingCeiling(t *testing.T) {
	f := newApprovalFixture(t)
	for i := 0; i < MaxPendingApprovals; i++ {
		if s, raw := f.submit(t, []byte{byte(i)}, f.clock.t.UnixMilli()+60_000); s != 201 {
			t.Fatalf("submit %d: %d %s", i, s, raw)
		}
	}
	// The 11th pending request hits the ceiling.
	if s, raw := f.submit(t, []byte("x"), f.clock.t.UnixMilli()+60_000); s != 429 || expectError(t, raw, "quota_exceeded") != 0 {
		t.Fatalf("11th pending: want 429 quota_exceeded, got %d %s", s, raw)
	}
	// Approving one frees a slot (§10.5-7: decisions always work).
	list := f.pendingList(t)
	if len(list.Approvals) != MaxPendingApprovals {
		t.Fatalf("pending = %d, want %d", len(list.Approvals), MaxPendingApprovals)
	}
	id := list.Approvals[0].ApprovalID
	if s := f.decision(t, id, wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied}); s != 204 {
		t.Fatalf("deny: %d", s)
	}
	if s, _ := f.submit(t, []byte("y"), f.clock.t.UnixMilli()+60_000); s != 201 {
		t.Fatalf("submit after deny: %d", s)
	}
}

func TestApprovalExpiredStates(t *testing.T) {
	f := newApprovalFixture(t)

	// A pending row past its request window expires on the next poll.
	pending := &store.Approval{
		ID: randHexID(t), VaultID: f.owner.vaultID, CLIDeviceID: f.cli.deviceID,
		ItemID: f.item, RequestCiphertext: []byte("ct"), RequestSignature: []byte("sig"),
		Status: wire.ApprovalStatusPending, ExpiresAt: f.clock.t.UnixMilli() - 1,
		CreatedAt: f.clock.t.UnixMilli() - 60_000,
	}
	if err := f.e.st.InsertApproval(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	s, out := f.poll(t, pending.ID)
	if s != 200 || out.Status != wire.ApprovalStatusExpired {
		t.Fatalf("expired pending poll: %d %+v", s, out)
	}
	// Deciding an expired row is rejected.
	if s := f.decision(t, pending.ID, wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied}); s != 409 {
		t.Fatalf("decision on expired: %d", s)
	}

	// An approved row whose 60 s pickup window closed expires instead of
	// serving the wrap.
	approved := &store.Approval{
		ID: randHexID(t), VaultID: f.owner.vaultID, CLIDeviceID: f.cli.deviceID,
		ItemID: f.item, RequestCiphertext: []byte("ct"), RequestSignature: []byte("sig"),
		Status: wire.ApprovalStatusApproved, OneTimeWrap: []byte{0, 2, 1, 2},
		ExpiresAt: f.clock.t.UnixMilli() - 1, CreatedAt: f.clock.t.UnixMilli() - 120_000,
	}
	if err := f.e.st.InsertApproval(context.Background(), approved); err != nil {
		t.Fatal(err)
	}
	s, out = f.poll(t, approved.ID)
	if s != 200 || out.Status != wire.ApprovalStatusExpired {
		t.Fatalf("expired approved poll: %d %+v", s, out)
	}
	if len(out.OneTimeEnc) != 0 {
		t.Fatal("expired wrap must not be served")
	}

	// A foreign CLI never sees another CLI's approval.
	other := f.e.registerPair(t)
	f.owner.completePair(t, other, nil)
	other.session(t)
	if s, _ := f.e.do("GET", "/v1/approvals/"+pending.ID, other.token, nil); s != 404 {
		t.Fatalf("foreign CLI poll: want 404, got %d", s)
	}
}

func TestApprovalPollingFloor(t *testing.T) {
	f := newApprovalFixture(t)
	if s, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 201 {
		t.Fatalf("create: %d %s", s, raw)
	}
	id := f.pendingID(t)

	// First poll allowed, immediate second rejected (protocol §1.3: 审批
	// 轮询间隔 < 2 秒 → 429 rate_limited).
	f.clock.Advance(ApprovalPollMinInterval + time.Millisecond)
	if s, _ := f.e.do("GET", "/v1/approvals/"+id, f.cli.token, nil); s != 200 {
		t.Fatalf("first poll: %d", s)
	}
	if s, raw := f.e.do("GET", "/v1/approvals/"+id, f.cli.token, nil); s != 429 || expectError(t, raw, "rate_limited") != 0 {
		t.Fatalf("fast poll: want 429 rate_limited, got %d %s", s, raw)
	}

	// The floor does not consume the daily request budget (design §8.3):
	// usage_daily stays untouched by polls.
	n, err := f.e.st.GetUsage(context.Background(), f.owner.vaultID, f.clock.t.UTC().Format("2006-01-02"))
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("approval polls counted toward daily usage: %d", n)
	}
}

func TestApprovalSyncVisibilityAndStorage(t *testing.T) {
	f := newApprovalFixture(t)
	// Pending approval bytes count toward storage (design §10.5).
	before, err := f.e.st.VaultStorageBytes(context.Background(), f.owner.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	reqCT := bytes.Repeat([]byte{7}, 100)
	if s, _ := f.submit(t, reqCT, f.clock.t.UnixMilli()+60_000); s != 201 {
		t.Fatal("create")
	}
	id := f.pendingID(t)
	withPending, err := f.e.st.VaultStorageBytes(context.Background(), f.owner.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if withPending-before < int64(len(reqCT)) {
		t.Fatalf("storage bytes %d → %d exclude the pending approval ciphertext", before, withPending)
	}

	// Bootstrap sync carries the approval status to the owner and the
	// initiating CLI (protocol §8.1), with a status summary only.
	for _, tok := range []string{f.owner.token, f.cli.token} {
		batch := f.e.sync(t, tok, 0)
		var found []wire.SyncChange
		for _, c := range changesByEntity(batch)[wire.EntityApproval] {
			found = append(found, c)
		}
		if len(found) != 1 {
			t.Fatalf("bootstrap approval changes = %d, want 1", len(found))
		}
		var d wire.ApprovalStatusData
		if err := json.Unmarshal(found[0].Data, &d); err != nil {
			t.Fatal(err)
		}
		if d.ApprovalID != id || d.Status != wire.ApprovalStatusPending {
			t.Fatalf("approval status data: %+v", d)
		}
	}

	// An unrelated CLI sees no approval entity.
	other := f.e.registerPair(t)
	f.owner.completePair(t, other, nil)
	other.session(t)
	batch := f.e.sync(t, other.token, 0)
	if n := len(changesByEntity(batch)[wire.EntityApproval]); n != 0 {
		t.Fatalf("unrelated CLI saw %d approval changes", n)
	}

	// The decision transitions are delivered as further changes.
	b0 := f.e.sync(t, f.cli.token, 0) // bootstrap already showed pending
	f.decision(t, id, wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied})
	batch = f.e.sync(t, f.cli.token, b0.Cursor)
	var statuses []string
	for _, c := range changesByEntity(batch)[wire.EntityApproval] {
		var d wire.ApprovalStatusData
		json.Unmarshal(c.Data, &d)
		statuses = append(statuses, d.Status)
	}
	if len(statuses) != 1 || statuses[0] != wire.ApprovalStatusDenied {
		t.Fatalf("approval change trail after decision: %v", statuses)
	}

	// Consumed/denied approvals no longer count toward storage.
	total, err := f.e.st.VaultStorageBytes(context.Background(), f.owner.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	if total != before {
		t.Fatalf("non-pending approvals still counted: %d != %d", total, before)
	}
}
