package api

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/wire"
)

// Local items (design §6.6, v0.7): secret_ciphertext is SQL NULL, the
// row is meta-only, use grants are mutually exclusive with the NULL
// secret, and the approval decision widens to 96 KiB so the owner can
// deliver the secret itself HPKE-wrapped to the CLI's ephemeral key.

// putItemLocal uploads one meta-only item revision (secret_ciphertext
// and vault_wrapped_item_key empty = SQL NULL, protocol §8.3).
func (o *testOwner) putItemLocal(t *testing.T, itemID string, revision uint64, meta []byte) (int, []byte) {
	t.Helper()
	return o.putItemRevision(t, itemID, revision, meta, nil)
}

// putItemRevision uploads one item revision with an explicit secret column
// (nil = SQL NULL) and returns the raw response for error-code asserts.
func (o *testOwner) putItemRevision(t *testing.T, itemID string, revision uint64, meta, secret []byte) (int, []byte) {
	t.Helper()
	vwm := bytes.Repeat([]byte{0xa1}, 40)
	var vwi []byte
	if secret != nil {
		vwi = bytes.Repeat([]byte{0xa2}, 40)
	}
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: o.vaultID, ItemID: itemID, Revision: revision,
		MetaCiphertext:      meta,
		SecretCiphertext:    secret,
		VaultWrappedMetaKey: vwm,
		VaultWrappedItemKey: vwi,
		WriterDeviceID:      o.deviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(tb, o.signKey)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := o.env.do("PUT", "/v1/items/"+itemID, o.token, wire.PutItemRequest{
		Revision: revision, MetaCiphertext: meta, SecretCiphertext: secret,
		VaultWrappedMetaKey: vwm, VaultWrappedItemKey: vwi,
		WriterDeviceID: o.deviceID, Signature: sig,
	})
	return status, raw
}

// localItemFixture is one vault with a meta-only item and a paired CLI
// holding the view grant — the shape of a local item (design §6.6:
// 永远没有 use 授予；每次 exec 审批).
type localItemFixture struct {
	f    *approvalFixture
	item string
	meta []byte
}

func newLocalItemFixture(t *testing.T) *localItemFixture {
	t.Helper()
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	item := randHexID(t)
	meta := []byte("meta-of-a-local-item")
	if s, raw := owner.putItemLocal(t, item, 1, meta); s != 200 {
		t.Fatalf("put meta-only item: %d %s", s, raw)
	}
	cli := e.registerPair(t)
	owner.completePair(t, cli, []wire.GrantData{
		owner.grant(t, cli.deviceID, item, wire.GrantKindView, 1, 0),
	})
	cli.session(t)
	clock := &fakeClock{t: time.Now()}
	e.api.cfg.Now = clock.Now
	// Reuse the approval-flow helpers (submit/poll/decision) by filling
	// the shared fixture with the local item.
	return &localItemFixture{
		f:    &approvalFixture{e: e, owner: owner, cli: cli, item: item, clock: clock},
		item: item, meta: meta,
	}
}

// TestLocalItemApprovalFlow drives the whole v0.7 chain: meta-only PUT →
// view grant → approval submit → owner decision carrying a
// secret-sized wrap (≤64 KiB payload + HPKE overhead) → the initiating
// CLI picks the wrap up exactly once.
func TestLocalItemApprovalFlow(t *testing.T) {
	lf := newLocalItemFixture(t)
	f := lf.f

	// GET /v1/items: the CLI sees meta, the secret column is empty.
	s, raw := f.e.do("GET", "/v1/items/"+lf.item, f.cli.token, nil)
	if s != 200 {
		t.Fatalf("cli get item: %d %s", s, raw)
	}
	var item wire.ItemData
	if err := json.Unmarshal(raw, &item); err != nil {
		t.Fatal(err)
	}
	if len(item.MetaCiphertext) == 0 || len(item.SecretCiphertext) != 0 {
		t.Fatalf("local item row for CLI: meta=%d secret=%d", len(item.MetaCiphertext), len(item.SecretCiphertext))
	}

	// Submit an approval for the local item and approve it with a
	// secret-sized payload: a 40 KiB "secret" wrapped by HPKE adds only
	// the 32-byte encapsulation plus the AEAD tag.
	reqCT := []byte("approval-request-for-local-item")
	if s, raw := f.submit(t, reqCT, f.clock.t.UnixMilli()+60_000); s != 201 {
		t.Fatalf("approval create: %d %s", s, raw)
	}
	id := f.pendingID(t)
	secretPayload := bytes.Repeat([]byte{0x5e}, 40<<10)
	if s := f.decision(t, id, wire.ApprovalDecisionRequest{
		Decision:          wire.ApprovalStatusApproved,
		OneTimeEnc:        randBytes(t, 32),
		OneTimeWrappedKey: append(randBytes(t, 32), secretPayload...),
	}); s != 204 {
		t.Fatalf("decision with secret-sized wrap: %d", s)
	}
	s, out := f.poll(t, id)
	if s != 200 || out.Status != wire.ApprovalStatusApproved {
		t.Fatalf("poll approved: %d %+v", s, out)
	}
	if !bytes.Contains(out.OneTimeWrappedKey, secretPayload) {
		t.Fatal("poll lost the delivered secret payload")
	}
	if s, out2 := f.poll(t, id); s != 200 || out2.Status != wire.ApprovalStatusConsumed {
		t.Fatalf("poll consumed: %d %+v", s, out2)
	}

	// Storage accounting (design §10.5 via §6.6): the local item
	// contributes ONLY its meta ciphertext bytes — the NULL secret and
	// NULL vault_wrapped_item_key must not void the row in the SUM.
	total, err := f.e.st.VaultStorageBytes(context.Background(), f.owner.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	// No approvals are pending any more and no audit rows exist, so the
	// total is exactly the meta row: meta + vault_wrapped_meta_key.
	if want := int64(len(lf.meta) + 40); total != want {
		t.Fatalf("storage bytes = %d, want %d (meta-only accounting)", total, want)
	}
}

// TestLocalItemGrantMutualExclusion pins both directions of the
// secret_ciphertext ⇄ use-grant exclusion (design §6.6, error code
// local_item_grant_conflict).
func TestLocalItemGrantMutualExclusion(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	local := randHexID(t)
	synced := randHexID(t)
	if s, raw := owner.putItemLocal(t, local, 1, []byte("local-meta")); s != 200 {
		t.Fatalf("put local item: %d %s", s, raw)
	}
	if s := owner.putItem(t, synced, 1, []byte("synced-meta"), []byte("synced-secret")); s != 200 {
		t.Fatalf("put synced item: %d", s)
	}
	cli := e.registerPair(t)
	owner.completePair(t, cli, nil)
	cli.session(t)

	// A use grant on a local item is rejected; a view grant is fine.
	bad := owner.grant(t, cli.deviceID, local, wire.GrantKindUse, 1, 0)
	s, raw := e.do("PUT", "/v1/grants", owner.token, wire.PutGrantsRequest{Grants: []wire.GrantData{bad}})
	if s != 400 || expectError(t, raw, "local_item_grant_conflict") != 0 {
		t.Fatalf("use grant on local item: want 400 local_item_grant_conflict, got %d %s", s, raw)
	}
	view := owner.grant(t, cli.deviceID, local, wire.GrantKindView, 1, 0)
	if s, raw := e.do("PUT", "/v1/grants", owner.token, wire.PutGrantsRequest{Grants: []wire.GrantData{view}}); s != 200 {
		t.Fatalf("view grant on local item: %d %s", s, raw)
	}

	// Control: the same use grant applies to a synced item.
	good := owner.grant(t, cli.deviceID, synced, wire.GrantKindUse, 1, 0)
	if s, raw := e.do("PUT", "/v1/grants", owner.token, wire.PutGrantsRequest{Grants: []wire.GrantData{good}}); s != 200 {
		t.Fatalf("use grant on synced item: %d %s", s, raw)
	}

	// Flipping a use-granted synced item to meta-only is rejected with
	// the dedicated code; the same flip without any use grant (the local
	// item) succeeds.
	flipRaw := []byte("synced-meta-2")
	if s, raw := owner.putItemRevision(t, synced, 2, flipRaw, nil); s != 400 || expectError(t, raw, "local_item_grant_conflict") != 0 {
		t.Fatalf("null-secret flip: want 400 local_item_grant_conflict, got %d %s", s, raw)
	}
	// The rejection must not have consumed the revision.
	if s, raw := owner.putItemRevision(t, synced, 2, flipRaw, []byte("synced-secret-2")); s != 200 {
		t.Fatalf("synced revision 2 with secret: %d %s", s, raw)
	}

	// A fresh meta-only item may gain a secret later (no use grants
	// exist to conflict with).
	grow := randHexID(t)
	if s, raw := owner.putItemLocal(t, grow, 1, []byte("grow-meta")); s != 200 {
		t.Fatalf("put grow item: %d %s", s, raw)
	}
	if s := owner.putItem(t, grow, 2, []byte("grow-meta-2"), []byte("grow-secret")); s != 200 {
		t.Fatalf("local item gains a secret: %d", s)
	}

	// Pair complete obeys the same rule: a use grant for the local item
	// inside the pair transcript is refused.
	rogue := e.registerPair(t)
	useGrant := owner.grant(t, rogue.deviceID, local, wire.GrantKindUse, 1, 0)
	gts := []wire.GrantTranscript{useGrant.Transcript(owner.vaultID)}
	pairTB, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID: owner.vaultID, OwnerSignPublicKey: owner.signPub,
		Nonce: rogue.nonce, DeviceID: rogue.deviceID,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: rogue.hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: rogue.signPub,
		Label: "build-agent-1", Grants: gts,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(pairTB, owner.signKey)
	if err != nil {
		t.Fatal(err)
	}
	s, raw = e.do("POST", "/v1/pair/complete", owner.token, wire.PairCompleteRequest{
		Nonce: rogue.nonce,
		Device: wire.DeviceInput{
			DeviceID: rogue.deviceID, Kind: wire.DeviceKindCLI,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: rogue.hpkePub,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: rogue.signPub,
			Label: "build-agent-1",
		},
		Grants: []wire.GrantData{useGrant}, Signature: sig,
	})
	if s != 400 || expectError(t, raw, "local_item_grant_conflict") != 0 {
		t.Fatalf("pair complete with use grant on local item: want 400 local_item_grant_conflict, got %d %s", s, raw)
	}
}

// TestDecisionBodyLimit pins the asymmetric ceilings of protocol §1.2
// (v0.7): the decision endpoint widens to 96 KiB, the approval request
// keeps 8 KiB.
func TestDecisionBodyLimit(t *testing.T) {
	f := newApprovalFixture(t)

	// The approval request keeps its 8 KiB ceiling: 9 KiB of ciphertext
	// (12 KiB base64) is refused before parsing.
	if s, raw := f.submit(t, bytes.Repeat([]byte{1}, 9<<10), f.clock.t.UnixMilli()+60_000); s != 413 || expectError(t, raw, "body_too_large") != 0 {
		t.Fatalf("oversized approval request: want 413 body_too_large, got %d %s", s, raw)
	}

	// A decision just under 96 KiB of JSON is accepted.
	if s, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 201 {
		t.Fatalf("create: %d %s", s, raw)
	}
	id := f.pendingID(t)
	// 66 KiB wrapped + 32 B enc → ~88 KiB base64 → under the ceiling.
	big := wire.ApprovalDecisionRequest{
		Decision:          wire.ApprovalStatusApproved,
		OneTimeEnc:        randBytes(t, 32),
		OneTimeWrappedKey: bytes.Repeat([]byte{2}, 66<<10),
	}
	if s := f.decision(t, id, big); s != 204 {
		t.Fatalf("decision at ~88 KiB: %d", s)
	}

	// A fresh approval whose decision crosses 96 KiB is refused with
	// body_too_large.
	if s, raw := f.submit(t, []byte("ct2"), f.clock.t.UnixMilli()+60_000); s != 201 {
		t.Fatalf("create 2: %d %s", s, raw)
	}
	id2 := f.pendingID(t)
	tooBig := wire.ApprovalDecisionRequest{
		Decision:          wire.ApprovalStatusApproved,
		OneTimeEnc:        randBytes(t, 32),
		OneTimeWrappedKey: bytes.Repeat([]byte{3}, 80<<10),
	}
	s, raw := f.e.do("POST", "/v1/approvals/"+id2+"/decision", f.owner.token, tooBig)
	if s != 413 || expectError(t, raw, "body_too_large") != 0 {
		t.Fatalf("oversized decision: want 413 body_too_large, got %d %s", s, raw)
	}
	// The row is still pending: the ceiling fired before any parsing.
	if id := f.pendingID(t); id != id2 {
		t.Fatalf("oversized decision disturbed the queue: %s != %s", id, id2)
	}
}
