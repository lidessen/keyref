package api

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/wire"
)

// A pending approval past expires_at must not accept a decision, even if
// the CLI never polled it (it would otherwise get a fresh 60 s window).
func TestApprovalDecisionAfterExpiryRefused(t *testing.T) {
	f := newApprovalFixture(t)
	status, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000)
	if status != 201 {
		t.Fatalf("create: %d %s", status, raw)
	}
	id := f.pendingID(t)
	f.clock.Advance(61 * time.Second)

	s, raw := f.e.do("POST", "/v1/approvals/"+id+"/decision", f.owner.token, wire.ApprovalDecisionRequest{
		Decision: wire.ApprovalStatusApproved, OneTimeEnc: []byte("enc"), OneTimeWrappedKey: []byte("wk"),
	})
	if s != 409 {
		t.Fatalf("late decision: want 409, got %d %s", s, raw)
	}
	expectError(t, raw, "approval_not_pending")
	if _, p := f.poll(t, id); p.Status != wire.ApprovalStatusExpired || len(p.OneTimeEnc) != 0 {
		t.Fatalf("poll after late decision: %+v", p)
	}
}

// Abandoned pending approvals must not hold the per-vault ceiling.
func TestExpiredPendingApprovalsFreeTheCap(t *testing.T) {
	f := newApprovalFixture(t)
	for i := 0; i < MaxPendingApprovals; i++ {
		if s, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 201 {
			t.Fatalf("create %d: %d %s", i, s, raw)
		}
	}
	if s, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 429 {
		t.Fatalf("over cap: want 429, got %d %s", s, raw)
	}
	f.clock.Advance(61 * time.Second)
	// Listing expires the stale rows ...
	if got := len(f.pendingList(t).Approvals); got != 0 {
		t.Fatalf("pending after expiry = %d, want 0", got)
	}
	// ... and creating works again.
	if s, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 201 {
		t.Fatalf("create after expiry: %d %s", s, raw)
	}
}

func TestExpiredPendingApprovalsFreeTheCapOnCreate(t *testing.T) {
	f := newApprovalFixture(t)
	for i := 0; i < MaxPendingApprovals; i++ {
		if s, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 201 {
			t.Fatalf("create %d: %d %s", i, s, raw)
		}
	}
	f.clock.Advance(61 * time.Second)
	if s, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 201 {
		t.Fatalf("create after expiry: %d %s", s, raw)
	}
}

// A pairing nonce is one-shot: re-registering it (even with other keys)
// must fail instead of resetting the row.
func TestPairRegisterNonceOneShot(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	cli := e.registerPair(t)
	owner.completePair(t, cli, nil)

	nonceRaw, _ := hex.DecodeString(cli.nonce)
	tb, err := wire.BuildPairRegisterTranscript(nonceRaw, "build-agent-1")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignEd25519(tb, cli.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := e.do("POST", "/v1/pair/register", "", wire.PairRegisterRequest{
		Nonce: cli.nonce, HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli.hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: cli.signPub,
		ProposedName: "build-agent-1", Signature: sig,
	})
	if status != 410 {
		t.Fatalf("re-register: want 410, got %d %s", status, raw)
	}
	expectError(t, raw, "pair_expired")
	sum := sha256.Sum256(nonceRaw)
	ps, err := e.st.GetPairSession(t.Context(), hex.EncodeToString(sum[:]))
	if err != nil || !ps.ConsumedAt.Valid {
		t.Fatalf("pair session must stay consumed: %+v %v", ps, err)
	}
}

// The signed delegation bytes carry a revision; it must equal the
// request's delegation_revision.
func TestDelegationRevisionMustMatchSignedBytes(t *testing.T) {
	e := newTestEnv(t, false)
	owner := e.createVault(t)
	signed, err := wire.BuildDelegationTranscript(wire.DelegationTranscript{
		VaultID: owner.vaultID, DelegationRevision: 1, PolicyJSON: `{"v":1}`,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(signed, owner.signKey)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := e.do("PUT", "/v1/delegation", owner.token, wire.DelegationPutRequest{
		DelegationRevision: 2, DelegationSigned: signed, Signature: sig,
	})
	if status != 400 {
		t.Fatalf("mismatched revision: want 400, got %d %s", status, raw)
	}
	expectError(t, raw, "invalid_field")
	status, raw = e.do("PUT", "/v1/delegation", owner.token, wire.DelegationPutRequest{
		DelegationRevision: 1, DelegationSigned: signed, Signature: sig,
	})
	if status != 204 {
		t.Fatalf("matching revision: want 204, got %d %s", status, raw)
	}
}
