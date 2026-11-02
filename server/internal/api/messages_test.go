package api

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/wire"
)

// futureExpires keeps approval windows inside the server's 120-second
// ceiling relative to the real clock.
func futureExpires() int64 { return time.Now().Add(60 * time.Second).UnixMilli() }

// ---------------------------------------------------------------------------
// fixtures for the v0.8 device kinds (design §14.2/§14.8)

type testKindDevice struct {
	env      *testEnv
	kind     string
	signPriv ed25519.PrivateKey
	signPub  []byte
	hpkePub  []byte
	nonce    string
	deviceID string
	token    string
}

// registerPairKind is registerPair generalized over the device kind
// (source/decider pair like a CLI: register, then owner completes).
func (e *testEnv) registerPairKind(t *testing.T, kind string) *testKindDevice {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	d := &testKindDevice{
		env: e, kind: kind,
		signPriv: priv, signPub: priv.Public().(ed25519.PublicKey),
		hpkePub:  randBytes(t, wire.SizeX25519Key),
		nonce:    randHexID(t),
		deviceID: randHexID(t),
	}
	nonceRaw, _ := hex.DecodeString(d.nonce)
	tb, err := wire.BuildPairRegisterTranscript(nonceRaw, "kind-"+kind)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignEd25519(tb, d.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	var out wire.PairRegisterResponse
	if status := e.doOut("POST", "/v1/pair/register", "", wire.PairRegisterRequest{
		Nonce: d.nonce, HPKEKEM: wire.KEMX25519, HPKEPublicKey: d.hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: d.signPub,
		ProposedName: "kind-" + kind, Signature: sig,
	}, &out); status != 201 {
		t.Fatalf("pair register %s: status %d", kind, status)
	}
	return d
}

// completePairKind runs pair/complete from the owner. source/decider
// devices always pair with an empty grant set (design §14.2, §14.8).
func (o *testOwner) completePairKind(t *testing.T, d *testKindDevice, grants []wire.GrantData) {
	t.Helper()
	grantsTB := make([]wire.GrantTranscript, 0, len(grants))
	for i := range grants {
		grants[i].DeviceID = d.deviceID
		grantsTB = append(grantsTB, grants[i].Transcript(o.vaultID))
	}
	pairTB, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID: o.vaultID, OwnerSignPublicKey: o.signPub,
		Nonce: d.nonce, DeviceID: d.deviceID,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: d.hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: d.signPub,
		Label: "kind-" + d.kind, Grants: grantsTB,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(pairTB, o.signKey)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := o.env.do("POST", "/v1/pair/complete", o.token, wire.PairCompleteRequest{
		Nonce: d.nonce,
		Device: wire.DeviceInput{
			DeviceID: d.deviceID, Kind: d.kind,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: d.hpkePub,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: d.signPub,
			Label: "kind-" + d.kind,
		},
		Grants: grants, Signature: sig,
	})
	if status != 204 {
		t.Fatalf("pair complete %s: status %d %s", d.kind, status, raw)
	}
}

func (d *testKindDevice) session(t *testing.T) {
	t.Helper()
	var chal wire.SessionChallengeResponse
	if status := d.env.doOut("POST", "/v1/session", "", wire.SessionRequest{DeviceID: d.deviceID}, &chal); status != 200 {
		t.Fatalf("%s session step 1: status %d", d.kind, status)
	}
	d.token = d.env.openSession(t, d.deviceID, chal.Challenge, func(tb []byte) ([]byte, error) {
		return wire.SignEd25519(tb, d.signPriv)
	})
}

// buildEnvelope assembles a minimal valid §3.9 envelope for one target
// (u8 count ‖ record ‖ body) — the server only walks the structure.
func buildEnvelope(t *testing.T, deviceID string, enc, wrapped []byte) []byte {
	t.Helper()
	rec, err := buildEnvelopeRecord(deviceID, enc, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	out := []byte{1}
	out = append(out, rec...)
	return append(out, randBytes(t, 40)...)
}

// ---------------------------------------------------------------------------
// the flow: source uploads → owner reads → CLI consumes via approval

func TestMessageFlow(t *testing.T) {
	env := newTestEnv(t, false)
	owner := env.createVault(t)

	src := env.registerPairKind(t, wire.DeviceKindSource)
	owner.completePairKind(t, src, nil)
	src.session(t)

	dec := env.registerPairKind(t, wire.DeviceKindDecider)
	owner.completePairKind(t, dec, nil)
	dec.session(t)

	cli := env.registerPair(t)
	owner.completePair(t, cli, nil)
	cli.session(t)

	// Kind enforcement: only a source uploads; cli/owner are 403.
	if status, _ := env.do("POST", "/v1/messages", cli.token, wire.MessageCreateRequest{
		Envelope: []byte{0}, ReceivedAt: 1,
	}); status != http.StatusForbidden {
		t.Fatalf("cli upload: status %d, want 403", status)
	}
	if status, _ := env.do("POST", "/v1/messages", owner.token, wire.MessageCreateRequest{
		Envelope: []byte{0}, ReceivedAt: 1,
	}); status != http.StatusForbidden {
		t.Fatalf("owner upload: status %d, want 403", status)
	}
	// A source cannot touch owner endpoints.
	if status, _ := env.do("PUT", "/v1/items/"+randHexID(t), src.token, map[string]any{}); status != http.StatusForbidden {
		t.Fatalf("source put item: status %d, want 403", status)
	}

	// Upload with a bad signature → 403 before the row is stored.
	good := buildEnvelope(t, owner.deviceID, randBytes(t, 32), randBytes(t, wire.SizeMessageWrappedKey))
	if status, _ := env.do("POST", "/v1/messages", src.token, wire.MessageCreateRequest{
		Envelope: good, RequestSignature: randBytes(t, 64), ReceivedAt: 1790000000000,
	}); status != http.StatusForbidden {
		t.Fatalf("upload bad signature: status %d, want 403", status)
	}

	// A good upload is accepted and stamped with the server TTL.
	tb, err := wire.BuildMessageUploadTranscript(wire.MessageUploadTranscript{
		VaultID: owner.vaultID, SourceDeviceID: src.deviceID,
		ReceivedAt: 1790000000000, Envelope: good,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignEd25519(tb, src.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	var created wire.MessageCreateResponse
	if status, raw := env.do("POST", "/v1/messages", src.token, wire.MessageCreateRequest{
		Envelope: good, RequestSignature: sig, ReceivedAt: 1790000000000,
	}); status != http.StatusCreated {
		t.Fatalf("upload: status %d body %s", status, raw)
	} else if err := json.Unmarshal(raw, &created); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	// Owner lists it; the decider sees it too; the CLI gets 403.
	var ownerList, decList wire.MessageListResponse
	if status := env.doOut("GET", "/v1/messages", owner.token, nil, &ownerList); status != 200 || len(ownerList.Messages) != 1 {
		t.Fatalf("owner list: status %d len %d", status, len(ownerList.Messages))
	}
	msg := ownerList.Messages[0]
	if msg.MessageID != created.MessageID || msg.Status != wire.MessageStatusActive {
		t.Fatalf("row mismatch: %+v", msg)
	}
	if status := env.doOut("GET", "/v1/messages", dec.token, nil, &decList); status != 200 || len(decList.Messages) != 1 {
		t.Fatalf("decider list: status %d len %d", status, len(decList.Messages))
	}
	if status, _ := env.do("GET", "/v1/messages", cli.token, nil); status != http.StatusForbidden {
		t.Fatalf("cli list: status %d, want 403", status)
	}

	// CLI consumes via approval; two concurrent approvals for one
	// message are rejected (design §14.3).
	mkReq := func() wire.ApprovalCreateRequest {
		ct := randBytes(t, 64)
		return wire.ApprovalCreateRequest{
			MessageID:             created.MessageID,
			CLIEphemeralPublicKey: randBytes(t, wire.SizeX25519Key),
			RequestCiphertext:     ct,
			RequestSignature:      signBytes(t, cli.signPriv, ct),
			ExpiresAt:             futureExpires(),
		}
	}
	var first wire.ApprovalCreateResponse
	if status := env.doOut("POST", "/v1/approvals", cli.token, mkReq(), &first); status != http.StatusCreated {
		t.Fatalf("message approval: status %d", status)
	}
	if status, _ := env.do("POST", "/v1/approvals", cli.token, mkReq()); status != http.StatusConflict {
		t.Fatalf("second pending approval: status %d, want 409", status)
	}

	// The owner sees the message row with the plaintext ephemeral key.
	var queue wire.ApprovalListResponse
	if status := env.doOut("GET", "/v1/approvals", owner.token, nil, &queue); status != 200 || len(queue.Approvals) != 1 {
		t.Fatalf("owner approval queue: status %d len %d", status, len(queue.Approvals))
	}
	row := queue.Approvals[0]
	if row.MessageID != created.MessageID || row.ItemID != "" || len(row.CLIEphemeralPublicKey) != wire.SizeX25519Key {
		t.Fatalf("message approval row: %+v", row)
	}

	// A CLI decision on anything is 403 before existence checks.
	if status, _ := env.do("POST", "/v1/approvals/"+first.ApprovalID+"/decision", cli.token,
		wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied}); status != http.StatusForbidden {
		t.Fatalf("cli decision: status %d, want 403", status)
	}

	// Owner approves; the CLI picks the wrap up exactly once.
	if status, _ := env.do("POST", "/v1/approvals/"+first.ApprovalID+"/decision", owner.token,
		wire.ApprovalDecisionRequest{
			Decision:          wire.ApprovalStatusApproved,
			OneTimeEnc:        randBytes(t, 32),
			OneTimeWrappedKey: randBytes(t, 60),
		}); status != http.StatusNoContent {
		t.Fatalf("owner decision: status %d", status)
	}
	var poll wire.ApprovalPollResponse
	if status := env.doOut("GET", "/v1/approvals/"+first.ApprovalID, cli.token, nil, &poll); status != 200 || poll.Status != wire.ApprovalStatusApproved {
		t.Fatalf("poll: status %d status-body %s", status, poll.Status)
	}
	time.Sleep(ApprovalPollMinInterval) // the 2s polling floor (§6.22)
	if status := env.doOut("GET", "/v1/approvals/"+first.ApprovalID, cli.token, nil, &poll); status != 200 || poll.Status != wire.ApprovalStatusConsumed {
		t.Fatalf("second poll: status %d status-body %s", status, poll.Status)
	}

	// The message is consumed: no further approvals, invisible to a
	// fresh owner list filtered client-side by status.
	if status, _ := env.do("POST", "/v1/approvals", cli.token, mkReq()); status != http.StatusNotFound {
		t.Fatalf("approval on consumed message: status %d, want 404", status)
	}

	// Manual delete (owner only) and the 404 for unknown ids.
	if status, _ := env.do("DELETE", "/v1/messages/"+created.MessageID, owner.token, nil); status != http.StatusNoContent {
		t.Fatalf("owner delete: status %d", status)
	}
	if status, _ := env.do("DELETE", "/v1/messages/"+created.MessageID, owner.token, nil); status != http.StatusNotFound {
		t.Fatalf("second delete: status %d, want 404", status)
	}
}

// TestDeciderDecisionPath pins the §14.8 boundary: the decider decides
// message subjects and nothing else; the server enforces it.
func TestDeciderDecisionPath(t *testing.T) {
	env := newTestEnv(t, false)
	owner := env.createVault(t)

	dec := env.registerPairKind(t, wire.DeviceKindDecider)
	owner.completePairKind(t, dec, nil)
	dec.session(t)

	cli := env.registerPair(t)
	owner.completePair(t, cli, nil)
	cli.session(t)

	// Delegate: owner signs the §3.10 transcript; revision must rise.
	policy := `{"v":1,"senders":["10086"],"max_age_min":5}`
	tb, err := wire.BuildDelegationTranscript(wire.DelegationTranscript{
		VaultID: owner.vaultID, DelegationRevision: 1, PolicyJSON: policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(tb, owner.signKey)
	if err != nil {
		t.Fatal(err)
	}
	if status, _ := env.do("PUT", "/v1/delegation", owner.token, wire.DelegationPutRequest{
		DelegationRevision: 1, DelegationSigned: tb, Signature: sig,
	}); status != http.StatusNoContent {
		t.Fatalf("put delegation: status %d", status)
	}
	// Same revision again → conflict.
	if status, _ := env.do("PUT", "/v1/delegation", owner.token, wire.DelegationPutRequest{
		DelegationRevision: 1, DelegationSigned: tb, Signature: sig,
	}); status != http.StatusConflict {
		t.Fatalf("stale delegation: status %d, want 409", status)
	}
	// The decider reads the policy; a CLI reading it is fine too.
	var got wire.DelegationGetResponse
	if status := env.doOut("GET", "/v1/delegation", dec.token, nil, &got); status != 200 || got.DelegationRevision != 1 {
		t.Fatalf("decider get delegation: status %d body %+v", status, got)
	}

	// One item approval + one message approval.
	itemID := randHexID(t)
	if status := owner.putItem(t, itemID, 1, randBytes(t, 32), randBytes(t, 32)); status != 200 {
		t.Fatalf("put item: %d", status)
	}
	itemCT := randBytes(t, 64)
	var itemApproval wire.ApprovalCreateResponse
	if status := env.doOut("POST", "/v1/approvals", cli.token, wire.ApprovalCreateRequest{
		ItemID: itemID, RequestCiphertext: itemCT,
		RequestSignature: signBytes(t, cli.signPriv, itemCT), ExpiresAt: futureExpires(),
	}, &itemApproval); status != http.StatusCreated {
		t.Fatalf("item approval: status %d", status)
	}

	src := env.registerPairKind(t, wire.DeviceKindSource)
	owner.completePairKind(t, src, nil)
	src.session(t)
	envelope := buildEnvelope(t, owner.deviceID, randBytes(t, 32), randBytes(t, wire.SizeMessageWrappedKey))
	utb, err := wire.BuildMessageUploadTranscript(wire.MessageUploadTranscript{
		VaultID: owner.vaultID, SourceDeviceID: src.deviceID,
		ReceivedAt: 1790000000000, Envelope: envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	usig, err := wire.SignEd25519(utb, src.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	var created wire.MessageCreateResponse
	if status := env.doOut("POST", "/v1/messages", src.token, wire.MessageCreateRequest{
		Envelope: envelope, RequestSignature: usig, ReceivedAt: 1790000000000,
	}, &created); status != http.StatusCreated {
		t.Fatalf("upload: status %d", status)
	}
	msgCT := randBytes(t, 64)
	var msgApproval wire.ApprovalCreateResponse
	if status := env.doOut("POST", "/v1/approvals", cli.token, wire.ApprovalCreateRequest{
		MessageID: created.MessageID, CLIEphemeralPublicKey: randBytes(t, 32),
		RequestCiphertext: msgCT, RequestSignature: signBytes(t, cli.signPriv, msgCT),
		ExpiresAt: futureExpires(),
	}, &msgApproval); status != http.StatusCreated {
		t.Fatalf("message approval: status %d", status)
	}

	// The decider's queue is exactly the message row; the item row is
	// invisible to it (server-filtered, design §14.8).
	var queue wire.ApprovalListResponse
	if status := env.doOut("GET", "/v1/approvals", dec.token, nil, &queue); status != 200 || len(queue.Approvals) != 1 {
		t.Fatalf("decider queue: status %d len %d", status, len(queue.Approvals))
	}
	if queue.Approvals[0].MessageID != created.MessageID {
		t.Fatalf("decider queue row: %+v", queue.Approvals[0])
	}

	// The decider cannot decide the item approval — the human-only
	// boundary is server-enforced (§14.8).
	if status, _ := env.do("POST", "/v1/approvals/"+itemApproval.ApprovalID+"/decision", dec.token,
		wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied}); status != http.StatusForbidden {
		t.Fatalf("decider item decision: status %d, want 403", status)
	}
	// ...but may approve the message one.
	if status, _ := env.do("POST", "/v1/approvals/"+msgApproval.ApprovalID+"/decision", dec.token,
		wire.ApprovalDecisionRequest{
			Decision:          wire.ApprovalStatusApproved,
			OneTimeEnc:        randBytes(t, 32),
			OneTimeWrappedKey: randBytes(t, 60),
		}); status != http.StatusNoContent {
		t.Fatalf("decider message decision: status %d", status)
	}
	// The CLI's poll names the decider (protocol §6.22) — design §14.5
	// requires it in the consumption audit plaintext.
	if status, raw := env.do("GET", "/v1/approvals/"+msgApproval.ApprovalID, cli.token, nil); status != 200 {
		t.Fatalf("cli poll after decider decision: status %d %s", status, raw)
	} else {
		var poll wire.ApprovalPollResponse
		if err := json.Unmarshal(raw, &poll); err != nil {
			t.Fatal(err)
		}
		if poll.Status != wire.ApprovalStatusApproved || poll.DecisionDeviceID != dec.deviceID {
			t.Fatalf("poll after decider decision: %+v, want decider %q", poll, dec.deviceID)
		}
	}
	// And the message is consumed: the owner's read shows consumed.
	var list wire.MessageListResponse
	if status := env.doOut("GET", "/v1/messages", owner.token, nil, &list); status != 200 || len(list.Messages) != 1 || list.Messages[0].Status != wire.MessageStatusConsumed {
		t.Fatalf("consumed message: status %d %+v", status, list.Messages)
	}

	// Backfill wraps (§6.30): a second decider gets a record; the
	// duplicate target is a conflict. The envelope must stay parseable
	// with the body preserved.
	dec2 := env.registerPairKind(t, wire.DeviceKindDecider)
	owner.completePairKind(t, dec2, nil)
	dec2.session(t)
	wraps := wire.MessageWrapsRequest{Wraps: []wire.MessageWrap{{
		DeviceID: dec2.deviceID, HPKEEnc: randBytes(t, 32), WrappedKey: randBytes(t, wire.SizeMessageWrappedKey),
	}}}
	if status, _ := env.do("PUT", "/v1/messages/"+created.MessageID+"/wraps", owner.token, wraps); status != http.StatusNoContent {
		t.Fatalf("backfill: status %d", status)
	}
	if status, _ := env.do("PUT", "/v1/messages/"+created.MessageID+"/wraps", owner.token, wraps); status != http.StatusConflict {
		t.Fatalf("duplicate backfill: status %d, want 409", status)
	}
}

// TestMessageTTLSweep pins the lazy-expiry contract: expired rows vanish
// from reads and from the storage accounting (design §14.3).
func TestMessageTTLSweep(t *testing.T) {
	env := newTestEnv(t, false)
	owner := env.createVault(t)

	src := env.registerPairKind(t, wire.DeviceKindSource)
	owner.completePairKind(t, src, nil)
	src.session(t)

	envelope := buildEnvelope(t, owner.deviceID, randBytes(t, 32), randBytes(t, wire.SizeMessageWrappedKey))
	tb, err := wire.BuildMessageUploadTranscript(wire.MessageUploadTranscript{
		VaultID: owner.vaultID, SourceDeviceID: src.deviceID,
		ReceivedAt: 1790000000000, Envelope: envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignEd25519(tb, src.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	var created wire.MessageCreateResponse
	if status := env.doOut("POST", "/v1/messages", src.token, wire.MessageCreateRequest{
		Envelope: envelope, RequestSignature: sig, ReceivedAt: 1790000000000,
	}, &created); status != http.StatusCreated {
		t.Fatalf("upload: status %d", status)
	}
	if err := env.st.DeleteExpiredMessages(t.Context(), owner.vaultID, created.ExpiresAt); err != nil {
		t.Fatal(err)
	}
	var list wire.MessageListResponse
	if status := env.doOut("GET", "/v1/messages", owner.token, nil, &list); status != 200 || len(list.Messages) != 0 {
		t.Fatalf("after sweep: status %d len %d", status, len(list.Messages))
	}
}

// signBytes signs arbitrary bytes with the CLI's Ed25519 key (the
// request_ciphertext signature, protocol D7).
func signBytes(t *testing.T, priv ed25519.PrivateKey, data []byte) []byte {
	t.Helper()
	sig, err := wire.SignEd25519(data, priv)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
