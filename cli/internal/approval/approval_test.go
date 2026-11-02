package approval

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/audit"
	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/device"
)

const (
	testVaultID  = "11112222333344445555666677778888"
	testDeviceID = "aaaabbbbccccddddeeeeffff00001111"
	testItemID   = "deadbeefdeadbeefdeadbeefdeadbeef"
	testOwnerID  = "99998888777766665555444433332211"
)

// fakeOwner is the software owner side: it receives the HPKE-wrapped
// request, verifies the CLI signature, decrypts the transcript and
// answers with a correctly bound one-time wrap (what the e2e owner and
// eventually iOS do).
type fakeOwner struct {
	t               *testing.T
	keys            *crypto.DeviceKeys // the CLI device under test
	srv             *httptest.Server
	mu              sync.Mutex
	decision        string  // pending | approved | denied
	lastReq         request // decrypted §6.19 plaintext
	lastCT          []byte  // request ciphertext as submitted
	lastSig         []byte  // request signature as submitted
	expires         int64   // expires_at from the create call
	polls           int     // GET /v1/approvals/:id count
	rateFirst       bool    // 429 on the first poll
	failNext        bool    // transient network error on next poll
	wrapWithWrongID bool    // bind the one-time wrap to another approval id
	// decisionDeviceID is what the fake server reports as the deciding
	// device (protocol §6.22); "" = an older server that omits the key.
	decisionDeviceID string
	itemKey          []byte
	// deliverSecret switches the fake owner to the LOCAL-item payload
	// (design §6.6, v0.7): the decision wraps secretPayload — the secret
	// value itself — instead of the 32-byte item key.
	deliverSecret bool
	secretPayload []byte
	approvalID    string
}

func newFakeOwner(t *testing.T, decision string) *fakeOwner {
	t.Helper()
	keys, err := crypto.GenerateDeviceKeys()
	if err != nil {
		t.Fatal(err)
	}
	o := &fakeOwner{t: t, decision: decision, itemKey: randMaterial(t), keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/approvals", o.handleCreate)
	mux.HandleFunc("GET /v1/approvals/", o.handlePoll)
	o.srv = httptest.NewServer(mux)
	t.Cleanup(o.srv.Close)
	return o
}

func (o *fakeOwner) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req wire.ApprovalCreateRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		o.t.Fatalf("owner decode create: %v", err)
	}
	// The owner verifies the CLI signature over the ciphertext BEFORE
	// decrypting (design §8.3 step 3).
	if err := wire.VerifyCLISignature(req.RequestCiphertext, req.RequestSignature, o.keys.SignPublic); err != nil {
		o.t.Fatalf("owner: CLI signature verification failed: %v", err)
	}
	// The server-side ciphertext layout is enc ‖ ct ‖ tag: split at the
	// 32-byte X25519 encapsulation and decrypt with the owner key.
	enc, ct := req.RequestCiphertext[:32], req.RequestCiphertext[32:]
	info, err := crypto.Info(crypto.PurposeApprovalRequest, testVaultID, testOwnerID)
	if err != nil {
		o.t.Fatal(err)
	}
	pt, err := crypto.UnwrapKey(wire.KEMX25519, o.keys.HPKEPrivate, info, enc, ct)
	if err != nil {
		o.t.Fatalf("owner: request unwrap failed: %v", err)
	}
	defer crypto.WipeKey(pt)
	var rq request
	dec2 := json.NewDecoder(bytes.NewReader(pt))
	dec2.DisallowUnknownFields()
	if err := dec2.Decode(&rq); err != nil {
		o.t.Fatalf("owner: request plaintext decode: %v", err)
	}
	o.mu.Lock()
	o.lastReq, o.lastCT, o.lastSig, o.expires = rq, req.RequestCiphertext, req.RequestSignature, req.ExpiresAt
	o.approvalID = randHex(o.t)
	o.mu.Unlock()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(wire.ApprovalCreateResponse{ApprovalID: o.approvalID, ExpiresAt: req.ExpiresAt})
}

func (o *fakeOwner) handlePoll(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.polls++
	if o.rateFirst && o.polls == 1 {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"rate_limited"}`))
		return
	}
	if o.failNext {
		o.failNext = false
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte(`{"error":"internal"}`))
		return
	}
	if o.decision == "pending" {
		json.NewEncoder(w).Encode(wire.ApprovalPollResponse{ApprovalID: o.approvalID, Status: wire.ApprovalStatusPending})
		return
	}
	if o.decision == "denied" {
		json.NewEncoder(w).Encode(wire.ApprovalPollResponse{ApprovalID: o.approvalID, Status: wire.ApprovalStatusDenied,
			DecisionDeviceID: o.decisionDeviceID})
		return
	}
	// Approved: wrap the payload to the request's ephemeral public key
	// with the D4 one-time info binding — the 32-byte item key for
	// synced items, the secret value itself for local items (§6.6).
	// wrapWithWrongID breaks the binding on purpose (negative test).
	bindID := o.approvalID
	if o.wrapWithWrongID {
		bindID = randHex(o.t)
	}
	info, err := crypto.OneTimeItemKeyInfo(testVaultID, testDeviceID, testItemID, bindID, o.lastCT)
	if err != nil {
		o.t.Fatal(err)
	}
	payload := o.itemKey
	if o.deliverSecret {
		payload = o.secretPayload
	}
	enc, wrapped, err := crypto.WrapKey(wire.KEMX25519, o.lastReq.EphemeralPublicKey, info, payload)
	if err != nil {
		o.t.Fatal(err)
	}
	json.NewEncoder(w).Encode(wire.ApprovalPollResponse{
		ApprovalID: o.approvalID, Status: wire.ApprovalStatusApproved,
		OneTimeEnc: enc, OneTimeWrappedKey: wrapped, ExpiresAt: time.Now().Add(60 * time.Second).UnixMilli(),
		DecisionDeviceID: o.decisionDeviceID,
	})
}

func (o *fakeOwner) identity() *device.Identity {
	return &device.Identity{
		HPKEPublic:  o.keys.HPKEPublic,
		HPKEPrivate: o.keys.HPKEPrivate,
		SignPublic:  o.keys.SignPublic,
		SignPrivate: o.keys.SignPrivate,
	}
}

func (o *fakeOwner) options(cl *client.Client) *Options {
	return &Options{
		VaultID:   testVaultID,
		DeviceID:  testDeviceID,
		Identity:  o.identity(),
		Owners:    []audit.OwnerRecipient{{DeviceID: testOwnerID, HPKEKEM: wire.KEMX25519, HPKEPublicKey: o.keys.HPKEPublic}},
		ItemID:    testItemID,
		Ref:       "openai-prod",
		Argv:      []string{"curl", "https://api.example/v1"},
		Refs:      []string{"openai-prod"},
		Injection: []string{"env"},
		Hosts:     []string{"api.example"},
		Reply:     []string{"Password:=openai-prod"},
		Timeout:   5 * time.Second,
		Client:    cl,
		Stderr:    &bytes.Buffer{},
	}
}

func TestRequestItemKeyHappyPath(t *testing.T) {
	oldInterval := PollInterval
	PollInterval = 5 * time.Millisecond
	t.Cleanup(func() { PollInterval = oldInterval })

	o := newFakeOwner(t, "approved")
	itemKey := append([]byte(nil), o.itemKey...)
	o.rateFirst = true // the first poll is throttled; the flow retries
	o.failNext = true  // and a transient failure retries too

	cl := client.New(o.srv.URL, nil)
	key, code, state := RequestItemKey(o.options(cl), nil)
	if key == nil {
		t.Fatalf("RequestItemKey failed: code %d state %s", code, state)
	}
	defer key.Destroy()
	if code != 0 || state != "" {
		t.Fatalf("code/state = %d/%s", code, state)
	}
	if !key.EqualTo(itemKey) {
		t.Fatal("unwrapped key does not match the item key the owner wrapped")
	}

	// Request transcript assertions (§6.19): signed argv with the
	// placeholder, refs, injection, hosts, the reply pattern, the
	// ephemeral key material, and the expires_at window.
	rq := o.lastReq
	if rq.V != 1 || rq.CLIDeviceID != testDeviceID || rq.ItemID != testItemID {
		t.Fatalf("request identity fields: %+v", rq)
	}
	if len(rq.Argv) != 2 || rq.Argv[0] != "curl" || rq.Argv[1] != "https://api.example/v1" {
		t.Fatalf("request argv: %v", rq.Argv)
	}
	if len(rq.Refs) != 1 || rq.Refs[0] != "openai-prod" {
		t.Fatalf("request refs: %v", rq.Refs)
	}
	if rq.Injection != "env" || len(rq.Hosts) != 1 || rq.Hosts[0] != "api.example" {
		t.Fatalf("request injection/hosts: %q %v", rq.Injection, rq.Hosts)
	}
	if len(rq.Reply) != 1 || rq.Reply[0] != "Password:=openai-prod" {
		t.Fatalf("request reply patterns missing: %v", rq.Reply)
	}
	if rq.EphemeralKEM != wire.KEMX25519 || len(rq.EphemeralPublicKey) != 32 {
		t.Fatalf("request ephemeral key: %s %d bytes", rq.EphemeralKEM, len(rq.EphemeralPublicKey))
	}
	if time.Now().UnixMilli()-rq.CreatedAt > 10_000 || rq.CreatedAt-time.Now().UnixMilli() > 10_000 {
		t.Fatalf("request created_at far from now: %d", rq.CreatedAt)
	}
	if o.expires < time.Now().UnixMilli() || o.expires > time.Now().UnixMilli()+MaxTimeoutMs {
		t.Fatalf("expires_at outside the 120 s window: %d", o.expires)
	}
	if o.polls != 3 {
		t.Fatalf("polls = %d, want 3 (429 retry + 500 retry + approved)", o.polls)
	}
}

func TestRequestItemKeyDenied(t *testing.T) {
	oldInterval := PollInterval
	PollInterval = time.Millisecond
	t.Cleanup(func() { PollInterval = oldInterval })

	o := newFakeOwner(t, "denied")
	key, code, state := RequestItemKey(o.options(client.New(o.srv.URL, nil)), nil)
	if key != nil || code != 13 || state != "approval-denied" {
		t.Fatalf("denied flow: key=%v code=%d state=%s", key != nil, code, state)
	}
}

func TestRequestItemKeyTimeout(t *testing.T) {
	oldInterval := PollInterval
	PollInterval = time.Millisecond
	t.Cleanup(func() { PollInterval = oldInterval })

	o := newFakeOwner(t, "pending")
	opts := o.options(client.New(o.srv.URL, nil))
	opts.Timeout = 300 * time.Millisecond
	start := time.Now()
	key, code, state := RequestItemKey(opts, nil)
	if key != nil || code != 13 || state != "approval-timeout" {
		t.Fatalf("timeout flow: key=%v code=%d state=%s", key != nil, code, state)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("timeout took %s, want fast failure", elapsed)
	}
}

func TestRequestItemKeyNoOwner(t *testing.T) {
	o := newFakeOwner(t, "approved")
	opts := o.options(client.New(o.srv.URL, nil))
	opts.Owners = nil
	key, code, state := RequestItemKey(opts, nil)
	if key != nil || code != 1 || state != "internal" {
		t.Fatalf("no-owner flow: key=%v code=%d state=%s", key != nil, code, state)
	}
}

func TestRequestItemKeySubmitRejected(t *testing.T) {
	o := newFakeOwner(t, "approved")
	// Simulate a full approval queue: the server refuses with 429
	// quota_exceeded and the flow maps that to exit 13.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":"quota_exceeded"}`))
	}))
	defer srv.Close()
	opts := o.options(client.New(srv.URL, nil))
	key, code, state := RequestItemKey(opts, nil)
	if key != nil || code != 13 || state != "approval-queue-full" {
		t.Fatalf("queue-full flow: key=%v code=%d state=%s", key != nil, code, state)
	}
}

// TestRequestItemKeyWrapBinding pins the D4 binding: a wrap built with
// a DIFFERENT request digest (e.g. answering another request) must not
// open.
func TestRequestItemKeyWrapBinding(t *testing.T) {
	oldInterval := PollInterval
	PollInterval = time.Millisecond
	t.Cleanup(func() { PollInterval = oldInterval })

	o := newFakeOwner(t, "approved")
	// Corrupt the binding: the owner wraps with a DIFFERENT approval id
	// than the one it issued (e.g. answering another request).
	o.mu.Lock()
	o.wrapWithWrongID = true
	o.mu.Unlock()
	key, code, state := RequestItemKey(o.options(client.New(o.srv.URL, nil)), nil)
	if key != nil || code != 13 || state != "approval-unwrap" {
		t.Fatalf("misbound wrap opened: key=%v code=%d state=%s", key != nil, code, state)
	}
}

// TestRequestItemKeyZeroizeOnDeny checks the ephemeral wipe path does
// not panic and the deny message carries no secret material.
func TestRequestItemKeyZeroizeOnDeny(t *testing.T) {
	oldInterval := PollInterval
	PollInterval = time.Millisecond
	t.Cleanup(func() { PollInterval = oldInterval })

	o := newFakeOwner(t, "denied")
	errBuf := &bytes.Buffer{}
	opts := o.options(client.New(o.srv.URL, nil))
	opts.Stderr = errBuf
	key, _, _ := RequestItemKey(opts, nil)
	if key != nil {
		t.Fatal("denied flow returned a key")
	}
	if out := errBuf.String(); strings.Contains(out, itemKeyString(o.itemKey)) {
		t.Fatalf("stderr echoed key material: %s", out)
	}
}

// TestRequestSecretLocalItem drives the local-item branch of design
// §6.6 (v0.7): the owner's decision wraps the secret VALUE itself, and
// RequestSecret delivers it in guarded memory — destroy wipes it.
func TestRequestSecretLocalItem(t *testing.T) {
	oldInterval := PollInterval
	PollInterval = 5 * time.Millisecond
	t.Cleanup(func() { PollInterval = oldInterval })

	o := newFakeOwner(t, "approved")
	payload := bytes.Repeat([]byte{0x7c}, 4096) // a "TOTP seed"-sized secret
	o.mu.Lock()
	o.deliverSecret = true
	o.secretPayload = payload
	o.mu.Unlock()

	value, code, state := RequestSecret(o.options(client.New(o.srv.URL, nil)), nil)
	if value == nil {
		t.Fatalf("RequestSecret failed: code %d state %s", code, state)
	}
	if !value.EqualTo(payload) {
		t.Fatal("unwrapped secret does not match the payload the owner sealed")
	}
	value.Destroy()
	if len(value.Bytes()) != 0 {
		t.Fatal("secret plaintext not wiped by Destroy")
	}

	// The request transcript is identical to the synced-item flow — the
	// server and the transcript never learn which payload kind follows.
	if o.lastReq.ItemID != testItemID || o.lastReq.CLIDeviceID != testDeviceID {
		t.Fatalf("local-item request identity: %+v", o.lastReq)
	}
}

// TestRequestSecretBinding pins the D4 binding on the local-item path:
// a wrap bound to another approval id must not open into a value.
func TestRequestSecretBinding(t *testing.T) {
	oldInterval := PollInterval
	PollInterval = time.Millisecond
	t.Cleanup(func() { PollInterval = oldInterval })

	o := newFakeOwner(t, "approved")
	o.mu.Lock()
	o.deliverSecret = true
	o.secretPayload = []byte("sk-local-secret")
	o.wrapWithWrongID = true
	o.mu.Unlock()

	value, code, state := RequestSecret(o.options(client.New(o.srv.URL, nil)), nil)
	if value != nil || code != 13 || state != "approval-unwrap" {
		t.Fatalf("misbound secret opened: value=%v code=%d state=%s", value != nil, code, state)
	}
}

// TestRequestSecretDenied mirrors the deny path for local items.
func TestRequestSecretDenied(t *testing.T) {
	oldInterval := PollInterval
	PollInterval = time.Millisecond
	t.Cleanup(func() { PollInterval = oldInterval })

	o := newFakeOwner(t, "denied")
	o.mu.Lock()
	o.deliverSecret = true
	o.secretPayload = []byte("sk-local-secret")
	o.mu.Unlock()

	value, code, state := RequestSecret(o.options(client.New(o.srv.URL, nil)), nil)
	if value != nil || code != 13 || state != "approval-denied" {
		t.Fatalf("denied local flow: value=%v code=%d state=%s", value != nil, code, state)
	}
}

// TestRequestDecisionDeviceID pins protocol §6.22: the optional
// decision_device_id of the poll answer reaches the caller, so the exec
// audit event can name who approved (design v0.8 §14.5/§14.8). A server
// that omits the key (v1.1 shape) leaves it empty.
func TestRequestDecisionDeviceID(t *testing.T) {
	oldInterval := PollInterval
	PollInterval = 5 * time.Millisecond
	t.Cleanup(func() { PollInterval = oldInterval })

	o := newFakeOwner(t, "approved")
	o.mu.Lock()
	o.decisionDeviceID = testOwnerID
	o.mu.Unlock()

	var decider string
	key, code, state := RequestItemKey(o.options(client.New(o.srv.URL, nil)), &decider)
	if key == nil {
		t.Fatalf("RequestItemKey failed: code %d state %s", code, state)
	}
	key.Destroy()
	if decider != testOwnerID {
		t.Fatalf("decision device = %q, want %q", decider, testOwnerID)
	}

	// No decision_device_id in the response → the caller sees "".
	plain := newFakeOwner(t, "approved")
	var noDecider string
	key, code, state = RequestItemKey(plain.options(client.New(plain.srv.URL, nil)), &noDecider)
	if key == nil {
		t.Fatalf("RequestItemKey failed: code %d state %s", code, state)
	}
	key.Destroy()
	if noDecider != "" {
		t.Fatalf("decision device = %q, want empty for a response without the key", noDecider)
	}
}

// ---- small helpers ----

func randHex(t *testing.T) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", b)
}

func randMaterial(t *testing.T) []byte {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

func itemKeyString(b []byte) string { return fmt.Sprintf("%x", b) }
