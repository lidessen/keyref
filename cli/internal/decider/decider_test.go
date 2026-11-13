package decider

// The §14.8 gates, exercised against a fake keyref API: every path that
// must NOT auto-approve is asserted explicitly, because "approved when it
// should not have been" is the only failure mode that matters here.

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"io"
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
	testVault   = "0f1e2d3c4b5a69788796a5b4c3d2e1f0"
	testCLI     = "aaaabbbbccccddddeeeeffff00001111"
	testSource  = "bbbbccccddddeeeeffff000011112222"
	testMsg     = "12121212121212121212121212121212"
	testAppr    = "34343434343434343434343434343434"
	testDecider = "56565656565656565656565656565656"
)

const smsJSON = `{"v":1,"sender":"10086","body":"【XX银行】您的验证码 482913，5 分钟内有效。","sim":"备用卡1","received_at":1790000000000}`

// fakeAPI stands in for the keyref server: delegation, approvals, messages
// and the decision endpoint.
type fakeAPI struct {
	mu         sync.Mutex
	delegation wire.DelegationPutRequest
	messages   []wire.MessageRow
	approvals  []wire.ApprovalRow
	decisions  []wire.ApprovalDecisionRequest
	srv        *httptest.Server
}

func newFakeAPI(t *testing.T) *fakeAPI {
	t.Helper()
	f := &fakeAPI{}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/delegation", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		resp := wire.DelegationGetResponse{
			DelegationRevision: f.delegation.DelegationRevision,
			DelegationSigned:   f.delegation.DelegationSigned,
			Signature:          f.delegation.Signature,
		}
		_ = json.NewEncoder(w).Encode(resp)
	})
	mux.HandleFunc("/v1/approvals", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(wire.ApprovalListResponse{Approvals: f.approvals})
	})
	mux.HandleFunc("/v1/approvals/", func(w http.ResponseWriter, r *http.Request) {
		var req wire.ApprovalDecisionRequest
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.decisions = append(f.decisions, req)
		f.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/v1/messages", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(wire.MessageListResponse{Messages: f.messages})
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

// fixture wires one decider + one pending message approval.
type fixture struct {
	api           *fakeAPI
	owner         *ecdsa.PrivateKey
	decider       *device.Identity
	cliSignPub    ed25519.PublicKey
	sourceSignPub ed25519.PublicKey
	now           time.Time
	// devices overrides the signed directory the decider reads; nil
	// means the default owner-signed listing (active CLI + active
	// source).
	devices func() ([]audit.DeviceRecord, error)
}

func newFixture(t *testing.T, policy wire.DelegationPolicy) *fixture {
	return newFixtureWithAge(t, policy, 30)
}

func newFixtureWithAge(t *testing.T, policy wire.DelegationPolicy, ageSeconds int64) *fixture {
	t.Helper()
	ownerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hpkePub, hpkePriv, err := crypto.GenerateHPKEKeyPair(wire.KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deciderID := &device.Identity{HPKEPublic: hpkePub, HPKEPrivate: hpkePriv,
		SignPublic: signPub, SignPrivate: signPriv}

	now := time.UnixMilli(1_790_000_100_000)
	createdAt := now.UnixMilli() - ageSeconds*1000
	api := newFakeAPI(t)

	// A signed delegation carrying the policy.
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := wire.BuildDelegationTranscript(wire.DelegationTranscript{
		VaultID: testVault, DelegationRevision: 1, PolicyJSON: string(policyJSON)})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(tb, ownerKey)
	if err != nil {
		t.Fatal(err)
	}
	api.delegation = wire.DelegationPutRequest{
		DelegationRevision: 1, DelegationSigned: tb, Signature: sig}

	// One message sealed to the decider, signed by the source device the
	// directory lists (protocol v2 C): the decider refuses a row whose
	// upload signature does not verify — without this it cannot tell a
	// real SMS from a row the server made up.
	sourcePub, sourcePriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	messageKey := make([]byte, 32)
	if _, err := rand.Read(messageKey); err != nil {
		t.Fatal(err)
	}
	rec, err := crypto.SealMessageRecord(testVault, testDecider, hpkePub, messageKey)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := crypto.MessageBodyAAD(testVault, testSource)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.SealBlob(messageKey, aad, []byte(smsJSON))
	if err != nil {
		t.Fatal(err)
	}
	envelope := append([]byte{1}, rec...)
	envelope = append(envelope, blob...)
	_, body, err := crypto.SplitMessageEnvelope(envelope)
	if err != nil {
		t.Fatal(err)
	}
	msgTB, err := wire.BuildMessageUploadTranscript(wire.MessageUploadTranscript{
		VaultID: testVault, SourceDeviceID: testSource,
		ReceivedAt: uint64(createdAt), Body: body,
	})
	if err != nil {
		t.Fatal(err)
	}
	msgSig, err := wire.SignEd25519(msgTB, sourcePriv)
	if err != nil {
		t.Fatal(err)
	}
	api.messages = []wire.MessageRow{{
		MessageID: testMsg, SourceDeviceID: testSource, Status: wire.MessageStatusActive,
		Envelope: envelope, RequestSignature: msgSig, ReceivedAt: createdAt,
		CreatedAt: createdAt,
		ExpiresAt: now.UnixMilli() + 24*3600*1000,
	}}
	ephemeral := make([]byte, 32)
	if _, err := rand.Read(ephemeral); err != nil {
		t.Fatal(err)
	}
	// The request is signed by the CLI device the directory lists
	// (protocol v2 A): the decider refuses anything it cannot attribute.
	cliPub, cliPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	approvalExpires := now.UnixMilli() + 120_000
	reqTB, err := wire.BuildApprovalRequestTranscript(wire.ApprovalRequestTranscript{
		VaultID: testVault, CLIDeviceID: testCLI,
		SubjectKind: wire.EntityMessage, SubjectID: testMsg,
		ExpiresAt:             uint64(approvalExpires),
		CLIEphemeralPublicKey: ephemeral,
		RequestCiphertext:     []byte("ciphertext-for-digest"),
	})
	if err != nil {
		t.Fatal(err)
	}
	reqSig, err := wire.SignEd25519(reqTB, cliPriv)
	if err != nil {
		t.Fatal(err)
	}
	api.approvals = []wire.ApprovalRow{{
		ApprovalID: testAppr, CLIDeviceID: testCLI, MessageID: testMsg,
		CLIEphemeralPublicKey: ephemeral,
		RequestCiphertext:     []byte("ciphertext-for-digest"),
		RequestSignature:      reqSig,
		CreatedAt:             now.UnixMilli(), ExpiresAt: approvalExpires,
	}}

	return &fixture{api: api, owner: ownerKey, decider: deciderID, now: now,
		cliSignPub: cliPub, sourceSignPub: sourcePub}
}

func (f *fixture) run(t *testing.T, policy wire.DelegationPolicy, reviewer Reviewer) (int, error) {
	t.Helper()
	devices := f.devices
	if devices == nil {
		devices = func() ([]audit.DeviceRecord, error) {
			return []audit.DeviceRecord{
				{DeviceID: testCLI, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
					SignAlg: wire.SignAlgEd25519, SignPublicKey: f.cliSignPub},
				{DeviceID: testSource, Kind: wire.DeviceKindSource, Status: wire.DeviceStatusActive,
					SignAlg: wire.SignAlgEd25519, SignPublicKey: f.sourceSignPub},
			}, nil
		}
	}
	d, err := New(Config{
		VaultID:            testVault,
		DeviceID:           testDecider,
		Identity:           f.decider,
		Client:             client.New(f.api.srv.URL, nil),
		OwnerSignPublicKey: elliptic.Marshal(elliptic.P256(), f.owner.PublicKey.X, f.owner.PublicKey.Y),
		Reviewer:           reviewer,
		Now:                func() time.Time { return f.now },
		Devices:            devices,
	})
	if err != nil {
		t.Fatal(err)
	}
	return d.RunOnce(context.Background())
}

var allowAll = wire.DelegationPolicy{
	V: 1, Senders: []string{"10086"}, MaxAgeMin: 5,
	PerCLIHourly: 10, PerCLIDaily: 50,
}

func TestAutoApprovesInsidePolicy(t *testing.T) {
	f := newFixture(t, allowAll)
	var reviewed ReviewInput
	n, err := f.run(t, allowAll, ReviewerFunc(func(_ context.Context, in ReviewInput) (Verdict, error) {
		reviewed = in
		return Pass, nil
	}))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 1 || len(f.api.decisions) != 1 {
		t.Fatalf("approved %d, decisions %d", n, len(f.api.decisions))
	}
	// The decision is signed by the decider device over exactly the wrap
	// it delivered (protocol §3.12, v2 B).
	dec := f.api.decisions[0]
	dtb, err := wire.BuildApprovalDecisionTranscript(wire.ApprovalDecisionTranscript{
		VaultID: testVault, ApprovalID: testAppr, DecisionDeviceID: testDecider,
		Decision:          wire.ApprovalStatusApproved,
		RequestCiphertext: f.api.approvals[0].RequestCiphertext,
		OneTimeEnc:        dec.OneTimeEnc, OneTimeWrappedKey: dec.OneTimeWrappedKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := wire.VerifyDeviceSignature(dtb, dec.DecisionSignature, wire.SignAlgEd25519, f.decider.SignPublic); err != nil {
		t.Fatalf("decision signature: %v", err)
	}
	// The reviewer saw the body isolated from the metadata.
	if !strings.Contains(reviewed.Body, "482913") || reviewed.Sender != "10086" ||
		reviewed.CLI != testCLI || reviewed.AgeSeconds != 30 {
		t.Fatalf("review input: %+v", reviewed)
	}
	// The decision answers exactly this message and request.
	d := f.api.decisions[0]
	if d.Decision != wire.ApprovalStatusApproved || len(d.OneTimeEnc) == 0 ||
		len(d.OneTimeWrappedKey) == 0 {
		t.Fatalf("decision: %+v", d)
	}
}

func TestGatesRefuse(t *testing.T) {
	cases := []struct {
		name     string
		policy   wire.DelegationPolicy
		reviewer Reviewer
	}{
		{"sender not listed", wire.DelegationPolicy{V: 1, Senders: []string{"95533"}}, passReview},
		{"empty policy is revocation", wire.DelegationPolicy{V: 1}, passReview},
		{"CLI not allowed", wire.DelegationPolicy{V: 1, Senders: []string{"10086"},
			CLIDevices: []string{testSource}}, passReview},
		{"reviewer vetoes", allowAll, ReviewerFunc(func(context.Context, ReviewInput) (Verdict, error) {
			return Veto, nil
		})},
		{"reviewer errors", allowAll, ReviewerFunc(func(context.Context, ReviewInput) (Verdict, error) {
			return Pass, io.ErrUnexpectedEOF
		})},
		{"no reviewer configured", allowAll, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newFixture(t, c.policy)
			n, err := f.run(t, c.policy, c.reviewer)
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if n != 0 || len(f.api.decisions) != 0 {
				t.Fatalf("approved %d, decisions %d — must not auto-approve", n, len(f.api.decisions))
			}
		})
	}
}

// A message older than the delegation's max_age_min is left for a human.
func TestStaleMessageIsNotAutoApproved(t *testing.T) {
	f := newFixtureWithAge(t, allowAll, 600) // 10 minutes old, policy allows 5
	n, err := f.run(t, allowAll, passReview)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 0 || len(f.api.decisions) != 0 {
		t.Fatal("a stale message must not be auto-approved")
	}
}

// A tampered delegation (signature from another key) is never acted on.
func TestForgedDelegationIsIgnored(t *testing.T) {
	f := newFixture(t, allowAll)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f.owner = other // the decider now pins a different owner key
	// A forged policy is a hard error, not "no policy": the decider must
	// surface it (the loop logs and retries) rather than act on anything.
	n, err := f.run(t, allowAll, passReview)
	if err == nil {
		t.Fatal("a delegation signed by another key must be rejected")
	}
	if n != 0 || len(f.api.decisions) != 0 {
		t.Fatal("nothing may be approved from an unverified delegation")
	}
}

var passReview = ReviewerFunc(func(context.Context, ReviewInput) (Verdict, error) { return Pass, nil })

// TestLimiter covers the per-CLI caps.
func TestLimiter(t *testing.T) {
	now := time.Unix(1_790_000_000, 0)
	l := NewLimiter(func() time.Time { return now })
	p := wire.DelegationPolicy{V: 1, Senders: []string{"10086"}, PerCLIHourly: 2, PerCLIDaily: 3}
	if !l.Allow("c", p) {
		t.Fatal("first must pass")
	}
	l.Record("c")
	l.Record("c")
	if l.Allow("c", p) {
		t.Fatal("hourly cap must refuse the third")
	}
	now = now.Add(2 * time.Hour)
	if !l.Allow("c", p) {
		t.Fatal("after an hour the hourly window frees up")
	}
	l.Record("c")
	if l.Allow("c", p) {
		t.Fatal("daily cap (3) must refuse the fourth")
	}
}

// TestRefusesRequestItCannotAttribute pins v2 A at the decider: when the
// server alters any signed field of the request, the decider must not seal
// the SMS plaintext to the key in the row.
func TestRefusesRequestItCannotAttribute(t *testing.T) {
	cases := map[string]func(*fakeAPI){
		"swapped ephemeral key": func(a *fakeAPI) {
			a.approvals[0].CLIEphemeralPublicKey = make([]byte, wire.SizeX25519Key)
		},
		"tampered ciphertext": func(a *fakeAPI) {
			a.approvals[0].RequestCiphertext = []byte("another-ciphertext")
		},
		"extended expiry": func(a *fakeAPI) {
			a.approvals[0].ExpiresAt += 1
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, allowAll)
			mutate(f.api)
			n, err := f.run(t, allowAll, ReviewerFunc(func(context.Context, ReviewInput) (Verdict, error) {
				return Pass, nil
			}))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if n != 0 || len(f.api.decisions) != 0 {
				t.Fatalf("approved %d, decisions %d, want none", n, len(f.api.decisions))
			}
		})
	}
}

// TestRefusesUnknownCLI: a request from a device the directory does not
// list as an active CLI gets no decision either.
func TestRefusesUnknownCLI(t *testing.T) {
	f := newFixture(t, allowAll)
	f.api.approvals[0].CLIDeviceID = testSource
	n, err := f.run(t, allowAll, ReviewerFunc(func(context.Context, ReviewInput) (Verdict, error) {
		return Pass, nil
	}))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 0 || len(f.api.decisions) != 0 {
		t.Fatalf("approved %d, decisions %d, want none", n, len(f.api.decisions))
	}
}

// TestRefusesMessageItCannotAttribute pins v2 C at the decider: a
// message row whose upload signature does not verify under the signed
// directory is never opened, never reviewed, never delivered — the
// decider would otherwise hand the CLI a body the server made up.
func TestRefusesMessageItCannotAttribute(t *testing.T) {
	cases := map[string]func(*fakeAPI){
		"tampered body": func(a *fakeAPI) {
			// Flip one body byte: same structure, different signed bytes.
			a.messages[0].Envelope = append([]byte{}, a.messages[0].Envelope...)
			a.messages[0].Envelope[len(a.messages[0].Envelope)-1] ^= 0x01
		},
		"swapped source": func(a *fakeAPI) {
			a.messages[0].SourceDeviceID = testCLI
		},
		"tampered received_at": func(a *fakeAPI) {
			a.messages[0].ReceivedAt++
		},
		"stripped signature": func(a *fakeAPI) {
			a.messages[0].RequestSignature = nil
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, allowAll)
			mutate(f.api)
			n, err := f.run(t, allowAll, ReviewerFunc(func(context.Context, ReviewInput) (Verdict, error) {
				return Pass, nil
			}))
			if err != nil {
				t.Fatalf("run: %v", err)
			}
			if n != 0 || len(f.api.decisions) != 0 {
				t.Fatalf("approved %d, decisions %d, want none", n, len(f.api.decisions))
			}
		})
	}
}

// TestRefusesRevokedSource: a message from a source device the owner
// revoked in the directory is not delivered either (v2 C) — the row's
// signature still verifies, but a revoked device may no longer speak.
func TestRefusesRevokedSource(t *testing.T) {
	f := newFixture(t, allowAll)
	f.devices = func() ([]audit.DeviceRecord, error) {
		return []audit.DeviceRecord{
			{DeviceID: testCLI, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
				SignAlg: wire.SignAlgEd25519, SignPublicKey: f.cliSignPub},
			{DeviceID: testSource, Kind: wire.DeviceKindSource, Status: wire.DeviceStatusRevoked,
				SignAlg: wire.SignAlgEd25519, SignPublicKey: f.sourceSignPub},
		}, nil
	}
	n, err := f.run(t, allowAll, ReviewerFunc(func(context.Context, ReviewInput) (Verdict, error) {
		return Pass, nil
	}))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if n != 0 || len(f.api.decisions) != 0 {
		t.Fatalf("approved %d, decisions %d, want none", n, len(f.api.decisions))
	}
}
