package apns

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// testKey generates one P-256 key for the signing tests.
func testKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// p8PEM encodes a private key as the PKCS#8 .p8 file the developer
// console exports.
func p8PEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func sec1PEM(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

func TestParseP8KeyPKCS8(t *testing.T) {
	key := testKey(t)
	got, err := ParseP8Key(p8PEM(t, key))
	if err != nil {
		t.Fatalf("parse PKCS#8: %v", err)
	}
	if got.PublicKey.X.Cmp(key.PublicKey.X) != 0 || got.PublicKey.Y.Cmp(key.PublicKey.Y) != 0 {
		t.Fatal("parsed key does not match the input key")
	}
}

func TestParseP8KeySEC1(t *testing.T) {
	key := testKey(t)
	got, err := ParseP8Key(sec1PEM(t, key))
	if err != nil {
		t.Fatalf("parse SEC1: %v", err)
	}
	if got.PublicKey.X.Cmp(key.PublicKey.X) != 0 {
		t.Fatal("parsed key does not match the input key")
	}
}

func TestParseP8KeyRejects(t *testing.T) {
	// Not a PEM file at all.
	if _, err := ParseP8Key([]byte("not a pem file")); err == nil {
		t.Fatal("non-PEM input accepted")
	}
	// Non-ECDSA PKCS#8 key (Ed25519).
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(ed)
	if err != nil {
		t.Fatal(err)
	}
	edPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if _, err := ParseP8Key(edPEM); err == nil {
		t.Fatal("Ed25519 PKCS#8 key accepted")
	}
	// Wrong curve (P-384).
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384DER, err := x509.MarshalPKCS8PrivateKey(p384)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseP8Key(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: p384DER})); err == nil {
		t.Fatal("P-384 key accepted")
	}
	// Unknown PEM type.
	if _, err := ParseP8Key(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}})); err == nil {
		t.Fatal("certificate block accepted")
	}
}

// newTestProvider wires a provider to an httptest server recording every
// request, with a controllable clock.
type recordedRequest struct {
	Path   string
	Header http.Header
	Body   []byte
}

type testAPNs struct {
	srv *httptest.Server
	mu  sync.Mutex
	req []recordedRequest

	status int
	reason string
}

func newTestAPNs(t *testing.T, key *ecdsa.PrivateKey, status int, reason string) (*TokenProvider, *testAPNs, *fakeClock) {
	t.Helper()
	a := &testAPNs{status: status, reason: reason}
	a.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		a.mu.Lock()
		a.req = append(a.req, recordedRequest{Path: r.URL.Path, Header: r.Header.Clone(), Body: body})
		a.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		io.WriteString(w, `{"reason":"`+reason+`"}`)
	}))
	t.Cleanup(a.srv.Close)
	clock := &fakeClock{t: time.Now()}
	p, err := NewTokenProvider(Config{
		Key: key, KeyID: "KEYID12345", TeamID: "TEAMID1234", Topic: "app.keyref.ios",
		BaseURL: a.srv.URL, Now: clock.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	return p, a, clock
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (a *testAPNs) requests() []recordedRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]recordedRequest(nil), a.req...)
}

func TestPushRequestShape(t *testing.T) {
	p, a, clock := newTestAPNs(t, testKey(t), http.StatusOK, "")
	payload := []byte(`{"aps":{"alert":{"title":"keyref 审批"}},"approval_id":"abc"}`)
	if err := p.Push("DEVICETOKEN001", payload); err != nil {
		t.Fatalf("push: %v", err)
	}
	reqs := a.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Path != "/3/device/DEVICETOKEN001" {
		t.Fatalf("path = %q", r.Path)
	}
	auth := r.Header.Get("authorization")
	if len(auth) < 7 || auth[:7] != "bearer " {
		t.Fatalf("authorization = %q", auth)
	}
	if got := r.Header.Get("apns-topic"); got != "app.keyref.ios" {
		t.Fatalf("apns-topic = %q", got)
	}
	if got := r.Header.Get("apns-push-type"); got != "alert" {
		t.Fatalf("apns-push-type = %q", got)
	}
	if got := r.Header.Get("apns-priority"); got != "10" {
		t.Fatalf("apns-priority = %q", got)
	}
	// apns-expiration is now + 5 minutes (Unix seconds): a push that
	// cannot be delivered quickly must never outlive the approval.
	exp := clock.Now().Add(ExpirationTTL).Unix()
	if got := r.Header.Get("apns-expiration"); got != itoa(exp) {
		t.Fatalf("apns-expiration = %q, want %d", got, exp)
	}
	if string(r.Body) != string(payload) {
		t.Fatalf("payload = %s", r.Body)
	}

	// The bearer token is a verifiable ES256 JWT with the exact
	// header/claims shape.
	jwtPart := auth[len("bearer "):]
	if err := verifyProviderToken(jwtPart, &p.key.PublicKey); err != nil {
		t.Fatalf("provider token does not verify: %v", err)
	}
	header, claims, _, err := decodeJWTProviderToken(jwtPart)
	if err != nil {
		t.Fatal(err)
	}
	var h jwtHeader
	if err := json.Unmarshal(header, &h); err != nil {
		t.Fatal(err)
	}
	if h.Alg != "ES256" || h.Kid != "KEYID12345" {
		t.Fatalf("jwt header = %+v", h)
	}
	var c jwtClaims
	if err := json.Unmarshal(claims, &c); err != nil {
		t.Fatal(err)
	}
	if c.Iss != "TEAMID1234" || c.Iat != clock.Now().Unix() {
		t.Fatalf("jwt claims = %+v", c)
	}
}

func itoa(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}

func TestProviderTokenReusedAndRefreshed(t *testing.T) {
	p, a, clock := newTestAPNs(t, testKey(t), http.StatusOK, "")
	// Two pushes inside the reuse window share one provider token.
	if err := p.Push("t1", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	if err := p.Push("t2", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	reqs := a.requests()
	if len(reqs) != 2 {
		t.Fatalf("requests = %d", len(reqs))
	}
	if reqs[0].Header.Get("authorization") != reqs[1].Header.Get("authorization") {
		t.Fatal("provider token minted twice inside the reuse window")
	}
	// 51 minutes later the token is re-minted (APNs caps at one hour).
	clock.Advance(51 * time.Minute)
	if err := p.Push("t3", []byte("{}")); err != nil {
		t.Fatal(err)
	}
	reqs = a.requests()
	if reqs[2].Header.Get("authorization") == reqs[1].Header.Get("authorization") {
		t.Fatal("provider token not refreshed past the reuse window")
	}
}

func TestPushErrorMapping(t *testing.T) {
	t.Run("410 Unregistered matches ErrTokenInvalid", func(t *testing.T) {
		p, _, _ := newTestAPNs(t, testKey(t), http.StatusGone, "Unregistered")
		err := p.Push("tok", []byte("{}"))
		if err == nil {
			t.Fatal("410 accepted as success")
		}
		if !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("410 Unregistered does not match ErrTokenInvalid: %v", err)
		}
		var re *ResponseError
		if !errors.As(err, &re) || re.Status != 410 || re.Reason != "Unregistered" {
			t.Fatalf("response error = %v", err)
		}
	})
	t.Run("BadDeviceToken matches ErrTokenInvalid", func(t *testing.T) {
		p, _, _ := newTestAPNs(t, testKey(t), http.StatusBadRequest, "BadDeviceToken")
		if err := p.Push("tok", []byte("{}")); !errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("BadDeviceToken does not match ErrTokenInvalid: %v", err)
		}
	})
	t.Run("other failures do not match", func(t *testing.T) {
		p, _, _ := newTestAPNs(t, testKey(t), http.StatusForbidden, "InvalidProviderToken")
		err := p.Push("tok", []byte("{}"))
		if err == nil || errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("403 InvalidProviderToken mapped to ErrTokenInvalid: %v", err)
		}
		var re *ResponseError
		if !errors.As(err, &re) || re.Reason != "InvalidProviderToken" {
			t.Fatalf("reason not preserved: %v", err)
		}
	})
	t.Run("garbage error body keeps the status", func(t *testing.T) {
		p, _, _ := newTestAPNs(t, testKey(t), http.StatusInternalServerError, "")
		err := p.Push("tok", []byte("{}"))
		if err == nil || errors.Is(err, ErrTokenInvalid) {
			t.Fatalf("500 mapped unexpectedly: %v", err)
		}
	})
}

func TestNewTokenProviderDefaults(t *testing.T) {
	key := testKey(t)
	if _, err := NewTokenProvider(Config{}); err == nil {
		t.Fatal("empty config accepted")
	}
	p, err := NewTokenProvider(Config{Key: key, KeyID: "k", TeamID: "t", Topic: "b"})
	if err != nil {
		t.Fatal(err)
	}
	if p.base != ProductionURL {
		t.Fatalf("base = %q, want production host", p.base)
	}
	sp, err := NewTokenProvider(Config{Key: key, KeyID: "k", TeamID: "t", Topic: "b", Sandbox: true})
	if err != nil {
		t.Fatal(err)
	}
	if sp.base != SandboxURL {
		t.Fatalf("sandbox base = %q, want sandbox host", sp.base)
	}
	// Explicit BaseURL wins over the sandbox flag (test injection).
	bp, err := NewTokenProvider(Config{Key: key, KeyID: "k", TeamID: "t", Topic: "b", Sandbox: true, BaseURL: "http://x"})
	if err != nil {
		t.Fatal(err)
	}
	if bp.base != "http://x" {
		t.Fatalf("base override ignored: %q", bp.base)
	}
}

func TestLoadFromEnv(t *testing.T) {
	key := testKey(t)
	keyFile := t.TempDir() + "/AuthKey.p8"
	if err := writeFile(keyFile, p8PEM(t, key)); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{
		"KEYREF_APN_KEY_PATH": keyFile,
		"KEYREF_APN_KEY_ID":   "KEYID12345",
		"KEYREF_TEAM_ID":      "TEAMID1234",
		"KEYREF_APN_TOPIC":    "app.keyref.ios",
		"KEYREF_APN_ENV":      "sandbox",
	}
	lookup := func(name string) string { return env[name] }

	p, why := LoadFromEnv(lookup)
	if p == nil || why != "" {
		t.Fatalf("complete env: provider=%v why=%q", p, why)
	}
	tp := p.(*TokenProvider)
	if tp.base != SandboxURL {
		t.Fatalf("env sandbox not honored: %q", tp.base)
	}

	// Any missing variable disables push with a reason, never an error.
	for name := range env {
		saved := env[name]
		delete(env, name)
		p, why := LoadFromEnv(lookup)
		if p != nil || why == "" {
			t.Fatalf("missing %s: provider=%v why=%q", name, p, why)
		}
		env[name] = saved
	}
	// Bad env value.
	env["KEYREF_APN_ENV"] = "staging"
	if p, why := LoadFromEnv(lookup); p != nil || why == "" {
		t.Fatalf("bad KEYREF_APN_ENV accepted: %v %q", p, why)
	}
	env["KEYREF_APN_ENV"] = "production"
	if p, why := LoadFromEnv(lookup); p == nil || why != "" {
		t.Fatalf("production env: %v %q", p, why)
	}
	// Unreadable key file.
	env["KEYREF_APN_KEY_PATH"] = keyFile + ".missing"
	if p, why := LoadFromEnv(lookup); p != nil || why == "" {
		t.Fatalf("missing key file accepted: %v %q", p, why)
	}
	// Unparseable key file.
	bad := keyFile + ".bad"
	if err := writeFile(bad, []byte("garbage")); err != nil {
		t.Fatal(err)
	}
	env["KEYREF_APN_KEY_PATH"] = bad
	if p, why := LoadFromEnv(lookup); p != nil || why == "" {
		t.Fatalf("garbage key accepted: %v %q", p, why)
	}
}

func writeFile(path string, data []byte) error {
	return os.WriteFile(path, data, 0o600)
}
