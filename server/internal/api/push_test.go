package api

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/apns"
)

// fakePush records Push calls for the approval-trigger tests. notify
// (when set) receives every call so tests can await the fire-and-forget
// goroutines deterministically.
type fakePush struct {
	mu     sync.Mutex
	calls  []pushCall
	err    error
	notify chan pushCall
}

type pushCall struct {
	Token   string
	Payload []byte
}

func (f *fakePush) Push(token string, payload []byte) error {
	f.mu.Lock()
	f.calls = append(f.calls, pushCall{Token: token, Payload: append([]byte(nil), payload...)})
	call := f.calls[len(f.calls)-1]
	f.mu.Unlock()
	if f.notify != nil {
		f.notify <- call
	}
	return f.err
}

// callsAfter returns the tokens of every call after the given count.
func (f *fakePush) callsAfter(n int) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for i, c := range f.calls {
		if i >= n {
			out = append(out, c.Token)
		}
	}
	return out
}

func (f *fakePush) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakePush) wait(t *testing.T, n int) []pushCall {
	t.Helper()
	got := make([]pushCall, 0, n)
	for len(got) < n {
		select {
		case c := <-f.notify:
			got = append(got, c)
		case <-time.After(2 * time.Second):
			t.Fatalf("push calls = %d, want %d (within timeout)", len(got), n)
		}
	}
	return got
}

// pushFixture is the approval fixture plus a fake provider installed in
// api.Config.Push.
type pushFixture struct {
	*approvalFixture
	push *fakePush
}

func newPushFixture(t *testing.T) *pushFixture {
	f := newApprovalFixture(t)
	fp := &fakePush{notify: make(chan pushCall, 16)}
	f.e.api.cfg.Push = fp
	return &pushFixture{approvalFixture: f, push: fp}
}

func token64(t *testing.T) string {
	t.Helper()
	return strings.Repeat("ab", 32) // 64 even hex chars, the APNs shape
}

func TestPushTokenRegistration(t *testing.T) {
	f := newApprovalFixture(t)
	tok := token64(t)

	// Only a logged-in owner can register.
	if s, raw := f.e.do("PUT", "/v1/devices/push-token", "", wire.PushTokenRequest{Token: tok, Env: "sandbox"}); s != 401 {
		t.Fatalf("unauthenticated register: want 401, got %d %s", s, raw)
	}
	// A CLI device is forbidden (owner-only, §11 pattern).
	if s, raw := f.e.do("PUT", "/v1/devices/push-token", f.cli.token, wire.PushTokenRequest{Token: tok, Env: "sandbox"}); s != 403 || expectError(t, raw, "forbidden") != 0 {
		t.Fatalf("cli register: want 403 forbidden, got %d %s", s, raw)
	}
	if s, _ := f.e.do("PUT", "/v1/devices/push-token", f.owner.token, wire.PushTokenRequest{Token: tok, Env: "sandbox"}); s != 204 {
		t.Fatalf("owner register: %d", s)
	}

	// Stored on the AUTHENTICATED device row — registration is
	// self-service, the client cannot name another device.
	d, err := f.e.st.GetDevice(context.Background(), f.owner.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.PushToken.Valid || d.PushToken.String != tok {
		t.Fatalf("push_token = %v", d.PushToken)
	}

	// Re-registering overwrites.
	tok2 := strings.Repeat("cd", 32)
	if s, _ := f.e.do("PUT", "/v1/devices/push-token", f.owner.token, wire.PushTokenRequest{Token: tok2, Env: "production"}); s != 204 {
		t.Fatalf("re-register: %d", s)
	}
	d, err = f.e.st.GetDevice(context.Background(), f.owner.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	if !d.PushToken.Valid || d.PushToken.String != tok2 {
		t.Fatalf("push_token after overwrite = %v", d.PushToken)
	}
}

func TestPushTokenRegistrationValidation(t *testing.T) {
	f := newApprovalFixture(t)
	cases := []struct {
		name string
		req  wire.PushTokenRequest
	}{
		{"env sandbox ok", wire.PushTokenRequest{Token: token64(t), Env: "sandbox"}},
		{"env production ok", wire.PushTokenRequest{Token: token64(t), Env: "production"}},
	}
	for _, c := range cases {
		if s, _ := f.e.do("PUT", "/v1/devices/push-token", f.owner.token, c.req); s != 204 {
			t.Fatalf("%s: want 204, got %d", c.name, s)
		}
	}
	bad := []struct {
		name string
		req  wire.PushTokenRequest
	}{
		{"env missing", wire.PushTokenRequest{Token: token64(t)}},
		{"env invalid", wire.PushTokenRequest{Token: token64(t), Env: "staging"}},
		{"token not hex", wire.PushTokenRequest{Token: strings.Repeat("zz", 32), Env: "sandbox"}},
		{"token odd length", wire.PushTokenRequest{Token: "abc", Env: "sandbox"}},
		{"token too short", wire.PushTokenRequest{Token: "aabb", Env: "sandbox"}},
		{"token empty", wire.PushTokenRequest{Token: "", Env: "sandbox"}},
	}
	for _, c := range bad {
		if s, raw := f.e.do("PUT", "/v1/devices/push-token", f.owner.token, c.req); s != 400 || expectError(t, raw, "invalid_field") != 0 {
			t.Fatalf("%s: want 400 invalid_field, got %d %s", c.name, s, raw)
		}
	}
	// Unknown fields are rejected by the strict decoder (§12.3).
	if s, raw := f.e.do("PUT", "/v1/devices/push-token", f.owner.token, map[string]any{
		"token": token64(t), "env": "sandbox", "device_id": f.owner.deviceID,
	}); s != 400 {
		t.Fatalf("unknown field: want 400, got %d %s", s, raw)
	}
}

func TestApprovalCreateTriggersPush(t *testing.T) {
	f := newPushFixture(t)
	tok := token64(t)
	if s, _ := f.e.do("PUT", "/v1/devices/push-token", f.owner.token, wire.PushTokenRequest{Token: tok, Env: "sandbox"}); s != 204 {
		t.Fatalf("register: %d", s)
	}

	// A second active owner device with its own token: both receive the
	// push; the CLI has none and never gets one.
	owner2 := "22222222222222222222222222222222"
	if _, err := f.e.st.DB().Exec(`INSERT INTO devices (device_id, vault_id, kind, status, hpke_kem, hpke_public_key,
sign_alg, sign_public_key, label, created_at, revoked_at, push_token) VALUES (?,?,?,?,?,?,?,?,?,?,NULL,?)`,
		owner2, f.owner.vaultID, "ios", "active", "P-256", []byte{1}, "ed25519", []byte{2}, "iPhone 2", int64(1), strings.Repeat("ef", 32)); err != nil {
		t.Fatal(err)
	}

	status, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000)
	if status != 201 {
		t.Fatalf("approval create: %d %s", status, raw)
	}
	var created wire.ApprovalCreateResponse
	json.Unmarshal(raw, &created)

	calls := f.push.wait(t, 2)
	tokens := map[string][]byte{}
	for _, c := range calls {
		tokens[c.Token] = c.Payload
	}
	if len(tokens) != 2 {
		t.Fatalf("push audience = %v", tokens)
	}
	payload, ok := tokens[tok]
	if !ok {
		t.Fatalf("owner token %s not pushed: %v", tok, tokens)
	}
	var env struct {
		Aps struct {
			Alert struct {
				Title string `json:"title"`
				Body  string `json:"body"`
			} `json:"alert"`
			Sound string `json:"sound"`
		} `json:"aps"`
		ApprovalID string `json:"approval_id"`
	}
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatalf("payload %s: %v", payload, err)
	}
	if env.Aps.Alert.Title != "keyref 审批" || env.Aps.Alert.Body != "有一条待审批的命令" || env.Aps.Sound != "default" {
		t.Fatalf("alert payload: %+v", env)
	}
	if env.ApprovalID != created.ApprovalID {
		t.Fatalf("approval_id = %q, want %q", env.ApprovalID, created.ApprovalID)
	}
}

func TestApprovalPushBestEffort(t *testing.T) {
	t.Run("provider errors never fail the approval", func(t *testing.T) {
		f := newPushFixture(t)
		f.push.err = apns.ErrTokenInvalid // any error must be swallowed
		tok := token64(t)
		if s, _ := f.e.do("PUT", "/v1/devices/push-token", f.owner.token, wire.PushTokenRequest{Token: tok, Env: "sandbox"}); s != 204 {
			t.Fatalf("register: %d", s)
		}
		if s, raw := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 201 {
			t.Fatalf("approval create with failing provider: %d %s", s, raw)
		}
		f.push.wait(t, 1)
		// The rejected token is cleared so future approvals stop hitting
		// the dead device (APNs 410 → cleanup callback).
		f.e.waitFor(t, func() bool {
			d, err := f.e.st.GetDevice(context.Background(), f.owner.deviceID)
			return err == nil && !d.PushToken.Valid
		}, "push_token not cleared")
	})
	t.Run("no registered tokens means no push calls", func(t *testing.T) {
		f := newPushFixture(t)
		if s, _ := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 201 {
			t.Fatal("approval create")
		}
		// No push token registered: nothing is sent.
		time.Sleep(50 * time.Millisecond)
		if n := f.push.count(); n != 0 {
			t.Fatalf("push calls with no tokens = %d", n)
		}
	})
	t.Run("disabled provider skips push entirely", func(t *testing.T) {
		// cfg.Push is nil — the deployment without KEYREF_APN_* variables.
		f := newApprovalFixture(t)
		if f.e.api.cfg.Push != nil {
			t.Fatal("fixture unexpectedly has a provider")
		}
		if s, _ := f.submit(t, []byte("ct"), f.clock.t.UnixMilli()+60_000); s != 201 {
			t.Fatal("approval create without push must still be 201")
		}
		toks, err := f.e.st.ListPushTokens(context.Background(), f.owner.vaultID)
		if err != nil {
			t.Fatal(err)
		}
		if len(toks) != 0 {
			t.Fatalf("unexpected tokens %v", toks)
		}
	})
}

// waitFor polls cond until it holds or the deadline passes (the push
// dispatcher is asynchronous).
func (e *testEnv) waitFor(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal(msg)
}
