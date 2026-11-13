package session

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/cache"
	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/keyring"
)

const tvDevice = "0123456789abcdef0123456789abcdef"

func newIdentity(t *testing.T) *device.Identity {
	t.Helper()
	base, err := os.MkdirTemp("", "sess-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	ks, err := keyring.NewDirStore(filepath.Join(base, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	id, err := device.LoadOrCreate(ks)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func newStore(t *testing.T) *cache.Store {
	t.Helper()
	base, err := os.MkdirTemp("", "sess-store-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	st, err := cache.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

// challengeServer verifies the session transcript signature like the
// real server should (§6.7): the signature must verify under the
// device's Ed25519 key.
func challengeServer(t *testing.T, id *device.Identity) (*httptest.Server, *int32) {
	t.Helper()
	var challenges int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			DeviceID  string    `json:"device_id"`
			Challenge wire.Blob `json:"challenge"`
			Signature wire.Blob `json:"signature"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.Signature == nil {
			atomic.AddInt32(&challenges, 1)
			ch := wire.Blob(bytes32())
			json.NewEncoder(w).Encode(map[string]any{"challenge": ch, "expires_at": 1})
			return
		}
		tb, err := wire.BuildSessionTranscript(body.DeviceID, body.Challenge)
		if err != nil {
			t.Errorf("transcript: %v", err)
			w.WriteHeader(400)
			return
		}
		if err := wire.VerifyCLISignature(tb, body.Signature, id.SignPublic); err != nil {
			t.Error("session signature did not verify")
			w.WriteHeader(403)
			json.NewEncoder(w).Encode(map[string]string{"error": "unauthorized"})
			return
		}
		json.NewEncoder(w).Encode(map[string]any{
			"token": "6162", "expires_at": 999999999999999, "origin": "o", "plan": "unlimited",
		})
	}))
	t.Cleanup(srv.Close)
	return srv, &challenges
}

func bytes32() []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = byte(i)
	}
	return b
}

func TestSessionTwoStepAndCaching(t *testing.T) {
	id := newIdentity(t)
	st := newStore(t)
	_ = st.SetKV(KVDeviceID, []byte(tvDevice))
	srv, challenges := challengeServer(t, id)

	cl := client.New(srv.URL, nil)
	mgr := New(st, cl, id)
	cl.SetTokenSource(mgr.TokenSource())

	tok, err := mgr.Token()
	if err != nil {
		t.Fatal(err)
	}
	if tok != "6162" {
		t.Fatalf("token %q", tok)
	}
	if n := atomic.LoadInt32(challenges); n != 1 {
		t.Fatalf("challenges %d, want 1", n)
	}
	// Cached: no second challenge.
	tok2, err := mgr.Token()
	if err != nil || tok2 != tok {
		t.Fatalf("cached token %q err %v", tok2, err)
	}
	if n := atomic.LoadInt32(challenges); n != 1 {
		t.Fatalf("challenges %d after cache hit", n)
	}
}

func TestSessionNotPaired(t *testing.T) {
	id := newIdentity(t)
	st := newStore(t)
	cl := client.New("http://127.0.0.1:1", nil)
	mgr := New(st, cl, id)
	if _, err := mgr.Token(); err != ErrNotPaired {
		t.Fatalf("got %v, want ErrNotPaired", err)
	}
}

var _ = base64.StdEncoding
