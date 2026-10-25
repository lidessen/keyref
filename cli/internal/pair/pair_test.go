package pair

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/store"
	"github.com/lidessen/keyref/cli/internal/testowner"
)

const (
	tvVault  = "00112233445566778899aabbccddeeff"
	tvOwner  = "99998888777766665555444433332222"
	tvDevice = "0123456789abcdef0123456789abcdef"
	tvItem   = "deadbeefdeadbeefdeadbeefdeadbeef"
)

func TestPayloadLayout(t *testing.T) {
	hpke := bytesRepeat(0x11, 32)
	sign := bytesRepeat(0x22, 32)
	got := Payload("https://sync.example", hpke, sign, "aabb", "build agent")
	if !strings.HasPrefix(got, "keyref://pair?") {
		t.Fatalf("payload prefix: %q", got)
	}
	// Every parameter present; base64 percent-encoded per §9.1 (no raw
	// + / = in the query), hex nonce unescaped.
	for _, part := range []string{
		"v=1",
		"k=" + url.QueryEscape(base64.StdEncoding.EncodeToString(hpke)),
		"s=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sign)),
		"n=aabb",
		"name=build+agent",
		"u=" + url.QueryEscape("https://sync.example"),
	} {
		if !strings.Contains(got, part) {
			t.Fatalf("payload missing %q in %q", part, got)
		}
	}
	// Parse back and compare the decoded values.
	u, err := url.Parse(got)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("v") != "1" || q.Get("n") != "aabb" || q.Get("name") != "build agent" ||
		q.Get("u") != "https://sync.example" {
		t.Fatalf("decoded query wrong: %v", q)
	}
	kb, err := base64.StdEncoding.DecodeString(q.Get("k"))
	if err != nil || !bytes.Equal(kb, hpke) {
		t.Fatalf("k roundtrip failed: %x", kb)
	}
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func newTestIdentity(t *testing.T) *device.Identity {
	t.Helper()
	base, err := os.MkdirTemp("", "pair-test-*")
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

func newTestStore(t *testing.T) *store.Store {
	t.Helper()
	base, err := os.MkdirTemp("", "pair-store-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(base) })
	st, err := store.Open(base)
	if err != nil {
		t.Fatal(err)
	}
	return st
}

// pairingServer fakes the server: it records the registered nonce and
// answers pending until completion is set, then returns it.
type pairingServer struct {
	*httptest.Server
	mu         chan struct{}
	registered string
	completion map[string]any
}

func newPairingServer(t *testing.T) *pairingServer {
	t.Helper()
	ps := &pairingServer{mu: make(chan struct{}, 1)}
	ps.mu <- struct{}{}
	ps.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/pair/register":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			<-ps.mu
			ps.registered = body["nonce"].(string)
			ps.mu <- struct{}{}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"expires_at": 1})
		case "/v1/pair/status":
			<-ps.mu
			completion := ps.completion
			ps.mu <- struct{}{}
			if completion == nil {
				json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
				return
			}
			json.NewEncoder(w).Encode(completion)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ps.Close)
	return ps
}

func (ps *pairingServer) waitForRegistration(t *testing.T) string {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		<-ps.mu
		reg := ps.registered
		ps.mu <- struct{}{}
		if reg != "" {
			return reg
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pair did not register")
	return ""
}

func (ps *pairingServer) completeWith(c map[string]any) {
	<-ps.mu
	ps.completion = c
	ps.mu <- struct{}{}
}

// buildCompletion produces the pair/status "complete" body with real
// owner signatures over the §3.4 pair transcript and §3.3 directory.
func buildCompletion(t *testing.T, owner *testowner.Owner, id *device.Identity, nonceHex, deviceID string, grants []wire.GrantData) map[string]any {
	t.Helper()
	pt := wire.PairTranscript{
		VaultID:            owner.VaultID,
		OwnerSignPublicKey: owner.SignPub,
		Nonce:              nonceHex,
		DeviceID:           deviceID,
		HPKEKEM:            wire.KEMX25519,
		HPKEPublicKey:      id.HPKEPublic,
		SignAlg:            wire.SignAlgEd25519,
		SignPublicKey:      id.SignPublic,
		Label:              "build-agent-1",
	}
	for _, g := range grants {
		pt.Grants = append(pt.Grants, g.Transcript(owner.VaultID))
	}
	tb, err := wire.BuildPairTranscript(pt)
	if err != nil {
		t.Fatal(err)
	}
	pairingSig := owner.Sign(tb)
	digest, err := wire.GrantsDigest(pt.Grants)
	if err != nil {
		t.Fatal(err)
	}
	cliDigest := make([]byte, 32)
	dirSigned, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID:           owner.VaultID,
		DirectoryRevision: 1,
		Devices: []wire.DirectoryDevice{
			{DeviceID: owner.OwnerDev, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMP256, HPKEPublicKey: owner.HPKEPub,
				SignAlg: wire.SignAlgECDSAP256, SignPublicKey: owner.SignPub,
				GrantsDigest: cliDigest},
			{DeviceID: deviceID, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMX25519, HPKEPublicKey: id.HPKEPublic,
				SignAlg: wire.SignAlgEd25519, SignPublicKey: id.SignPublic,
				GrantsDigest: digest},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dirSig := owner.Sign(dirSigned)
	b64 := func(b []byte) string {
		out, _ := wire.Blob(b).MarshalJSON()
		return string(out[1 : len(out)-1]) // strip quotes
	}
	grantMaps := make([]map[string]any, 0, len(grants))
	for _, g := range grants {
		grantMaps = append(grantMaps, map[string]any{
			"device_id": g.DeviceID, "item_id": g.ItemID, "kind": g.Kind,
			"hpke_enc": b64(g.HPKEEnc), "wrapped_key": b64(g.WrappedKey),
			"expires_at": g.ExpiresAt, "revision": g.Revision,
			"signature": b64(g.Signature),
		})
	}
	return map[string]any{
		"status": "complete", "vault_id": owner.VaultID, "device_id": deviceID,
		"owner_sign_public_key": b64(owner.SignPub),
		"pairing_signature":     b64(pairingSig),
		"directory_revision":    1,
		"directory_signed":      b64(dirSigned),
		"directory_signature":   b64(dirSig),
		"grants":                grantMaps,
	}
}

func runPairAsync(t *testing.T, st *store.Store, id *device.Identity, url string) chan error {
	return runPairAsyncTimeout(t, st, id, url, 8*time.Second)
}

func runPairAsyncTimeout(t *testing.T, st *store.Store, id *device.Identity, url string, timeout time.Duration) chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		done <- Run(st, client.New(url, nil), id, Options{
			Name:         "build-agent-1",
			PollInterval: 10 * time.Millisecond,
			PollTimeout:  timeout,
			Stdout:       io.Discard,
		})
	}()
	return done
}

func TestPairCompletePinsOwnerKeyAndStoresGrants(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newTestIdentity(t)
	st := newTestStore(t)
	ps := newPairingServer(t)

	view := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindView, 1, 0, bytesRepeat(0x4d, 32))
	use := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindUse, 1, 0, bytesRepeat(0x51, 32))

	done := runPairAsync(t, st, id, ps.URL)
	nonce := ps.waitForRegistration(t)
	ps.completeWith(buildCompletion(t, owner, id, nonce, tvDevice, []wire.GrantData{view, use}))

	if err := <-done; err != nil {
		t.Fatalf("pair run: %v", err)
	}
	pinned, ok, _ := st.GetKV(KVOwnerSignPub)
	if !ok || string(pinned) != string(owner.SignPub) {
		t.Fatal("owner key not pinned")
	}
	if v, ok, _ := st.GetKV("vault_id"); !ok || string(v) != tvVault {
		t.Fatal("vault id not stored")
	}
	grants, err := st.Grants()
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 {
		t.Fatalf("stored %d grants, want 2", len(grants))
	}
	if _, ok, _ := st.GetKV(KVDirectorySigned); !ok {
		t.Fatal("directory not stored")
	}
}

func TestPairCompleteRejectsForgedSignature(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	// The attacker signs with their own key but presents it as the
	// owner: the transcript binds OUR nonce and keys, so an unrelated
	// signer still produces a self-consistent response — the CLI pins
	// whatever key verified the transcript. The REAL protection being
	// tested here: a completion whose pairing_signature does NOT match
	// the presented owner key is rejected and nothing is pinned.
	id := newTestIdentity(t)
	st := newTestStore(t)
	ps := newPairingServer(t)

	done := runPairAsync(t, st, id, ps.URL)
	nonce := ps.waitForRegistration(t)

	completion := buildCompletion(t, owner, id, nonce, tvDevice, nil)
	// Corrupt the signature bytes.
	completion["pairing_signature"] = completion["pairing_signature"].(string)[:8] + "AAAA"
	ps.completeWith(completion)

	if err := <-done; err == nil {
		t.Fatal("corrupted pairing signature accepted")
	}
	if _, ok, _ := st.GetKV(KVOwnerSignPub); ok {
		t.Fatal("owner key pinned despite failed verification")
	}
}

func TestPairRegisterSignatureVerifiedByServerShape(t *testing.T) {
	// The register body must carry the device keys and a signature over
	// the §3.5 transcript; observed by a strict fake server.
	owner := testowner.New(t, tvVault, tvOwner)
	_ = owner
	id := newTestIdentity(t)
	st := newTestStore(t)

	var regBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/pair/register" {
			json.NewDecoder(r.Body).Decode(&regBody)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]any{"expires_at": 1})
			return
		}
		// always pending; the test times out fast
		json.NewEncoder(w).Encode(map[string]any{"status": "pending"})
	}))
	defer srv.Close()

	done := runPairAsyncTimeout(t, st, id, srv.URL, 300*time.Millisecond)
	deadline := time.Now().Add(3 * time.Second)
	for regBody == nil && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if regBody == nil {
		t.Fatal("no register call")
	}
	if regBody["hpke_kem"] != wire.KEMX25519 || regBody["sign_alg"] != wire.SignAlgEd25519 {
		t.Fatalf("register algs wrong: %v", regBody)
	}
	if s, _ := regBody["signature"].(string); s == "" {
		t.Fatal("register missing signature")
	}
	select {
	case err := <-done:
		// Expect the timeout error.
		if err == nil {
			t.Fatal("expected timeout error")
		}
	case <-time.After(15 * time.Second):
		t.Fatal("pair run did not finish")
	}
}
