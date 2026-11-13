package pair

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
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
	confirm := bytesRepeat(0x33, 32)
	got := Payload("https://sync.example", hpke, sign, "aabb", "build agent", confirm)
	if !strings.HasPrefix(got, "keyref://pair?") {
		t.Fatalf("payload prefix: %q", got)
	}
	// Every parameter present; base64 percent-encoded per §9.1 (no raw
	// + / = in the query), hex nonce unescaped.
	for _, part := range []string{
		"v=1",
		"k=" + url.QueryEscape(base64.StdEncoding.EncodeToString(hpke)),
		"s=" + url.QueryEscape(base64.StdEncoding.EncodeToString(sign)),
		"c=" + url.QueryEscape(base64.StdEncoding.EncodeToString(confirm)),
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
		q.Get("u") != "https://sync.example" || q.Get("t") != "" {
		t.Fatalf("decoded query wrong: %v", q)
	}
	kb, err := base64.StdEncoding.DecodeString(q.Get("k"))
	if err != nil || !bytes.Equal(kb, hpke) {
		t.Fatalf("k roundtrip failed: %x", kb)
	}
	// The pairing secret travels in the QR (§3.13) — and nowhere else.
	cb, err := base64.StdEncoding.DecodeString(q.Get("c"))
	if err != nil || !bytes.Equal(cb, confirm) {
		t.Fatalf("c roundtrip failed: %x", cb)
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
// owner signatures over the §3.4 pair transcript and §3.3 directory, plus
// the §3.13 pairing confirmation MAC computed from the QR secret `c` as
// the owner-side phone does (v2 D).
func buildCompletion(t *testing.T, owner *testowner.Owner, id *device.Identity,
	nonceHex, deviceID string, grants []wire.GrantData, confirmSecret []byte) map[string]any {
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
	mac, err := wire.BuildPairConfirmMAC(confirmSecret, wire.DeviceKindCLI, tb)
	if err != nil {
		t.Fatal(err)
	}
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
		"pairing_mac":           b64(mac),
		"directory_revision":    1,
		"directory_signed":      b64(dirSigned),
		"directory_signature":   b64(dirSig),
		"grants":                grantMaps,
	}
}

func runPairAsync(t *testing.T, st *store.Store, id *device.Identity, url string) (*pairCapture, chan error) {
	return runPairAsyncTimeout(t, st, id, url, 8*time.Second)
}

// b64 encodes one blob the way the wire JSON does (standard base64, no
// quotes), so a raw []byte can ride a map[string]any completion body.
func b64(b []byte) string {
	out, _ := wire.Blob(b).MarshalJSON()
	return string(out[1 : len(out)-1]) // strip quotes
}

// pairCapture reads the pairing payload line the CLI prints with
// --print-payload, so the test can pull the QR secret `c` off it exactly
// like the owner phone does (§3.13).
type pairCapture struct {
	buf *bytes.Buffer
}

func (p *pairCapture) payload(t *testing.T) url.Values {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(p.buf.String(), "\n") {
			if !strings.HasPrefix(line, "payload: ") {
				continue
			}
			u, err := url.Parse(strings.TrimPrefix(line, "payload: "))
			if err != nil {
				t.Fatal(err)
			}
			return u.Query()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("pair never printed its payload")
	return nil
}

func runPairAsyncTimeout(t *testing.T, st *store.Store, id *device.Identity, url string, timeout time.Duration) (*pairCapture, chan error) {
	t.Helper()
	buf := &bytes.Buffer{}
	done := make(chan error, 1)
	go func() {
		done <- Run(st, client.New(url, nil), id, Options{
			Name:         "build-agent-1",
			PrintPayload: true,
			PollInterval: 10 * time.Millisecond,
			PollTimeout:  timeout,
			Stdout:       buf,
		})
	}()
	return &pairCapture{buf: buf}, done
}

// confirmSecretOf reads the QR pairing secret `c` out of a payload's
// query (§3.13): base64, 32 bytes.
func confirmSecretOf(t *testing.T, q url.Values) []byte {
	t.Helper()
	c, err := base64.StdEncoding.DecodeString(q.Get("c"))
	if err != nil || len(c) != wire.SizePairConfirmKey {
		t.Fatalf("payload c: %x (%v)", c, err)
	}
	return c
}

func TestPairCompletePinsOwnerKeyAndStoresGrants(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newTestIdentity(t)
	st := newTestStore(t)
	ps := newPairingServer(t)

	view := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindView, 1, 0, bytesRepeat(0x4d, 32))
	use := owner.WrapGrant(id.HPKEPublic, tvDevice, tvItem, wire.GrantKindUse, 1, 0, bytesRepeat(0x51, 32))

	cap, done := runPairAsync(t, st, id, ps.URL)
	nonce := ps.waitForRegistration(t)
	confirm := confirmSecretOf(t, cap.payload(t))
	ps.completeWith(buildCompletion(t, owner, id, nonce, tvDevice,
		[]wire.GrantData{view, use}, confirm))

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

// TestPairCompleteRejectsForgedMAC pins v2 D at the CLI: a completion
// whose pairing confirmation MAC does not verify under the QR secret is
// refused — the server knows the registered keys and the nonce hash, so
// without the MAC it can fabricate a self-consistent completion and get
// its own key pinned as the owner key. Nothing may be written before the
// MAC check.
func TestPairCompleteRejectsForgedMAC(t *testing.T) {
	owner := testowner.New(t, tvVault, tvOwner)
	id := newTestIdentity(t)
	// A MAC minted under a different secret: well-formed, but it cannot
	// verify under the QR secret the CLI generated.
	wrongMAC, err := wire.BuildPairConfirmMAC(bytesRepeat(0xAA, 32), wire.DeviceKindCLI,
		mustPairBytes(t, owner, id, "00112233445566778899aabbccddeeff"))
	if err != nil {
		t.Fatal(err)
	}

	mutate := map[string]func(map[string]any){
		"missing MAC":  func(c map[string]any) { delete(c, "pairing_mac") },
		"short MAC":    func(c map[string]any) { c["pairing_mac"] = "AAAA" },
		"wrong secret": func(c map[string]any) { c["pairing_mac"] = b64(wrongMAC) },
	}
	for name, m := range mutate {
		t.Run(name, func(t *testing.T) {
			st2 := newTestStore(t)
			ps2 := newPairingServer(t)
			cap2, done2 := runPairAsync(t, st2, id, ps2.URL)
			nonce2 := ps2.waitForRegistration(t)
			confirm2 := confirmSecretOf(t, cap2.payload(t))
			completion := buildCompletion(t, owner, id, nonce2, tvDevice, nil, confirm2)
			m(completion)
			ps2.completeWith(completion)
			if err := <-done2; err == nil {
				t.Fatal("forged pairing MAC accepted")
			}
			if _, ok, _ := st2.GetKV(KVOwnerSignPub); ok {
				t.Fatal("owner key pinned despite failed MAC")
			}
			if _, ok, _ := st2.GetKV("vault_id"); ok {
				t.Fatal("vault id stored despite failed MAC")
			}
		})
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

	cap, done := runPairAsync(t, st, id, ps.URL)
	nonce := ps.waitForRegistration(t)
	confirm := confirmSecretOf(t, cap.payload(t))

	completion := buildCompletion(t, owner, id, nonce, tvDevice, nil, confirm)
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

	cap, done := runPairAsyncTimeout(t, st, id, srv.URL, 300*time.Millisecond)
	_ = cap
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
	// The QR secret never rides the register body (§3.13).
	if s, _ := regBody["c"].(string); s != "" {
		t.Fatalf("register leaked the pairing secret: %q", s)
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

// mustPairBytes rebuilds the §3.4 pair transcript bytes for a no-grant
// pairing, for MACs the test mints itself.
func mustPairBytes(t *testing.T, owner *testowner.Owner, id *device.Identity, nonceHex string) []byte {
	t.Helper()
	tb, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID: owner.VaultID, OwnerSignPublicKey: owner.SignPub,
		Nonce: nonceHex, DeviceID: tvDevice,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: id.HPKEPublic,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: id.SignPublic,
		Label: "build-agent-1",
	})
	if err != nil {
		t.Fatal(err)
	}
	return tb
}
