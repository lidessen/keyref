package api

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/wire"
	"github.com/lidessen/keyref/server/internal/pow"
	"github.com/lidessen/keyref/server/internal/quotas"
	"github.com/lidessen/keyref/server/internal/store"
)

// testEnv is one API server over a fresh SQLite file in a temp dir.
type testEnv struct {
	t       *testing.T
	ts      *httptest.Server
	api     *Server
	st      *store.Store
	quota   *quotas.Manager
	enforce bool
	clis    map[string]*testCLI // device_id -> registered CLI fixture
}

func newTestEnv(t *testing.T, enforce bool) *testEnv {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(context.Background(), filepath.Join(dir, store.DBFileName))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	qm := quotas.NewManager(st)
	if enforce {
		// Keep the plan tables but relax the request counters that would
		// throttle the test flow itself; specific subtests tighten them.
		qm.Free.RequestsPerMinute = 1 << 20
		qm.Free.RequestsPerDay = 1 << 24
	}
	apiSrv := New(st, qm, pow.NewIssuer(), Config{
		EnforceQuotas: enforce,
		Version:       "test",
		Commit:        "test",
		DataDir:       dir,
	})
	ts := httptest.NewServer(apiSrv.Handler())
	t.Cleanup(ts.Close)
	return &testEnv{t: t, ts: ts, api: apiSrv, st: st, quota: qm, enforce: enforce, clis: map[string]*testCLI{}}
}

// do performs one JSON request; body may be nil.
func (e *testEnv) do(method, path, token string, body any) (int, []byte) {
	e.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			e.t.Fatalf("marshal body: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, e.ts.URL+path, rd)
	if err != nil {
		e.t.Fatalf("new request: %v", err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

// doOut performs a request and decodes a 2xx response into out.
func (e *testEnv) doOut(method, path, token string, body, out any) int {
	e.t.Helper()
	status, raw := e.do(method, path, token, body)
	if status < 300 && out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			e.t.Fatalf("%s %s: decode response: %v (body %s)", method, path, err, raw)
		}
	}
	return status
}

// expectError asserts the fixed error code of an error response.
// setUsage forces a usage_daily counter row (quota subtests).
func (e *testEnv) setUsage(t *testing.T, vaultID, day string, n int64) {
	t.Helper()
	_, err := e.st.DB().Exec(`INSERT INTO usage_daily (vault_id, day, requests) VALUES (?,?,?)
ON CONFLICT (vault_id, day) DO UPDATE SET requests = excluded.requests`, vaultID, day, n)
	if err != nil {
		t.Fatal(err)
	}
}

func blobPtr(b []byte) *wire.Blob {
	w := wire.Blob(b)
	return &w
}

func expectError(t *testing.T, raw []byte, want string) int {
	t.Helper()
	var e struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal(raw, &e); err != nil {
		t.Fatalf("decode error body %s: %v", raw, err)
	}
	if e.Error != want {
		t.Fatalf("error code = %q, want %q (body %s)", e.Error, want, raw)
	}
	return 0
}

func randHexID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return b
}

// recoveryKeys derives the recovery authority exactly as protocol §3.8
// defines it (stdlib HKDF; no circl dependency needed in tests).
func recoveryKeys(t *testing.T, seed []byte) (ed25519.PrivateKey, []byte) {
	t.Helper()
	prk, err := hkdf.Extract(sha256.New, seed, nil)
	if err != nil {
		t.Fatal(err)
	}
	signSeed, err := hkdf.Expand(sha256.New, prk, "recovery-sign", 32)
	if err != nil {
		t.Fatal(err)
	}
	priv := ed25519.NewKeyFromSeed(signSeed)
	pub := priv.Public().(ed25519.PublicKey)
	return priv, pub
}

// ---------------------------------------------------------------------------
// owner fixture (software iPhone, protocol §11.2)

type testOwner struct {
	env      *testEnv
	signKey  *ecdsa.PrivateKey
	signPub  []byte // SEC1 uncompressed
	hpkePub  []byte // 65-byte P-256-shaped blob
	vaultID  string
	deviceID string
	token    string
	recSeed  []byte
	recPriv  ed25519.PrivateKey
	recPub   []byte
}

// createVault creates a vault and opens an owner session.
func (e *testEnv) createVault(t *testing.T) *testOwner {
	t.Helper()
	o, status, raw := e.createVaultStatus(t)
	if status != 201 {
		t.Fatalf("create vault: status %d body %s", status, raw)
	}
	o.session(t)
	return o
}

// createVaultStatus runs the whole creation flow but returns the final
// status instead of failing (for negative tests).
func (e *testEnv) createVaultStatus(t *testing.T) (*testOwner, int, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, err := wire.EncodeP256PublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	o := &testOwner{
		env: e, signKey: key, signPub: signPub,
		hpkePub:  append([]byte{0x04}, randBytes(t, 64)...),
		vaultID:  randHexID(t),
		deviceID: randHexID(t),
		recSeed:  randBytes(t, 32),
	}
	o.recPriv, o.recPub = recoveryKeys(t, o.recSeed)

	directory, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: o.vaultID, DirectoryRevision: 1,
		Devices: []wire.DirectoryDevice{{
			DeviceID: o.deviceID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
			HPKEKEM: wire.KEMP256, HPKEPublicKey: o.hpkePub,
			SignAlg: wire.SignAlgECDSAP256, SignPublicKey: o.signPub,
			GrantsDigest: wire.EmptyGrantsDigest(),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(directory, o.signKey)
	if err != nil {
		t.Fatal(err)
	}
	req := wire.CreateVaultRequest{
		VaultID: o.vaultID,
		Device: wire.DeviceInput{
			DeviceID: o.deviceID, Kind: wire.DeviceKindIOS,
			HPKEKEM: wire.KEMP256, HPKEPublicKey: o.hpkePub,
			SignAlg: wire.SignAlgECDSAP256, SignPublicKey: o.signPub,
			Label: "iPhone",
		},
		RecoveryWrap:      randBytes(t, 60),
		RecoveryKDFJSON:   `{"v":1,"kdf":"hkdf-sha256","salt":"","kek_info":"recovery-kek","sign_info":"recovery-sign"}`,
		RecoverySignPub:   o.recPub,
		DirectoryRevision: 1,
		DirectorySigned:   directory,
		Signature:         sig,
	}

	if e.enforce {
		// Proof of work round (protocol §10.1).
		var first struct {
			Error     string `json:"error"`
			Challenge string `json:"challenge"`
		}
		status, raw := e.do("POST", "/v1/vaults", "", req)
		if status != 401 {
			return o, status, raw
		}
		if err := json.Unmarshal(raw, &first); err != nil || first.Error != "pow_required" {
			t.Fatalf("expected pow_required, got %s", raw)
		}
		vaultRaw, _ := hex.DecodeString(o.vaultID)
		req.PoW = &wire.PoWSolution{
			Challenge: []byte(first.Challenge),
			Nonce:     pow.Solve(first.Challenge, vaultRaw),
		}
	}

	var out wire.CreateVaultResponse
	status, createRaw := e.do("POST", "/v1/vaults", "", req)
	json.Unmarshal(createRaw, &out)
	if status == 201 && out.VaultID != o.vaultID {
		t.Fatal("create vault response mismatch")
	}
	return o, status, createRaw
}

// session runs the two-step challenge flow and stores the token.
func (o *testOwner) session(t *testing.T) {
	t.Helper()
	var chal wire.SessionChallengeResponse
	if status := o.env.doOut("POST", "/v1/session", "", wire.SessionRequest{DeviceID: o.deviceID}, &chal); status != 200 {
		t.Fatalf("owner session step 1: status %d", status)
	}
	token := o.env.openSession(t, o.deviceID, chal.Challenge, func(tb []byte) ([]byte, error) {
		return wire.SignOwnerECDSA(tb, o.signKey)
	})
	o.token = token
}

// insertSessionRaw stores a session for a raw 32-byte token directly,
// bypassing the challenge flow — used to simulate a pre-existing session
// (e.g. one that survived a revocation).
func (e *testEnv) insertSessionRaw(t *testing.T, rawToken []byte, deviceID string) string {
	t.Helper()
	sum := sha256.Sum256(rawToken)
	err := e.st.InsertSession(context.Background(), &store.Session{
		TokenHash: hex.EncodeToString(sum[:]),
		DeviceID:  deviceID,
		ExpiresAt: time.Now().Add(time.Hour).UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(rawToken)
}

// openSession finishes the second session step with the given signer.
func (e *testEnv) openSession(t *testing.T, deviceID string, challenge []byte, sign func(tb []byte) ([]byte, error)) string {
	t.Helper()
	tb, err := wire.BuildSessionTranscript(deviceID, challenge)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(tb)
	if err != nil {
		t.Fatal(err)
	}
	var sess wire.SessionResponse
	if status := e.doOut("POST", "/v1/session", "", wire.SessionRequest{
		DeviceID: deviceID, Challenge: blobPtr(challenge), Signature: blobPtr(sig),
	}, &sess); status != 200 {
		t.Fatalf("session step 2 for %s: status %d", deviceID, status)
	}
	return sess.Token
}

// directoryFor assembles a fresh directory with the given statuses
// (owner device plus every registered CLI fixture).
func (o *testOwner) directoryFor(t *testing.T, revision uint64, statuses map[string]string) (wire.DirectoryTranscript, []byte) {
	t.Helper()
	records := []wire.DirectoryDevice{{
		DeviceID: o.deviceID, Kind: wire.DeviceKindIOS,
		Status:  statuses[o.deviceID],
		HPKEKEM: wire.KEMP256, HPKEPublicKey: o.hpkePub,
		SignAlg: wire.SignAlgECDSAP256, SignPublicKey: o.signPub,
		GrantsDigest: wire.EmptyGrantsDigest(),
	}}
	for devID, status := range statuses {
		if devID == o.deviceID {
			continue
		}
		cli := o.env.clis[devID]
		if cli == nil {
			t.Fatalf("no CLI fixture for %s", devID)
		}
		records = append(records, wire.DirectoryDevice{
			DeviceID: devID, Kind: wire.DeviceKindCLI, Status: status,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli.hpkePub,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: cli.signPub,
			GrantsDigest: wire.EmptyGrantsDigest(),
		})
	}
	dt := wire.DirectoryTranscript{VaultID: o.vaultID, DirectoryRevision: revision, Devices: records}
	b, err := wire.BuildDirectoryTranscript(dt)
	if err != nil {
		t.Fatal(err)
	}
	return dt, b
}

// putItem uploads one item revision; returns the HTTP status.
func (o *testOwner) putItem(t *testing.T, itemID string, revision uint64, meta, secret []byte) int {
	t.Helper()
	vwm, vwi := randBytes(t, 48), randBytes(t, 48)
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: o.vaultID, ItemID: itemID, Revision: revision,
		MetaCiphertext: meta, SecretCiphertext: secret,
		VaultWrappedMetaKey: vwm, VaultWrappedItemKey: vwi,
		WriterDeviceID: o.deviceID,
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
	if status >= 400 {
		t.Helper()
		_ = raw
	}
	return status
}

// grant builds an owner-signed grant row.
func (o *testOwner) grant(t *testing.T, deviceID, itemID, kind string, revision uint64, expiresAt int64) wire.GrantData {
	t.Helper()
	g := wire.GrantData{
		DeviceID: deviceID, ItemID: itemID, Kind: kind,
		HPKEEnc: randBytes(t, 32), WrappedKey: randBytes(t, 48),
		ExpiresAt: expiresAt, Revision: revision,
	}
	if err := g.Validate(); err != nil {
		t.Fatal(err)
	}
	tb, err := wire.BuildGrantTranscript(g.Transcript(o.vaultID))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(tb, o.signKey)
	if err != nil {
		t.Fatal(err)
	}
	g.Signature = sig
	return g
}

// deleteGrant signs and submits a grant deletion (§6.13).
func (o *testOwner) deleteGrant(t *testing.T, deviceID, itemID, kind string, revision uint64) (int, []byte) {
	t.Helper()
	tb, err := wire.BuildGrantTranscript(wire.GrantTranscript{
		VaultID: o.vaultID, DeviceID: deviceID, ItemID: itemID, Kind: kind, Revision: revision,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(tb, o.signKey)
	if err != nil {
		t.Fatal(err)
	}
	return o.env.do("DELETE", "/v1/grants", o.token, wire.DeleteGrantRequest{
		DeviceID: deviceID, ItemID: itemID, Kind: kind, Revision: revision, Signature: sig,
	})
}

// ---------------------------------------------------------------------------
// CLI fixture

type testCLI struct {
	env      *testEnv
	signPriv ed25519.PrivateKey
	signPub  []byte
	hpkePub  []byte // 32-byte X25519-shaped blob
	nonce    string
	deviceID string
	token    string
	vaultID  string
}

// registerPair runs POST /v1/pair/register for the CLI (§6.16).
func (e *testEnv) registerPair(t *testing.T) *testCLI {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cli := &testCLI{
		env: e, signPriv: priv, signPub: priv.Public().(ed25519.PublicKey),
		hpkePub:  randBytes(t, wire.SizeX25519Key),
		nonce:    randHexID(t), // 32 hex chars = 16 raw bytes
		deviceID: randHexID(t),
	}
	nonceRaw, _ := hex.DecodeString(cli.nonce)
	tb, err := wire.BuildPairRegisterTranscript(nonceRaw, "build-agent-1")
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignEd25519(tb, cli.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	var out wire.PairRegisterResponse
	if status := e.doOut("POST", "/v1/pair/register", "", wire.PairRegisterRequest{
		Nonce: cli.nonce, HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli.hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: cli.signPub,
		ProposedName: "build-agent-1", Signature: sig,
	}, &out); status != 201 {
		t.Fatalf("pair register: status %d", status)
	}
	e.clis[cli.deviceID] = cli
	return cli
}

// completePair runs POST /v1/pair/complete from the owner (§6.17).
func (o *testOwner) completePair(t *testing.T, cli *testCLI, grants []wire.GrantData) {
	t.Helper()
	for i := range grants {
		grants[i].DeviceID = cli.deviceID
	}
	grantsTB := make([]wire.GrantTranscript, 0, len(grants))
	for i := range grants {
		grantsTB = append(grantsTB, grants[i].Transcript(o.vaultID))
	}
	pairTB, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID: o.vaultID, OwnerSignPublicKey: o.signPub,
		Nonce: cli.nonce, DeviceID: cli.deviceID,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli.hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: cli.signPub,
		Label: "build-agent-1", Grants: grantsTB,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(pairTB, o.signKey)
	if err != nil {
		t.Fatal(err)
	}
	status, raw := o.env.do("POST", "/v1/pair/complete", o.token, wire.PairCompleteRequest{
		Nonce: cli.nonce,
		Device: wire.DeviceInput{
			DeviceID: cli.deviceID, Kind: wire.DeviceKindCLI,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: cli.hpkePub,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: cli.signPub,
			Label: "build-agent-1",
		},
		Grants: grants, Signature: sig,
	})
	if status != 204 {
		t.Fatalf("pair complete: status %d %s", status, raw)
	}
	cli.vaultID = o.vaultID
}

// session opens a CLI session (§6.7).
func (c *testCLI) session(t *testing.T) {
	t.Helper()
	var chal wire.SessionChallengeResponse
	if status := c.env.doOut("POST", "/v1/session", "", wire.SessionRequest{DeviceID: c.deviceID}, &chal); status != 200 {
		t.Fatalf("cli session step 1: status %d", status)
	}
	c.token = c.env.openSession(t, c.deviceID, chal.Challenge, func(tb []byte) ([]byte, error) {
		return wire.SignEd25519(tb, c.signPriv)
	})
}

// sync pulls one sync page (§8.1).
func (e *testEnv) sync(t *testing.T, token string, cursor int64) wire.SyncResponse {
	t.Helper()
	var out wire.SyncResponse
	if status := e.doOut("GET", "/v1/sync?cursor="+strconv.FormatInt(cursor, 10), token, nil, &out); status != 200 {
		t.Fatalf("sync cursor=%d: unexpected status %d", cursor, status)
	}
	return out
}

// changesByEntity indexes a sync batch by entity kind.
func changesByEntity(batch wire.SyncResponse) map[string][]wire.SyncChange {
	out := map[string][]wire.SyncChange{}
	for _, c := range batch.Changes {
		out[c.Entity] = append(out[c.Entity], c)
	}
	return out
}

func decodeItemData(t *testing.T, c wire.SyncChange) wire.ItemData {
	t.Helper()
	var d wire.ItemData
	if err := json.Unmarshal(c.Data, &d); err != nil {
		t.Fatalf("decode item data: %v", err)
	}
	return d
}

func decodeGrantData(t *testing.T, c wire.SyncChange) wire.GrantData {
	t.Helper()
	var d wire.GrantData
	if err := json.Unmarshal(c.Data, &d); err != nil {
		t.Fatalf("decode grant data: %v", err)
	}
	return d
}

func decodeDirectoryData(t *testing.T, c wire.SyncChange) wire.DirectoryData {
	t.Helper()
	var d wire.DirectoryData
	if err := json.Unmarshal(c.Data, &d); err != nil {
		t.Fatalf("decode directory data: %v", err)
	}
	return d
}
