//go:build e2e

// Package e2e drives the real keyref CLI binary against a real
// keyref-server (docs/protocol.md §11): a software P-256 owner creates
// the vault, items and grants, pairs the CLI, and the test asserts the
// masked views, the injected-but-redacted exec path, the policy
// rejections and the exit-code table of design.md §7.6.
package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"
)

// fxSecret is the fixture plaintext; every captured output is grepped
// for it and its common encodings (design.md §12.2 acceptance).
const fxSecret = "sk-E2E-PLAINTEXT-FIXTURE-do-not-leak-0123456789"

const (
	itemOpenAI = "deadbeefdeadbeefdeadbeefdeadbeef"
	cliLabel   = "build-agent-1"
)

var (
	base      string // temp dir with all binaries and homes
	serverURL string
	cliBin    string
	helperBin string
)

func TestMain(m *testing.M) {
	var err error
	base, err = os.MkdirTemp("", "keyref-e2e-*")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer os.RemoveAll(base)

	// Build the server, the CLI and the helper child fixture
	// (docs/protocol.md §11.3 step 1).
	if err := build("../..", "server", filepath.Join(base, "keyref-server"), "./cmd/keyref-server"); err != nil {
		fmt.Fprintln(os.Stderr, "build server:", err)
		os.Exit(1)
	}
	if err := build("../..", "cli", filepath.Join(base, "keyref"), "./cmd/keyref"); err != nil {
		fmt.Fprintln(os.Stderr, "build cli:", err)
		os.Exit(1)
	}
	if err := build(".", "", filepath.Join(base, "helper"), "./testdata/helper"); err != nil {
		fmt.Fprintln(os.Stderr, "build helper:", err)
		os.Exit(1)
	}
	cliBin = filepath.Join(base, "keyref")
	helperBin = filepath.Join(base, "helper")

	// Free port, temp data dir, plain-HTTP dev mode, no quotas.
	port, err := freePort()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	serverURL = "http://127.0.0.1:" + port
	dataDir := filepath.Join(base, "data")
	srv := exec.Command(filepath.Join(base, "keyref-server"), "serve", "--listen", "127.0.0.1:"+port)
	// The suite registers many devices from 127.0.0.1 in quick succession;
	// raise the per-IP pair/register window (test-only knob, protocol §6.16).
	srv.Env = append(os.Environ(), "KEYREF_DATA="+dataDir,
		"KEYREF_PAIR_REGISTER_PER_MINUTE=200")
	var srvLog bytes.Buffer
	srv.Stdout = &srvLog
	srv.Stderr = &srvLog
	if err := srv.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "start server:", err)
		os.Exit(1)
	}
	if err := waitHealthy(serverURL, 20*time.Second); err != nil {
		_ = srv.Process.Kill()
		fmt.Fprintln(os.Stderr, "server not healthy:", err, "\n", srvLog.String())
		os.Exit(1)
	}

	code := m.Run()

	_ = srv.Process.Kill()
	_, _ = srv.Process.Wait()
	if code != 0 {
		fmt.Fprintln(os.Stderr, "---- server log ----\n"+srvLog.String())
	}
	os.Exit(code)
}

func build(workdir, mod, out, pkg string) error {
	cmd := exec.Command("go", "build", "-C", filepath.Join(workdir, mod), "-o", out, pkg)
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	var buf bytes.Buffer
	cmd.Stderr = &buf
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%v: %s", err, buf.String())
	}
	return nil
}

func freePort() (string, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	defer l.Close()
	_, port, err := net.SplitHostPort(l.Addr().String())
	return port, err
}

func waitHealthy(origin string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		resp, err := http.Get(origin + "/v1/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	return fmt.Errorf("healthz not ready")
}

// ---- software owner (docs/protocol.md §11.2) ----

type owner struct {
	vaultID      string
	deviceID     string // this vault's owner device id (devices PK is global)
	signPriv     *ecdsa.PrivateKey
	signPub      []byte
	hpkePriv     []byte
	hpkePub      []byte
	token        string
	itemKeys     map[string][]byte
	metaKeys     map[string][]byte
	localSecrets map[string][]byte // local items: secret ciphertext of the owner's LOCAL copy (never uploaded)
	cliDeviceID  string            // assigned at pair completion
	cliHPKE      []byte            // CLI HPKE public key, from the QR payload
	cliSign      []byte            // CLI Ed25519 public key, from the QR payload
	cliGrants    []byte            // digest of the CLI's grants (directory record)
	// lastApprovalID is set by the approval responder for follow-up
	// assertions (consumed status, polling floor).
	lastApprovalID string
	hc             *http.Client
}

func newOwner(t *testing.T, vaultID string) *owner {
	t.Helper()
	o := &owner{
		vaultID:      vaultID,
		deviceID:     newID(t),
		itemKeys:     map[string][]byte{},
		metaKeys:     map[string][]byte{},
		localSecrets: map[string][]byte{},
		hc:           &http.Client{Timeout: 10 * time.Second},
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), nil)
	if err != nil {
		t.Fatal(err)
	}
	o.signPriv = priv
	if o.signPub, err = wire.EncodeP256PublicKey(&priv.PublicKey); err != nil {
		t.Fatal(err)
	}
	if o.hpkePub, o.hpkePriv, err = crypto.GenerateHPKEKeyPair(wire.KEMP256); err != nil {
		t.Fatal(err)
	}
	return o
}

func (o *owner) sign(tb []byte) []byte {
	sig, err := wire.SignOwnerECDSA(tb, o.signPriv)
	if err != nil {
		panic(err)
	}
	return sig
}

func (o *owner) do(t *testing.T, method, path string, body any, out any) *http.Response {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, serverURL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	if o.token != "" {
		req.Header.Set("Authorization", "Bearer "+o.token)
	}
	resp, err := o.hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	// Re-arm the body so callers can include it in failure messages.
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: decode %s: %v", method, path, raw, err)
		}
	}
	return resp
}

// createVault performs POST /v1/vaults (§6.1): directory revision 1
// with the owner device only, recovery material per §3.8.
func (o *owner) createVault(t *testing.T) {
	t.Helper()
	recoverySeed := make([]byte, 32)
	if _, err := rand.Read(recoverySeed); err != nil {
		t.Fatal(err)
	}
	kek, signPriv, err := crypto.RecoveryKeysFromSeed(recoverySeed)
	if err != nil {
		t.Fatal(err)
	}
	recoverySignPub := []byte(signPriv.Public().(ed25519.PublicKey))
	vmk := make([]byte, 32)
	if _, err := rand.Read(vmk); err != nil {
		t.Fatal(err)
	}
	aad, err := crypto.RecoveryAAD(o.vaultID)
	if err != nil {
		t.Fatal(err)
	}
	recoveryWrap, err := crypto.SealBlob(kek, aad, vmk)
	if err != nil {
		t.Fatal(err)
	}
	dir, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
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
	req := wire.CreateVaultRequest{
		VaultID: o.vaultID,
		Device: wire.DeviceInput{
			DeviceID: o.deviceID, Kind: wire.DeviceKindIOS,
			HPKEKEM: wire.KEMP256, HPKEPublicKey: o.hpkePub,
			SignAlg: wire.SignAlgECDSAP256, SignPublicKey: o.signPub,
			Label: "iPhone",
		},
		RecoveryWrap:      recoveryWrap,
		RecoveryKDFJSON:   `{"v":1,"kdf":"hkdf-sha256","salt":"","kek_info":"recovery-kek","sign_info":"recovery-sign"}`,
		RecoverySignPub:   recoverySignPub,
		DirectoryRevision: 1,
		DirectorySigned:   dir,
		Signature:         o.sign(dir),
	}
	var out wire.CreateVaultResponse
	if resp := o.do(t, "POST", "/v1/vaults", req, &out); resp.StatusCode != 201 {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("create vault: %d %s", resp.StatusCode, raw)
	}
}

// session runs the §6.7 two-step for the owner device.
func (o *owner) session(t *testing.T) {
	t.Helper()
	var ch wire.SessionChallengeResponse
	if resp := o.do(t, "POST", "/v1/session", wire.SessionRequest{DeviceID: o.deviceID}, &ch); resp.StatusCode != 200 {
		t.Fatalf("session step 1: %d", resp.StatusCode)
	}
	tb, err := wire.BuildSessionTranscript(o.deviceID, ch.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(tb, o.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	chB, sigB := wire.Blob(ch.Challenge), wire.Blob(sig)
	var out wire.SessionResponse
	resp := o.do(t, "POST", "/v1/session", wire.SessionRequest{
		DeviceID: o.deviceID, Challenge: &chB, Signature: &sigB,
	}, &out)
	if resp.StatusCode != 200 || out.Token == "" {
		t.Fatalf("session step 2: %d", resp.StatusCode)
	}
	o.token = out.Token
}

// putItem seals and uploads one item (§6.10).
func (o *owner) putItem(t *testing.T, itemID, ref, masked, secretValue string) {
	t.Helper()
	metaKey, itemKey := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(itemKey); err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{
		"v": 1, "ref": ref, "name": ref + " name", "description": "e2e fixture",
		"type": "api_key", "masked": masked, "injectable": true,
		"policy": map[string]any{
			"sensitivity": "standard", "commandPolicy": "deny-shells",
			"allowCommands": []string{}, "allowedHosts": []string{}, "allowArgv": false,
		},
	}
	metaJSON, _ := json.Marshal(meta)
	secretJSON, _ := json.Marshal(map[string]any{
		"v": 1, "value": secretValue, "username": "", "notes": "", "fields": map[string]any{},
	})
	metaAAD, _ := crypto.MetaAAD(o.vaultID, itemID)
	secretAAD, _ := crypto.SecretAAD(o.vaultID, itemID)
	metaCT, err := crypto.SealBlob(metaKey, metaAAD, metaJSON)
	if err != nil {
		t.Fatal(err)
	}
	secretCT, err := crypto.SealBlob(itemKey, secretAAD, secretJSON)
	if err != nil {
		t.Fatal(err)
	}
	vwmAAD, _ := crypto.VaultWrappedMetaKeyAAD(o.vaultID, itemID)
	vwiAAD, _ := crypto.VaultWrappedItemKeyAAD(o.vaultID, itemID)
	vmk := make([]byte, 32)
	vwm, err := crypto.SealBlob(vmk, vwmAAD, metaKey)
	if err != nil {
		t.Fatal(err)
	}
	vwi, err := crypto.SealBlob(vmk, vwiAAD, itemKey)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: o.vaultID, ItemID: itemID, Revision: 1,
		MetaCiphertext: metaCT, SecretCiphertext: secretCT,
		VaultWrappedMetaKey: vwm, VaultWrappedItemKey: vwi,
		WriterDeviceID: o.deviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := wire.PutItemRequest{
		Revision: 1, MetaCiphertext: metaCT, SecretCiphertext: secretCT,
		VaultWrappedMetaKey: vwm, VaultWrappedItemKey: vwi,
		WriterDeviceID: o.deviceID, Signature: o.sign(tb),
	}
	var out wire.PutItemResponse
	if resp := o.do(t, "PUT", "/v1/items/"+itemID, req, &out); resp.StatusCode != 200 {
		t.Fatalf("put item %s: %d", ref, resp.StatusCode)
	}
	o.metaKeys[itemID] = metaKey
	o.itemKeys[itemID] = itemKey
}

// putItemPolicy seals and uploads one item with a custom policy block
// (§6.10) — the approval and --reply fixtures need sensitivity,
// allowCommands and allowedHosts beyond the defaults.
func (o *owner) putItemPolicy(t *testing.T, itemID, ref, masked, secretValue string, policy map[string]any) {
	t.Helper()
	o.putItemFields(t, itemID, ref, masked, "", secretValue, policy)
}

func (o *owner) putItemFields(t *testing.T, itemID, ref, masked, username, secretValue string, policy map[string]any) {
	t.Helper()
	metaKey, itemKey := make([]byte, 32), make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(itemKey); err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{
		"v": 1, "ref": ref, "name": ref + " name", "description": "e2e fixture",
		"type": "api_key", "masked": masked, "injectable": true,
		"policy": policy,
	}
	metaJSON, _ := json.Marshal(meta)
	secretJSON, _ := json.Marshal(map[string]any{
		"v": 1, "value": secretValue, "username": username, "notes": "", "fields": map[string]any{},
	})
	metaAAD, _ := crypto.MetaAAD(o.vaultID, itemID)
	secretAAD, _ := crypto.SecretAAD(o.vaultID, itemID)
	metaCT, err := crypto.SealBlob(metaKey, metaAAD, metaJSON)
	if err != nil {
		t.Fatal(err)
	}
	secretCT, err := crypto.SealBlob(itemKey, secretAAD, secretJSON)
	if err != nil {
		t.Fatal(err)
	}
	vwmAAD, _ := crypto.VaultWrappedMetaKeyAAD(o.vaultID, itemID)
	vwiAAD, _ := crypto.VaultWrappedItemKeyAAD(o.vaultID, itemID)
	vmk := make([]byte, 32)
	vwm, err := crypto.SealBlob(vmk, vwmAAD, metaKey)
	if err != nil {
		t.Fatal(err)
	}
	vwi, err := crypto.SealBlob(vmk, vwiAAD, itemKey)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: o.vaultID, ItemID: itemID, Revision: 1,
		MetaCiphertext: metaCT, SecretCiphertext: secretCT,
		VaultWrappedMetaKey: vwm, VaultWrappedItemKey: vwi,
		WriterDeviceID: o.deviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := wire.PutItemRequest{
		Revision: 1, MetaCiphertext: metaCT, SecretCiphertext: secretCT,
		VaultWrappedMetaKey: vwm, VaultWrappedItemKey: vwi,
		WriterDeviceID: o.deviceID, Signature: o.sign(tb),
	}
	var out wire.PutItemResponse
	if resp := o.do(t, "PUT", "/v1/items/"+itemID, req, &out); resp.StatusCode != 200 {
		t.Fatalf("put item %s: %d", ref, resp.StatusCode)
	}
	o.metaKeys[itemID] = metaKey
	o.itemKeys[itemID] = itemKey
}

// grantLater wraps and uploads one grant AFTER pairing (§6.12): the
// server appends the synthetic item change the CLI's next sync picks
// up.
func (o *owner) grantLater(t *testing.T, itemID, kind string) {
	t.Helper()
	g := o.wrapGrant(t, o.cliHPKE, o.cliDeviceID, itemID, kind, o.keyFor(t, itemID, kind))
	var out wire.PutGrantsResponse
	if resp := o.do(t, "PUT", "/v1/grants", wire.PutGrantsRequest{Grants: []wire.GrantData{g}}, &out); resp.StatusCode != 200 {
		t.Fatalf("grant later %s %s: %d", itemID, kind, resp.StatusCode)
	}
}

func (o *owner) keyFor(t *testing.T, itemID, kind string) []byte {
	t.Helper()
	if kind == wire.GrantKindView {
		if k, ok := o.metaKeys[itemID]; ok {
			return k
		}
	} else if k, ok := o.itemKeys[itemID]; ok {
		return k
	}
	t.Fatalf("no %s key for item %s", kind, itemID)
	return nil
}

// wrapGrant builds a signed §3.2 grant row for the CLI device.
func (o *owner) wrapGrant(t *testing.T, cliHPKEPub []byte, cliDeviceID, itemID, kind string, key []byte) wire.GrantData {
	t.Helper()
	purpose := crypto.PurposeItemKey
	if kind == wire.GrantKindView {
		purpose = crypto.PurposeMetaKey
	}
	info, err := crypto.Info(purpose, o.vaultID, cliDeviceID)
	if err != nil {
		t.Fatal(err)
	}
	enc, wrapped, err := crypto.WrapKey(wire.KEMX25519, cliHPKEPub, info, key)
	if err != nil {
		t.Fatal(err)
	}
	g := wire.GrantData{
		DeviceID: cliDeviceID, ItemID: itemID, Kind: kind,
		HPKEEnc: enc, WrappedKey: wrapped, Revision: 1,
	}
	tb, err := wire.BuildGrantTranscript(g.Transcript(o.vaultID))
	if err != nil {
		t.Fatal(err)
	}
	g.Signature = o.sign(tb)
	return g
}

// completePairing answers the running `keyref pair` (§6.17). The CLI
// device keys and the QR pairing secret `c` are read off the QR payload,
// as the phone would (§3.13, v2 D): the phone computes the pairing
// confirmation MAC with the secret and sends it in pair/complete; the
// CLI re-verifies it before it pins the owner key.
func (o *owner) completePairing(t *testing.T, nonceHex, payloadLine string) {
	t.Helper()
	u, err := url.Parse(payloadLine)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	cliHPKE, err := base64.StdEncoding.DecodeString(q.Get("k"))
	if err != nil {
		t.Fatal(err)
	}
	cliSign, err := base64.StdEncoding.DecodeString(q.Get("s"))
	if err != nil {
		t.Fatal(err)
	}
	confirmSecret, err := base64.StdEncoding.DecodeString(q.Get("c"))
	if err != nil || len(confirmSecret) != wire.SizePairConfirmKey {
		t.Fatalf("pairing secret off the QR: %x (%v)", confirmSecret, err)
	}
	o.cliHPKE, o.cliSign = cliHPKE, cliSign
	cliDeviceID := newID(t)
	o.cliDeviceID = cliDeviceID

	grants := []wire.GrantData{
		o.wrapGrant(t, cliHPKE, cliDeviceID, itemOpenAI, wire.GrantKindView, o.metaKeys[itemOpenAI]),
		o.wrapGrant(t, cliHPKE, cliDeviceID, itemOpenAI, wire.GrantKindUse, o.itemKeys[itemOpenAI]),
	}
	gts := make([]wire.GrantTranscript, 0, len(grants))
	for _, g := range grants {
		gts = append(gts, g.Transcript(o.vaultID))
	}
	pairTB, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID: o.vaultID, OwnerSignPublicKey: o.signPub,
		Nonce: nonceHex, DeviceID: cliDeviceID,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: cliHPKE,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: cliSign,
		Label: cliLabel, Grants: gts,
	})
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := wire.GrantsDigest(gts); err == nil {
		o.cliGrants = digest
	}
	mac, err := wire.BuildPairConfirmMAC(confirmSecret, wire.DeviceKindCLI, pairTB)
	if err != nil {
		t.Fatal(err)
	}
	req := wire.PairCompleteRequest{
		Nonce: nonceHex,
		Device: wire.DeviceInput{
			DeviceID: cliDeviceID, Kind: wire.DeviceKindCLI,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: cliHPKE,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: cliSign,
			Label: cliLabel,
		},
		Grants:     grants,
		Signature:  o.sign(pairTB),
		PairingMAC: mac,
	}
	if resp := o.do(t, "POST", "/v1/pair/complete", req, nil); resp.StatusCode != 204 {
		t.Fatalf("pair complete: %d", resp.StatusCode)
	}
}

// publishDirectory publishes a new owner-signed directory (§6.15). The
// devices table follows it (v2 G), so every paired device has to be
// listed — one the directory omits is revoked.
func (o *owner) publishDirectory(t *testing.T, revision uint64, devices []wire.DirectoryDevice) {
	t.Helper()
	dir, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: o.vaultID, DirectoryRevision: revision, Devices: devices,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp := o.do(t, "PUT", "/v1/directory", wire.PutDirectoryRequest{
		DirectoryRevision: revision, DirectorySigned: dir, Signature: o.sign(dir),
	}, nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("publish directory: %d", resp.StatusCode)
	}
}

func newID(t *testing.T) string {
	t.Helper()
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(b)
}

// ---- CLI driver ----

type cliRun struct {
	stdout, stderr string
	code           int
}

func cliEnv() []string {
	return append(os.Environ(),
		"KEYREF_HOME="+filepath.Join(base, "cli-home"),
		"KEYREF_KEYRING_DIR="+filepath.Join(base, "cli-keyring"),
		"KEYREF_SERVER="+serverURL,
	)
}

func runCLI(t *testing.T, args ...string) cliRun {
	t.Helper()
	run, err := execCLI(args...)
	if err != nil {
		t.Fatalf("run keyref %v: %v", args, err)
	}
	return run
}

// execCLI runs the CLI binary and reports a start failure as an error
// instead of failing the test — safe to call from a spawned goroutine.
func execCLI(args ...string) (cliRun, error) {
	cmd := exec.Command(cliBin, args...)
	cmd.Env = cliEnv()
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		return cliRun{}, err
	}
	return cliRun{stdout: out.String(), stderr: errBuf.String(), code: code}, nil
}

type pairProc struct {
	cmd    *exec.Cmd
	stdout bytes.Buffer
	stderr *errSink
	done   chan error
}

// startPair runs `keyref pair --print-payload`. The whole suite shares
// one server process, so successive tests can exhaust the per-IP pair
// register limit (10/minute, design §10.5); a 429 there is expected
// backpressure, and the pair command exits 1. Retry the whole pairing
// with backoff until the window rolls over.
func startPair(t *testing.T) *pairProc {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		pp, rateLimited := tryStartPair(t)
		if !rateLimited {
			return pp
		}
		if time.Now().After(deadline) {
			t.Fatal("pair register still rate limited after 90s")
		}
		time.Sleep(5 * time.Second)
	}
}

func tryStartPair(t *testing.T) (*pairProc, bool) {
	t.Helper()
	cmd := exec.Command(cliBin, "pair", "--name", cliLabel, "--print-payload")
	cmd.Env = cliEnv()
	pp := &pairProc{cmd: cmd, done: make(chan error, 1)}
	cmd.Stdout = &pp.stdout
	pp.stderr = &errSink{b: &syncBuf{}}
	cmd.Stderr = pp.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { pp.done <- cmd.Wait() }()

	// The register happens within the first seconds; if it comes back
	// rate limited the process exits 1 quickly, before any QR polling.
	select {
	case err := <-pp.done:
		if err != nil && strings.Contains(pp.stderr.String(), "429 rate_limited") {
			return pp, true
		}
		t.Fatalf("pair exited early: %v\nstdout:\n%s\nstderr:\n%s", err, pp.stdout.String(), pp.stderr.String())
	case <-time.After(8 * time.Second):
		// Registered and past the limit; normal QR-polling flow.
	}
	return pp, false
}

// errSink and syncBuf keep pair stderr readable even when the test dies
// holding a bytes.Buffer that the pair process still writes to.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

type errSink struct{ b *syncBuf }

func (e *errSink) Write(p []byte) (int, error) { return e.b.Write(p) }

func (e *errSink) String() string { return e.b.String() }

func (pp *pairProc) waitPayloadLine(t *testing.T) (nonce, payload string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if n, p := parsePairOutput(pp.stdout.String()); n != "" && p != "" {
			return n, p
		}
		select {
		case err := <-pp.done:
			t.Fatalf("pair exited early: %v\nstdout:\n%s\nstderr:\n%s", err, pp.stdout.String(), pp.stderr.String())
		default:
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("pair did not print its payload in time")
	return "", ""
}

func parsePairOutput(s string) (nonce, payload string) {
	for _, line := range strings.Split(s, "\n") {
		if strings.HasPrefix(line, "nonce: ") {
			nonce = strings.TrimSpace(strings.TrimPrefix(line, "nonce: "))
		}
		if strings.HasPrefix(line, "payload: ") {
			payload = strings.TrimSpace(strings.TrimPrefix(line, "payload: "))
		}
	}
	return
}

// ---- leak assertions ----

func leakEncodings() []string {
	return []string{
		fxSecret,
		base64.StdEncoding.EncodeToString([]byte(fxSecret)),
		strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(fxSecret)), "="),
		base64.URLEncoding.EncodeToString([]byte(fxSecret)),
		hex.EncodeToString([]byte(fxSecret)),
		strings.ToUpper(hex.EncodeToString([]byte(fxSecret))),
	}
}

func assertNoLeak(t *testing.T, where string, outputs ...string) {
	t.Helper()
	for _, enc := range leakEncodings() {
		for _, out := range outputs {
			if strings.Contains(out, enc) {
				t.Fatalf("%s leaked the fixture secret (%q…): %.120q", where, enc[:12], out)
			}
		}
	}
}

// ---- the tests ----

func TestEndToEnd(t *testing.T) {
	vaultID := newID(t)
	owner := newOwner(t, vaultID)
	owner.createVault(t)
	owner.session(t)
	owner.putItem(t, itemOpenAI, "openai-prod", "sk-****abcd", fxSecret)

	// Pair: the CLI registers and polls; the owner completes.
	pp := startPair(t)
	nonceHex, payload := pp.waitPayloadLine(t)
	owner.completePairing(t, nonceHex, payload)
	select {
	case err := <-pp.done:
		if err != nil {
			t.Fatalf("keyref pair failed: %v\nstdout:\n%s", err, pp.stdout.String())
		}
	case <-time.After(30 * time.Second):
		_ = pp.cmd.Process.Kill()
		t.Fatal("keyref pair did not finish")
	}
	assertNoLeak(t, "pair output", pp.stdout.String())

	// Sync the bootstrap batch.
	sync := runCLI(t, "sync")
	if sync.code != 0 {
		t.Fatalf("sync exit %d: %s", sync.code, sync.stderr)
	}

	// list: masked metadata only (design §12.2).
	list := runCLI(t, "list")
	if list.code != 0 {
		t.Fatalf("list exit %d: %s", list.code, list.stderr)
	}
	if !strings.Contains(list.stdout, "openai-prod") || !strings.Contains(list.stdout, "sk-****abcd") {
		t.Fatalf("list output missing ref/mask:\n%s", list.stdout)
	}
	assertNoLeak(t, "list", list.stdout, list.stderr)

	listJSON := runCLI(t, "list", "--format", "json")
	if listJSON.code != 0 || !strings.Contains(listJSON.stdout, "\"masked\"") {
		t.Fatalf("list json: %d %s", listJSON.code, listJSON.stdout)
	}
	if strings.Contains(listJSON.stdout, "value") {
		t.Fatalf("list json carries a value field:\n%s", listJSON.stdout)
	}
	assertNoLeak(t, "list json", listJSON.stdout)

	get := runCLI(t, "get", "openai-prod")
	if get.code != 0 || !strings.Contains(get.stdout, "sk-****abcd") {
		t.Fatalf("get: %d %s", get.code, get.stdout)
	}
	assertNoLeak(t, "get", get.stdout, get.stderr)

	// status shows the use grant.
	status := runCLI(t, "status")
	if status.code != 0 || !strings.Contains(status.stdout, "grant:") {
		t.Fatalf("status: %d %s", status.code, status.stdout)
	}

	// exec --env: the child prints the secret, the CLI redacts it.
	ex := runCLI(t, "exec", "--env", "K=openai-prod", "--", helperBin, "print-env")
	if ex.code != 0 {
		t.Fatalf("exec exit %d: %s %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stdout, "K=<redacted:openai-prod>") {
		t.Fatalf("exec output not redacted:\n%s", ex.stdout)
	}
	assertNoLeak(t, "exec", ex.stdout, ex.stderr)

	// Unknown ref → exit 11.
	if r := runCLI(t, "get", "no-such-ref"); r.code != 11 {
		t.Fatalf("get unknown ref exit %d, want 11 (%s)", r.code, r.stderr)
	}
	if r := runCLI(t, "exec", "--env", "K=no-such-ref", "--", helperBin, "print-env"); r.code != 11 {
		t.Fatalf("exec unknown ref exit %d, want 11 (%s)", r.code, r.stderr)
	}

	// Policy rejections → exit 10, the child never starts.
	for _, argv := range [][]string{
		{"echo", "hi"},
		{"env"},
		{"sh", "-c", "echo hi"},
	} {
		args := append([]string{"exec", "--env", "K=openai-prod", "--"}, argv...)
		r := runCLI(t, args...)
		if r.code != 10 {
			t.Fatalf("exec %v exit %d, want 10 (%s)", argv, r.code, r.stderr)
		}
		if strings.Contains(r.stdout, "hi") {
			t.Fatalf("denied command produced output: %q", r.stdout)
		}
	}

	// A #!/bin/sh script is denied through its interpreter (§7.3).
	shScript := filepath.Join(base, "innocent.sh")
	if err := os.WriteFile(shScript, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if r := runCLI(t, "exec", "--env", "K=openai-prod", "--", shScript); r.code != 10 {
		t.Fatalf("shebang script exit %d, want 10 (%s)", r.code, r.stderr)
	}

	// Child exit code passes through (§7.6 first row).
	if r := runCLI(t, "exec", "--env", "K=openai-prod", "--", helperBin, "exit42"); r.code != 42 {
		t.Fatalf("child exit passthrough got %d, want 42", r.code)
	}

	// lock/unlock gates unwrapping with exit 12.
	if r := runCLI(t, "lock"); r.code != 0 {
		t.Fatalf("lock: %d", r.code)
	}
	if r := runCLI(t, "list"); r.code != 12 {
		t.Fatalf("locked list exit %d, want 12", r.code)
	}
	if r := runCLI(t, "exec", "--env", "K=openai-prod", "--", helperBin, "print-env"); r.code != 12 {
		t.Fatalf("locked exec exit %d, want 12", r.code)
	}
	if r := runCLI(t, "unlock"); r.code != 0 {
		t.Fatalf("unlock: %d", r.code)
	}
	if r := runCLI(t, "list"); r.code != 0 {
		t.Fatalf("unlocked list exit %d: %s", r.code, r.stderr)
	}

	// The audit trail must cover BOTH the allowed exec and the rejected
	// attempts (§7.7: every attempt is recorded), encrypted to the
	// owner and free of secret values.
	requireAuditArrived(t, owner)
}

// decryptAuditEnvelope opens one §6.23 envelope with the owner key and
// returns the event JSON.
func decryptAuditEnvelope(t *testing.T, o *owner, env []byte) map[string]any {
	t.Helper()
	if env[0] != 1 {
		t.Fatalf("wrap_count %d, want 1 (single-owner fixture)", env[0])
	}
	encLen := int(binary.BigEndian.Uint16(env[1:3]))
	enc := env[3 : 3+encLen]
	wrapped := env[3+encLen : 3+encLen+48]
	blob := env[3+encLen+48:]

	info, err := crypto.Info(crypto.PurposeAuditEventKey, o.vaultID, o.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	eventKey, err := crypto.UnwrapKey(wire.KEMP256, o.hpkePriv, info, enc, wrapped)
	if err != nil {
		t.Fatalf("audit unwrap failed: %v", err)
	}
	aad, err := crypto.AuditAAD(o.vaultID, o.cliDeviceID)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.OpenBlob(eventKey, aad, blob)
	if err != nil {
		t.Fatalf("audit open failed: %v", err)
	}
	var evt map[string]any
	if err := json.Unmarshal(pt, &evt); err != nil {
		t.Fatal(err)
	}
	assertNoLeak(t, "audit plaintext", string(pt))
	return evt
}

func requireAuditArrived(t *testing.T, o *owner) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	var events wire.AuditPageResponse
	for time.Now().Before(deadline) {
		resp := o.do(t, "GET", "/v1/audit?cursor=0", nil, &events)
		if resp.StatusCode == 200 && len(events.Events) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if len(events.Events) == 0 {
		t.Fatal("no audit events arrived")
	}
	sawAllow := false
	sawDeny := false
	for _, ev := range events.Events {
		evt := decryptAuditEnvelope(t, o, ev.Ciphertext)
		switch evt["policy_result"] {
		case "allow":
			sawAllow = true
		default:
			if strings.HasPrefix(fmt.Sprint(evt["policy_result"]), "deny:") {
				sawDeny = true
			}
		}
	}
	if !sawAllow {
		t.Fatal("no allowed-exec audit event arrived")
	}
	if !sawDeny {
		t.Fatal("no denied-exec audit event arrived (§7.7: every attempt is recorded)")
	}
}
