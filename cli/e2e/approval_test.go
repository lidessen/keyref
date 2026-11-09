//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"
)

// The Phase-2 e2e additions (design §8.3, §7.1, §7.8): the approval
// flow end to end against the real server and real CLI binary, with
// the software owner acting as the approving phone (docs/protocol.md
// §11.2, §11.3 step 8).

const (
	itemApproval = "cafe0000cafe0000cafe0000cafe0000"
	secretApprov = "sk-APPROVAL-PLAINTEXT-fixture-99887766"
	refApproval  = "approval-prod"
)

// approvalRequest mirrors the §6.19 request plaintext; unknown fields
// are rejected so a drift between the CLI and the contract fails here.
type approvalRequest struct {
	V                  int      `json:"v"`
	CLIDeviceID        string   `json:"cli_device_id"`
	ItemID             string   `json:"item_id"`
	Argv               []string `json:"argv"`
	Refs               []string `json:"refs"`
	Injection          string   `json:"injection"`
	Hosts              []string `json:"hosts"`
	Reply              []string `json:"reply"`
	EphemeralKEM       string   `json:"ephemeral_kem"`
	EphemeralPublicKey []byte   `json:"ephemeral_public_key"`
	CreatedAt          int64    `json:"created_at"`
}

// setupPairedVault creates a fresh vault whose CLI holds view+use for
// the standard openai item and NOTHING else: approval items are
// granted later through PUT /v1/grants (view only), the approval-only
// shape of design §6.1.
func setupPairedVault(t *testing.T) *owner {
	t.Helper()
	vaultID := newID(t)
	o := newOwner(t, vaultID)
	o.createVault(t)
	o.session(t)
	o.putItem(t, itemOpenAI, "openai-prod", "sk-****abcd", fxSecret)
	pp := startPair(t)
	nonceHex, payload := pp.waitPayloadLine(t)
	o.completePairing(t, nonceHex, payload)
	select {
	case err := <-pp.done:
		if err != nil {
			t.Fatalf("keyref pair failed: %v\nstdout:\n%s", err, pp.stdout.String())
		}
	case <-time.After(30 * time.Second):
		_ = pp.cmd.Process.Kill()
		t.Fatal("keyref pair did not finish")
	}
	if sync := runCLI(t, "sync"); sync.code != 0 {
		t.Fatalf("sync exit %d: %s", sync.code, sync.stderr)
	}
	return o
}

// putApprovalItem uploads an approval item (sensitivity=approval,
// CLI-facing allowCommands, one allowed host) and grants VIEW only.
func (o *owner) putApprovalItem(t *testing.T) {
	t.Helper()
	o.putItemPolicy(t, itemApproval, refApproval, "sk-****eeee", secretApprov, map[string]any{
		"sensitivity": "approval", "commandPolicy": "deny-shells",
		"allowCommands": []string{"helper"}, "allowedHosts": []string{"api.example.com"},
		"allowArgv": false,
	})
	o.grantLater(t, itemApproval, wire.GrantKindView)
	if sync := runCLI(t, "sync"); sync.code != 0 {
		t.Fatalf("sync after grant exit %d: %s", sync.code, sync.stderr)
	}
}

// approvalDecision is what the fake phone answers with.
type approvalDecision int

const (
	decideApprove approvalDecision = iota
	decideDeny
)

// serveOneApproval polls the owner's pending queue until an approval for
// the default fixture item appears, verifies the CLI signature,
// decrypts the transcript, asserts its shape, and answers with the
// decision and a correctly bound one-time wrap. It runs until the test
// ends.
func (o *owner) serveOneApproval(t *testing.T, decision approvalDecision, wantReply []string) *sync.WaitGroup {
	return o.serveOneApprovalFor(t, itemApproval, decision, wantReply)
}

// serveOneApprovalFor is serveOneApproval restricted to one item id (the
// local-item flow answers a different item than the default fixture).
func (o *owner) serveOneApprovalFor(t *testing.T, itemID string, decision approvalDecision, wantReply []string) *sync.WaitGroup {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			var list wire.ApprovalListResponse
			resp := o.do(t, "GET", "/v1/approvals?status=pending", nil, &list)
			if resp.StatusCode != 200 {
				time.Sleep(300 * time.Millisecond)
				continue
			}
			for _, row := range list.Approvals {
				if row.ItemID != itemID {
					continue
				}
				o.answerApproval(t, &row, decision, wantReply)
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
		t.Error("approval request never appeared in the owner queue")
	}()
	return &wg
}

// answerApproval plays the phone for one approval row: verify the CLI
// signature FIRST (design §8.3 step 3), decrypt, assert the request
// transcript, then approve with the one-time wrap or deny. The wrap
// payload follows the storage class (design §6.6, v0.7): a synced
// approval item wraps its item key; a LOCAL item delivers the secret
// value taken from the owner's own local copy, HPKE-sealed to the
// request's ephemeral key under the same D4 binding — the server is a
// blind relay for either.
func (o *owner) answerApproval(t *testing.T, row *wire.ApprovalRow, decision approvalDecision, wantReply []string) {
	t.Helper()
	// Signature over the raw ciphertext, before any decryption.
	if err := wire.VerifyCLISignature(row.RequestCiphertext, row.RequestSignature, o.cliSign); err != nil {
		t.Fatalf("owner: CLI approval signature verification failed: %v", err)
	}
	// Ciphertext layout: enc(65B P-256) ‖ ct‖tag.
	enc, ct := row.RequestCiphertext[:65], row.RequestCiphertext[65:]
	info, err := crypto.Info(crypto.PurposeApprovalRequest, o.vaultID, o.deviceID)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.UnwrapKey(wire.KEMP256, o.hpkePriv, info, enc, ct)
	if err != nil {
		t.Fatalf("owner: approval request unwrap failed: %v", err)
	}
	defer crypto.WipeKey(pt)
	var rq approvalRequest
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rq); err != nil {
		t.Fatalf("owner: approval transcript decode: %v\npayload: %.200q", err, pt)
	}
	if rq.CLIDeviceID != o.cliDeviceID || rq.ItemID != row.ItemID {
		t.Fatalf("approval transcript identity: %+v", rq)
	}
	if len(rq.Argv) == 0 || rq.Argv[0] != helperBin {
		t.Fatalf("approval transcript argv must carry the original argv: %v", rq.Argv)
	}
	wantRef := refApproval
	if row.ItemID == itemLocal {
		wantRef = refLocal
	}
	foundRef := false
	for _, r := range rq.Refs {
		if r == wantRef {
			foundRef = true
		}
	}
	if !foundRef {
		t.Fatalf("approval transcript refs missing %q: %v", wantRef, rq.Refs)
	}
	wantInjection := "env"
	if len(rq.Argv) > 1 && rq.Argv[1] == "login" {
		wantInjection = "stdin-login"
	}
	if !containsString(strings.Split(rq.Injection, ","), wantInjection) {
		t.Fatal("approval transcript has the wrong injection mode")
	}
	if len(rq.Hosts) != 1 || rq.Hosts[0] != "api.example.com" {
		t.Fatalf("approval transcript hosts: %v", rq.Hosts)
	}
	if rq.EphemeralKEM != wire.KEMX25519 || len(rq.EphemeralPublicKey) != 32 {
		t.Fatalf("approval transcript ephemeral key: %s %d", rq.EphemeralKEM, len(rq.EphemeralPublicKey))
	}
	for _, want := range wantReply {
		if !containsString(rq.Reply, want) {
			t.Fatalf("approval transcript reply patterns %v missing %q", rq.Reply, want)
		}
	}

	// The decision.
	body := wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied}
	if decision == decideApprove {
		wrapInfo, err := crypto.OneTimeItemKeyInfo(o.vaultID, o.cliDeviceID, row.ItemID, row.ApprovalID, row.RequestCiphertext)
		if err != nil {
			t.Fatal(err)
		}
		// Synced item: wrap the item key. Local item: deliver the secret
		// VALUE from the owner's local copy — never an item key, which
		// the CLI must not hold for a local item.
		payload := o.itemKeys[row.ItemID]
		if row.ItemID == itemLocal {
			payload = o.localSecretValue(t, row.ItemID)
		}
		oneEnc, wrapped, err := crypto.WrapKey(wire.KEMX25519, rq.EphemeralPublicKey, wrapInfo, payload)
		if err != nil {
			t.Fatal(err)
		}
		body = wire.ApprovalDecisionRequest{
			Decision: wire.ApprovalStatusApproved, OneTimeEnc: oneEnc, OneTimeWrappedKey: wrapped,
		}
	}
	if resp := o.do(t, "POST", "/v1/approvals/"+row.ApprovalID+"/decision", body, nil); resp.StatusCode != 204 {
		t.Fatalf("owner decision: %d", resp.StatusCode)
	}
	o.lastApprovalID = row.ApprovalID
}

func containsString(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestApprovalExecFlow(t *testing.T) {
	o := setupPairedVault(t)
	o.putApprovalItem(t)

	// list/get work on meta alone (view grant only) — the approval item
	// is visible and masked, with sensitivity reported.
	get := runCLI(t, "get", refApproval)
	if get.code != 0 || !strings.Contains(get.stdout, "masked: sk-****eeee") ||
		!strings.Contains(get.stdout, "sensitivity: approval") {
		t.Fatalf("get approval item: %d\n%s", get.code, get.stdout)
	}
	assertNoLeak(t, "get approval", get.stdout, get.stderr)

	done := o.serveOneApproval(t, decideApprove, nil)
	ex := runCLI(t, "exec", "--env", "K="+refApproval, "--", helperBin, "print-env")
	done.Wait()
	if ex.code != 0 {
		t.Fatalf("approval exec exit %d: %s %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stdout, "K=<redacted:"+refApproval+">") {
		t.Fatalf("approval exec output not redacted:\n%s", ex.stdout)
	}
	assertNoLeak(t, "approval exec", ex.stdout, ex.stderr)

	// The wrap was taken exactly once: the approval status summary in
	// the owner's sync bootstrap reports consumed (protocol §6.22,
	// §11.3 step 8; the poll endpoint itself serves the initiating CLI
	// only, so the status arrives through sync — §8.2/D8).
	if o.lastApprovalID == "" {
		t.Fatal("no approval id recorded")
	}
	assertApprovalStatus(t, o, o.lastApprovalID, wire.ApprovalStatusConsumed)
}

// assertApprovalStatus bootstraps the owner's sync and checks the
// approval entity's status summary.
func assertApprovalStatus(t *testing.T, o *owner, approvalID, want string) {
	t.Helper()
	batch := o.do(t, "GET", "/v1/sync?cursor=0", nil, nil)
	if batch.StatusCode != 200 {
		t.Fatalf("owner sync: %d", batch.StatusCode)
	}
	var resp wire.SyncResponse
	raw, _ := io.ReadAll(batch.Body)
	if err := json.Unmarshal(raw, &resp); err != nil {
		t.Fatalf("owner sync decode: %v", err)
	}
	for _, c := range resp.Changes {
		if c.Entity != wire.EntityApproval {
			continue
		}
		var d wire.ApprovalStatusData
		if err := json.Unmarshal(c.Data, &d); err != nil {
			t.Fatal(err)
		}
		if d.ApprovalID == approvalID {
			if d.Status != want {
				t.Fatalf("approval %s status = %q, want %q", approvalID, d.Status, want)
			}
			return
		}
	}
	t.Fatalf("approval %s not found in the owner sync batch", approvalID)
}

func TestApprovalDeniedExits13(t *testing.T) {
	o := setupPairedVault(t)
	o.putApprovalItem(t)
	done := o.serveOneApproval(t, decideDeny, nil)
	start := time.Now()
	ex := runCLI(t, "exec", "--env", "K="+refApproval, "--", helperBin, "print-env")
	done.Wait()
	if ex.code != 13 {
		t.Fatalf("denied approval exit %d, want 13 (stderr: %s)", ex.code, ex.stderr)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("denial took %s", elapsed)
	}
	if strings.Contains(ex.stderr, secretApprov) || strings.Contains(ex.stdout, secretApprov) {
		t.Fatal("denial output leaked the secret")
	}
}

func TestApprovalTimeoutExits13(t *testing.T) {
	o := setupPairedVault(t)
	o.putApprovalItem(t)
	// No responder: the CLI must give up after --timeout seconds.
	start := time.Now()
	ex := runCLI(t, "exec", "--timeout", "3", "--env", "K="+refApproval, "--", helperBin, "print-env")
	if ex.code != 13 {
		t.Fatalf("timed-out approval exit %d, want 13 (stderr: %s)", ex.code, ex.stderr)
	}
	if elapsed := time.Since(start); elapsed < 2*time.Second || elapsed > 25*time.Second {
		t.Fatalf("timeout fired after %s, want ≈3s+overhead", elapsed)
	}
}

// TestApprovalPolicyBeforeRequest pins design §15: the policy checks
// happen before the approval request exists — a denied command must not
// create a pending approval at all.
func TestApprovalPolicyBeforeRequest(t *testing.T) {
	o := setupPairedVault(t)
	o.putApprovalItem(t)
	if r := runCLI(t, "exec", "--env", "K="+refApproval, "--", "echo", "hi"); r.code != 10 {
		t.Fatalf("denied command exit %d, want 10", r.code)
	}
	var list wire.ApprovalListResponse
	o.do(t, "GET", "/v1/approvals?status=pending", nil, &list)
	if len(list.Approvals) != 0 {
		t.Fatalf("a policy-rejected exec created %d pending approvals", len(list.Approvals))
	}
}

// TestApprovalUnsignedRequestRejected posts an approval with a bad
// signature through a real second CLI device: the server must answer
// 403 bad_signature and store nothing (design §8.3: 没有发送方认证的
// 审批请求不受理; protocol §7.1 step 2).
func TestApprovalUnsignedRequestRejected(t *testing.T) {
	o := setupPairedVault(t)
	o.putApprovalItem(t)

	// A second CLI device with its own keys (registered via HTTP, as
	// the server-level fixtures do).
	_, signPriv, _ := ed25519.GenerateKey(nil)
	signPub := []byte(signPriv.Public().(ed25519.PublicKey))
	nonce := newID(t)
	regTB, err := wire.BuildPairRegisterTranscript(mustHex(t, nonce), "rogue-cli")
	if err != nil {
		t.Fatal(err)
	}
	sig, _ := wire.SignEd25519(regTB, signPriv)
	if resp := o.do(t, "POST", "/v1/pair/register", wire.PairRegisterRequest{
		Nonce: nonce, HPKEKEM: wire.KEMX25519, HPKEPublicKey: make([]byte, 32),
		SignAlg: wire.SignAlgEd25519, SignPublicKey: signPub,
		ProposedName: "rogue-cli", Signature: sig,
	}, nil); resp.StatusCode != 201 {
		t.Fatalf("rogue pair register: %d", resp.StatusCode)
	}
	rogueDevice := newID(t)
	o.completePairFor(t, nonce, rogueDevice, signPub, nil)

	// Rogue session.
	var ch wire.SessionChallengeResponse
	if resp := o.do(t, "POST", "/v1/session", wire.SessionRequest{DeviceID: rogueDevice}, &ch); resp.StatusCode != 200 {
		t.Fatalf("rogue session step 1: %d", resp.StatusCode)
	}
	sessTB, _ := wire.BuildSessionTranscript(rogueDevice, ch.Challenge)
	sessSig, _ := wire.SignEd25519(sessTB, signPriv)
	chB, sigB := wire.Blob(ch.Challenge), wire.Blob(sessSig)
	var sess wire.SessionResponse
	if resp := o.do(t, "POST", "/v1/session", wire.SessionRequest{
		DeviceID: rogueDevice, Challenge: &chB, Signature: &sigB,
	}, &sess); resp.StatusCode != 200 {
		t.Fatalf("rogue session step 2: %d", resp.StatusCode)
	}

	// Submit an approval whose signature does NOT verify (signed over
	// different bytes than the ciphertext carries).
	rogue := &owner{vaultID: o.vaultID, token: sess.Token, hc: o.hc}
	ct := append(make([]byte, 32), bytes.Repeat([]byte{7}, 64)...)
	badSig, _ := wire.SignEd25519([]byte("other bytes entirely"), signPriv)
	req := wire.ApprovalCreateRequest{
		ItemID: itemApproval, RequestCiphertext: ct, RequestSignature: badSig,
		ExpiresAt: time.Now().Add(60 * time.Second).UnixMilli(),
	}
	if resp := rogue.do(t, "POST", "/v1/approvals", req, nil); resp.StatusCode != 403 {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unsigned approval: want 403, got %d (%s)", resp.StatusCode, body)
	}
	// Nothing reached the pending queue.
	var list wire.ApprovalListResponse
	o.do(t, "GET", "/v1/approvals?status=pending", nil, &list)
	if len(list.Approvals) != 0 {
		t.Fatalf("a 403-ed approval reached the queue: %d rows", len(list.Approvals))
	}
}

// completePairFor completes pairing for an externally-registered CLI
// (used by the rogue-device fixture).
func (o *owner) completePairFor(t *testing.T, nonceHex, deviceID string, signPub []byte, grants []wire.GrantData) {
	t.Helper()
	gts := make([]wire.GrantTranscript, 0, len(grants))
	for _, g := range grants {
		gts = append(gts, g.Transcript(o.vaultID))
	}
	pairTB, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID: o.vaultID, OwnerSignPublicKey: o.signPub,
		Nonce: nonceHex, DeviceID: deviceID,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: make([]byte, 32),
		SignAlg: wire.SignAlgEd25519, SignPublicKey: signPub,
		Label: "rogue-cli", Grants: gts,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := wire.PairCompleteRequest{
		Nonce: nonceHex,
		Device: wire.DeviceInput{
			DeviceID: deviceID, Kind: wire.DeviceKindCLI,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: make([]byte, 32),
			SignAlg: wire.SignAlgEd25519, SignPublicKey: signPub,
			Label: "rogue-cli",
		},
		Grants:    grants,
		Signature: o.sign(pairTB),
	}
	if resp := o.do(t, "POST", "/v1/pair/complete", req, nil); resp.StatusCode != 204 {
		t.Fatalf("rogue pair complete: %d", resp.StatusCode)
	}
}

func mustHex(t *testing.T, hexStr string) []byte {
	t.Helper()
	raw := make([]byte, len(hexStr)/2)
	for i := range raw {
		if _, err := fmt.Sscanf(hexStr[i*2:i*2+2], "%02x", &raw[i]); err != nil {
			t.Fatal(err)
		}
	}
	return raw
}

// TestApprovalPollingFloor pins the server-side 2-second floor: an
// immediate second poll of the same approval is rejected with 429
// rate_limited (protocol §1.3, §6.22) — and the first poll of a foreign
// approval stays 404 for the owner.
func TestApprovalPollingFloor(t *testing.T) {
	o := setupPairedVault(t)
	o.putApprovalItem(t)

	// A real pending approval, submitted by the CLI itself.
	done := o.serveOneApproval(t, decideApprove, nil)
	ex := runCLI(t, "exec", "--env", "K="+refApproval, "--", helperBin, "print-env")
	done.Wait()
	if ex.code != 0 {
		t.Fatalf("exec exit %d: %s", ex.code, ex.stderr)
	}
	if o.lastApprovalID == "" {
		t.Fatal("no approval id")
	}

	// Two owner polls in quick succession: the first is answered (404 —
	// the owner is not the initiating CLI), the second hits the floor.
	resp1 := o.do(t, "GET", "/v1/approvals/"+o.lastApprovalID, nil, nil)
	if resp1.StatusCode != 404 {
		t.Fatalf("owner poll of a foreign approval: want 404, got %d", resp1.StatusCode)
	}
	resp2 := o.do(t, "GET", "/v1/approvals/"+o.lastApprovalID, nil, nil)
	if resp2.StatusCode != 429 {
		body, _ := io.ReadAll(resp2.Body)
		t.Fatalf("fast second poll: want 429 rate_limited, got %d (%s)", resp2.StatusCode, body)
	}
}

// TestPtyReplyFlow is the §7.1 interactive path end to end on a real
// pty: the helper prints "Password: ", the reply pattern matches the
// pre-redaction output, keyref types the approval-wrapped secret, and
// everything the caller sees is redacted. Skipped where no pty exists.
func TestPtyReplyFlow(t *testing.T) {
	if _, err := os.Stat("/dev/ptmx"); err != nil {
		t.Skipf("no pty in this environment: %v", err)
	}
	o := setupPairedVault(t)
	o.putApprovalItem(t)
	done := o.serveOneApproval(t, decideApprove, []string{"Password:=" + refApproval})
	ex := runCLI(t, "exec", "--pty",
		"--reply", "Password:="+refApproval,
		"--env", "K="+refApproval,
		"--", helperBin, "prompt")
	done.Wait()
	if ex.code != 0 {
		t.Fatalf("pty exec exit %d: %s %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stdout, "Password:") || !strings.Contains(ex.stdout, "got:<redacted:"+refApproval+">") {
		t.Fatalf("pty output missing prompt or redacted typed secret:\n%s", ex.stdout)
	}
	assertNoLeak(t, "pty exec", ex.stdout, ex.stderr)
}

// TestMCPFlow drives `keyref mcp` as a real subprocess over stdio
// (design §7.8): initialize, tools/list, then tools/call for get and
// exec — the exec tool must behave exactly like the CLI (redacted
// output plus exit code).
func TestMCPFlow(t *testing.T) {
	o := setupPairedVault(t)
	_ = o
	cmd := exec.Command(cliBin, "mcp")
	cmd.Env = cliEnv()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var errBuf bytes.Buffer
	cmd.Stderr = &errBuf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	reader := bufio.NewReader(stdout)

	send := func(method string, params map[string]any) map[string]any {
		t.Helper()
		req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": method}
		if params != nil {
			req["params"] = params
		}
		b, _ := json.Marshal(req)
		if _, err := stdin.Write(append(b, '\n')); err != nil {
			t.Fatalf("mcp write %s: %v", method, err)
		}
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatalf("mcp read %s: %v (stderr: %s)", method, err, errBuf.String())
		}
		var resp map[string]any
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatalf("mcp response %s: %v (%q)", method, err, line)
		}
		return resp
	}

	// initialize.
	init := send("initialize", map[string]any{"protocolVersion": "2024-11-05"})
	info, _ := init["result"].(map[string]any)
	if info == nil || info["protocolVersion"] != "2024-11-05" {
		t.Fatalf("initialize: %+v", init)
	}

	// tools/list: exactly list, get, exec.
	list := send("tools/list", nil)
	tools, _ := list["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("mcp tools = %d, want 3", len(tools))
	}

	// tools/call get: masked metadata only.
	get := send("tools/call", map[string]any{"name": "get", "arguments": map[string]any{"ref": "openai-prod"}})
	text := mcpText(t, get)
	if !strings.Contains(text, "sk-****abcd") || strings.Contains(text, fxSecret) {
		t.Fatalf("mcp get result wrong: %q", text)
	}

	// tools/call exec: same semantics as the CLI — child output
	// redacted, exit code returned.
	ex := send("tools/call", map[string]any{
		"name": "exec",
		"arguments": map[string]any{
			"argv": []any{helperBin, "print-env"},
			"env":  map[string]any{"K": "openai-prod"},
		},
	})
	text = mcpText(t, ex)
	if !strings.Contains(text, "K=<redacted:openai-prod>") || !strings.Contains(text, "exit_code: 0") {
		t.Fatalf("mcp exec result wrong: %q", text)
	}
	assertNoLeak(t, "mcp exec", text)

	// tools/call exec with an unknown ref: error result with exit code.
	bad := send("tools/call", map[string]any{
		"name": "exec",
		"arguments": map[string]any{
			"argv": []any{helperBin, "print-env"},
			"env":  map[string]any{"K": "no-such-ref"},
		},
	})
	text = mcpText(t, bad)
	if !strings.Contains(text, "exit_code: 11") {
		t.Fatalf("mcp exec unknown ref must map to exit 11: %q", text)
	}
	if res, ok := bad["result"].(map[string]any); !ok || res["isError"] != true {
		t.Fatalf("mcp exec unknown ref must be isError: %+v", bad)
	}

	// list never carries a value field.
	listCall := send("tools/call", map[string]any{"name": "list", "arguments": map[string]any{}})
	text = mcpText(t, listCall)
	if strings.Contains(text, `"value"`) || strings.Contains(text, fxSecret) {
		t.Fatalf("mcp list leaked secret material: %q", text)
	}
	assertNoLeak(t, "mcp list", text)
}

func mcpText(t *testing.T, resp map[string]any) string {
	t.Helper()
	res, ok := resp["result"].(map[string]any)
	if !ok {
		t.Fatalf("tools/call result missing: %+v", resp)
	}
	content, ok := res["content"].([]any)
	if !ok || len(content) == 0 {
		t.Fatalf("tools/call content missing: %+v", res)
	}
	first, _ := content[0].(map[string]any)
	text, _ := first["text"].(string)
	return text
}
