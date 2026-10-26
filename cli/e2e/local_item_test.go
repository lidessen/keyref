//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"
)

// The v0.7 local-item additions (design §6.6): a meta-only item whose
// secret never reaches the server. Every exec needs an approval, and the
// approved decision carries the secret value itself — the owner takes it
// from its own local copy, HPKE-sealed to the CLI's ephemeral key —
// instead of a wrapped item key. The CLI unwraps it into guarded memory,
// injects, and wipes: the second exec must ask again.

const (
	itemLocal   = "f00d0000f00d0000f00d0000f00d0000"
	refLocal    = "totp-seed"
	maskedLocal = "abcd****wxyz"
	secretLocal = "sk-LOCAL-ONLY-fixture-31415926535"
)

// putLocalItem uploads a meta-only item (§6.10 with an empty
// secret_ciphertext = SQL NULL): the secret is sealed with an item key
// that stays in the owner's local copy — the server row has neither a
// secret nor a vault-wrapped item key.
func (o *owner) putLocalItem(t *testing.T, itemID, ref, masked, secretValue string) {
	t.Helper()
	metaKey := make([]byte, 32)
	itemKey := make([]byte, 32)
	if _, err := rand.Read(metaKey); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(itemKey); err != nil {
		t.Fatal(err)
	}
	meta := map[string]any{
		"v": 1, "ref": ref, "name": ref + " name", "description": "local fixture",
		"type": "totp_seed", "masked": masked, "injectable": true,
		"policy": map[string]any{
			"sensitivity": "approval", "commandPolicy": "deny-shells",
			"allowCommands": []string{"helper"}, "allowedHosts": []string{"api.example.com"},
			"allowArgv": false,
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
	// The secret NEVER leaves the owner: sealed for the local copy only.
	secretCT, err := crypto.SealBlob(itemKey, secretAAD, secretJSON)
	if err != nil {
		t.Fatal(err)
	}
	vwmAAD, _ := crypto.VaultWrappedMetaKeyAAD(o.vaultID, itemID)
	vmk := make([]byte, 32)
	vwm, err := crypto.SealBlob(vmk, vwmAAD, metaKey)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := wire.BuildItemTranscript(wire.ItemTranscript{
		VaultID: o.vaultID, ItemID: itemID, Revision: 1,
		MetaCiphertext:      metaCT,
		SecretCiphertext:    nil,
		VaultWrappedMetaKey: vwm,
		VaultWrappedItemKey: nil,
		WriterDeviceID:      o.deviceID,
	})
	if err != nil {
		t.Fatal(err)
	}
	req := wire.PutItemRequest{
		Revision: 1, MetaCiphertext: metaCT,
		VaultWrappedMetaKey: vwm,
		WriterDeviceID:      o.deviceID, Signature: o.sign(tb),
	}
	var out wire.PutItemResponse
	if resp := o.do(t, "PUT", "/v1/items/"+itemID, req, &out); resp.StatusCode != 200 {
		t.Fatalf("put local item %s: %d", ref, resp.StatusCode)
	}
	o.metaKeys[itemID] = metaKey
	o.itemKeys[itemID] = itemKey
	o.localSecrets[itemID] = secretCT
}

// localSecretValue opens the owner's LOCAL copy of a local item — the
// phone-side decryption the approval flow builds on (the stored
// ciphertext is item-key sealed; only the owner can open it).
func (o *owner) localSecretValue(t *testing.T, itemID string) []byte {
	t.Helper()
	secretAAD, _ := crypto.SecretAAD(o.vaultID, itemID)
	pt, err := crypto.OpenBlob(o.itemKeys[itemID], secretAAD, o.localSecrets[itemID])
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(pt, &doc); err != nil {
		t.Fatal(err)
	}
	return []byte(doc.Value)
}

// serveOneApprovalFor is serveOneApproval restricted to one item id; the
// implementation lives next to answerApproval in approval_test.go.

func TestLocalItemExecFlow(t *testing.T) {
	vaultID := newID(t)
	owner := newOwner(t, vaultID)
	owner.createVault(t)
	owner.session(t)
	owner.putItem(t, itemOpenAI, "openai-prod", "sk-****abcd", fxSecret)
	owner.putLocalItem(t, itemLocal, refLocal, maskedLocal, secretLocal)

	pp := startPair(t)
	nonceHex, payload := pp.waitPayloadLine(t)
	// Pairing grants the openai item only; the local item gets its view
	// grant afterwards (PUT /v1/grants, view-only by contract).
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
	owner.grantLater(t, itemLocal, wire.GrantKindView)
	if sync := runCLI(t, "sync"); sync.code != 0 {
		t.Fatalf("sync exit %d: %s", sync.code, sync.stderr)
	}

	// list/get see the local item's meta (masked view only).
	list := runCLI(t, "list")
	if list.code != 0 || !strings.Contains(list.stdout, refLocal) || !strings.Contains(list.stdout, maskedLocal) {
		t.Fatalf("list missing local item meta:\n%s", list.stdout)
	}
	assertNoLeak(t, "list local", list.stdout, list.stderr)
	get := runCLI(t, "get", refLocal)
	if get.code != 0 || !strings.Contains(get.stdout, "masked: "+maskedLocal) ||
		!strings.Contains(get.stdout, "sensitivity: approval") {
		t.Fatalf("get local item: %d\n%s", get.code, get.stdout)
	}
	assertNoLeak(t, "get local", get.stdout, get.stderr)

	// First exec: the owner approves by delivering the secret value
	// itself; the CLI injects it and redacts the output.
	done := owner.serveOneApprovalFor(t, itemLocal, decideApprove, nil)
	ex := runCLI(t, "exec", "--env", "K="+refLocal, "--", helperBin, "print-env")
	done.Wait()
	if ex.code != 0 {
		t.Fatalf("local exec exit %d: %s %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stdout, "K=<redacted:"+refLocal+">") {
		t.Fatalf("local exec output not redacted:\n%s", ex.stdout)
	}
	assertNoLeak(t, "local exec", ex.stdout, ex.stderr)
	if owner.lastApprovalID == "" {
		t.Fatal("no approval id recorded")
	}
	assertApprovalStatus(t, owner, owner.lastApprovalID, wire.ApprovalStatusConsumed)

	// Deny path: the owner refuses; exit 13 quickly and without leaking.
	// (Run before the no-responder case so no stale pending approval is
	// left for a later responder to trip over.)
	start := time.Now()
	doneDeny := owner.serveOneApprovalFor(t, itemLocal, decideDeny, nil)
	ex3 := runCLI(t, "exec", "--env", "K="+refLocal, "--", helperBin, "print-env")
	doneDeny.Wait()
	if ex3.code != 13 {
		t.Fatalf("denied local exec exit %d, want 13 (stderr: %s)", ex3.code, ex3.stderr)
	}
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("denial took %s", elapsed)
	}
	assertNoLeak(t, "denied local exec", ex3.stdout, ex3.stderr)

	// 用后即清, observable: the next exec gets no responder at all, so
	// it must time out — a cached secret or a stored item key would let
	// it through (design §6.6: 永远没有 use 授予；每次 exec 审批).
	ex2 := runCLI(t, "exec", "--timeout", "3", "--env", "K="+refLocal, "--", helperBin, "print-env")
	if ex2.code != 13 {
		t.Fatalf("second local exec must need a fresh approval (exit 13), got %d: %s %s", ex2.code, ex2.stdout, ex2.stderr)
	}
	assertNoLeak(t, "second local exec", ex2.stdout, ex2.stderr)

	// A local item NEVER takes a use grant: the server enforces the
	// mutual exclusion (design §6.6) even though the owner here is
	// honest software.
	if _, ok := owner.metaKeys[itemLocal]; !ok {
		t.Fatal("fixture broken")
	}
}

// TestLocalItemMCPExec proves the MCP exec tool serves local items
// through the same core: the approved secret is injected, redacted and
// wiped, with the approval decision carrying the secret value.
func TestLocalItemMCPExec(t *testing.T) {
	vaultID := newID(t)
	owner := newOwner(t, vaultID)
	owner.createVault(t)
	owner.session(t)
	owner.putItem(t, itemOpenAI, "openai-prod", "sk-****abcd", fxSecret)
	owner.putLocalItem(t, itemLocal, refLocal, maskedLocal, secretLocal)
	pp := startPair(t)
	nonceHex, payload := pp.waitPayloadLine(t)
	owner.completePairing(t, nonceHex, payload)
	select {
	case err := <-pp.done:
		if err != nil {
			t.Fatalf("keyref pair failed: %v", err)
		}
	case <-time.After(30 * time.Second):
		_ = pp.cmd.Process.Kill()
		t.Fatal("keyref pair did not finish")
	}
	owner.grantLater(t, itemLocal, wire.GrantKindView)
	if sync := runCLI(t, "sync"); sync.code != 0 {
		t.Fatalf("sync exit %d: %s", sync.code, sync.stderr)
	}

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
	if init := send("initialize", map[string]any{"protocolVersion": "2024-11-05"}); init["result"] == nil {
		t.Fatalf("mcp initialize: %+v", init)
	}

	done := owner.serveOneApprovalFor(t, itemLocal, decideApprove, nil)
	ex := send("tools/call", map[string]any{
		"name": "exec",
		"arguments": map[string]any{
			"argv": []any{helperBin, "print-env"},
			"env":  map[string]any{"K": refLocal},
		},
	})
	done.Wait()
	text := mcpText(t, ex)
	if !strings.Contains(text, "K=<redacted:"+refLocal+">") || !strings.Contains(text, "exit_code: 0") {
		t.Fatalf("mcp local exec result wrong: %q", text)
	}
	assertNoLeak(t, "mcp local exec", text)
}
