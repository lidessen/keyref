//go:build e2e

package e2e

// The v0.8 SMS-consumption flow (design §14.2–§14.5) end to end against
// the real server and the real CLI binary:
//
//	source uploads an SMS → the CLI resolves `--env CODE=sms:<id>` through
//	its own approval round → the owner approves with the message
//	PLAINTEXT JSON (D18: the message key never reaches the CLI) → the
//	child sees the body, redacted in its output.
//
// This is the contract the CLI-side `sms:` wiring must keep: message refs
// carry no item policy, can only be injected through an injection value,
// and exit 11 when the message is unknown, expired or already consumed.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"
)

const smsBody = "【XX银行】您的验证码 482913，5 分钟内有效。"

// sealEnvelope builds a real §3.9 envelope: one record per recipient plus
// an AES-GCM body blob over the §3.9 plaintext JSON.
func sealEnvelope(t *testing.T, vaultID, sourceDeviceID string,
	recipients map[string][]byte, plaintext []byte) []byte {
	t.Helper()
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	out := []byte{byte(len(recipients))}
	for deviceID, pub := range recipients {
		rec, err := crypto.SealMessageRecord(vaultID, deviceID, pub, key)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rec...)
	}
	aad, err := crypto.MessageBodyAAD(vaultID, sourceDeviceID)
	if err != nil {
		t.Fatal(err)
	}
	blob, err := crypto.SealBlob(key, aad, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	return append(out, blob...)
}

// approvalRequestMessage mirrors the §6.19 request plaintext for a
// message subject (protocol D16: item_id is absent, message_id present).
type approvalRequestMessage struct {
	V                  int      `json:"v"`
	CLIDeviceID        string   `json:"cli_device_id"`
	MessageID          string   `json:"message_id"`
	Argv               []string `json:"argv"`
	Refs               []string `json:"refs"`
	Injection          string   `json:"injection"`
	Hosts              []string `json:"hosts"`
	Reply              []string `json:"reply"`
	EphemeralKEM       string   `json:"ephemeral_kem"`
	EphemeralPublicKey []byte   `json:"ephemeral_public_key"`
	CreatedAt          int64    `json:"created_at"`
}

// sourceDevice is a paired kind=source device: upload-only, no grants.
type sourceDevice struct {
	deviceID string
	signPriv ed25519.PrivateKey
	hpkePub  []byte // the key the owner seals message keys to
	nonce    string
	token    string
}

// apiDo is o.do with an explicit bearer token (the source device has its
// own session, separate from the owner's).
func apiDo(t *testing.T, token, method, path string, body, out any) *http.Response {
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
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			t.Fatalf("%s %s: decode %s: %v", method, path, raw, err)
		}
	}
	return resp
}

// registerSource pairs a kind=source device through the owner (§14.2:
// same §8.1 mechanism, empty grant set).
func (o *owner) registerSource(t *testing.T) *sourceDevice {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hpkePub := make([]byte, wire.SizeX25519Key)
	if _, err := rand.Read(hpkePub); err != nil {
		t.Fatal(err)
	}
	d := &sourceDevice{deviceID: newID(t), signPriv: priv, hpkePub: hpkePub, nonce: newID(t)}

	nonceRaw, err := hex.DecodeString(d.nonce)
	if err != nil {
		t.Fatal(err)
	}
	label := "sms-source"
	signPub := wire.Blob(priv.Public().(ed25519.PublicKey))
	rtb, err := wire.BuildPairRegisterTranscript(nonceRaw, label)
	if err != nil {
		t.Fatal(err)
	}
	rsig, err := wire.SignEd25519(rtb, d.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	if resp := apiDo(t, "", "POST", "/v1/pair/register", wire.PairRegisterRequest{
		Nonce: d.nonce, HPKEKEM: wire.KEMX25519, HPKEPublicKey: hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: signPub,
		ProposedName: label, Signature: rsig,
	}, nil); resp.StatusCode != http.StatusCreated {
		t.Fatalf("source pair register: %d", resp.StatusCode)
	}

	ptb, err := wire.BuildPairTranscript(wire.PairTranscript{
		VaultID: o.vaultID, OwnerSignPublicKey: o.signPub,
		Nonce: d.nonce, DeviceID: d.deviceID,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: signPub,
		Label: label, Grants: nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp := o.do(t, "POST", "/v1/pair/complete", wire.PairCompleteRequest{
		Nonce: d.nonce,
		Device: wire.DeviceInput{
			DeviceID: d.deviceID, Kind: wire.DeviceKindSource,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: hpkePub,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: signPub,
			Label: label,
		},
		Grants: nil, Signature: o.sign(ptb),
	}, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("source pair complete: %d", resp.StatusCode)
	}

	d.token = o.openSessionFor(t, d.deviceID, func(tb []byte) ([]byte, error) {
		return wire.SignEd25519(tb, d.signPriv)
	})
	return d
}

// openSessionFor runs the challenge→token flow for a non-owner device
// (source / decider) and returns its bearer token.
func (o *owner) openSessionFor(t *testing.T, deviceID string,
	sign func(transcript []byte) ([]byte, error)) string {
	t.Helper()
	var chal wire.SessionChallengeResponse
	if resp := apiDo(t, "", "POST", "/v1/session", wire.SessionRequest{DeviceID: deviceID}, &chal); resp.StatusCode != 200 {
		t.Fatalf("session step 1 (%s): %d", deviceID, resp.StatusCode)
	}
	stb, err := wire.BuildSessionTranscript(deviceID, chal.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(stb)
	if err != nil {
		t.Fatal(err)
	}
	chB, sigB := wire.Blob(chal.Challenge), wire.Blob(sig)
	var sess wire.SessionResponse
	if resp := apiDo(t, "", "POST", "/v1/session", wire.SessionRequest{
		DeviceID: deviceID, Challenge: &chB, Signature: &sigB,
	}, &sess); resp.StatusCode != 200 || sess.Token == "" {
		t.Fatalf("session step 2 (%s): %d", deviceID, resp.StatusCode)
	}
	return sess.Token
}

// uploadSMS stores one message and returns its server-assigned id. The
// envelope only has to satisfy the §3.9 structure — the server validates
// the upload signature, never the包裹 contents (nothing on the server can
// open them).
func (o *owner) uploadSMS(t *testing.T, src *sourceDevice) string {
	t.Helper()
	receivedAt := time.Now().UnixMilli()
	plaintext, err := json.Marshal(map[string]any{
		"v": 1, "sender": "10086", "body": smsBody, "sim": "备用卡1",
		"received_at": receivedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	envelope := sealEnvelope(t, o.vaultID, src.deviceID,
		map[string][]byte{o.deviceID: o.hpkePub}, plaintext)
	tb, err := wire.BuildMessageUploadTranscript(wire.MessageUploadTranscript{
		VaultID: o.vaultID, SourceDeviceID: src.deviceID,
		ReceivedAt: uint64(receivedAt), Envelope: envelope,
	})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignEd25519(tb, src.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	var created wire.MessageCreateResponse
	resp := apiDo(t, src.token, "POST", "/v1/messages", wire.MessageCreateRequest{
		Envelope: envelope, RequestSignature: sig, ReceivedAt: receivedAt,
	}, &created)
	if resp.StatusCode != http.StatusCreated {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("message upload: %d %s", resp.StatusCode, raw)
	}
	if created.MessageID == "" {
		t.Fatal("message upload returned no id")
	}
	return created.MessageID
}

// serveOneMessageApproval plays the phone for the message approval:
// verify the CLI signature, decrypt the request, assert it carries the
// message id, then approve with the message PLAINTEXT JSON sealed to the
// request's ephemeral key (D18 — not the message key).
func (o *owner) serveOneMessageApproval(t *testing.T, messageID, body string) *sync.WaitGroup {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			var list wire.ApprovalListResponse
			if resp := o.do(t, "GET", "/v1/approvals?status=pending", nil, &list); resp.StatusCode != 200 {
				time.Sleep(300 * time.Millisecond)
				continue
			}
			for _, row := range list.Approvals {
				if row.MessageID != messageID {
					continue
				}
				o.answerMessageApproval(t, &row, body)
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
		t.Error("message approval request never appeared in the owner queue")
	}()
	return &wg
}

func (o *owner) answerMessageApproval(t *testing.T, row *wire.ApprovalRow, body string) {
	t.Helper()
	o.verifyApprovalRequest(t, row)
	if len(row.ItemID) != 0 {
		t.Fatalf("message approval carried an item id: %q", row.ItemID)
	}
	if len(row.CLIEphemeralPublicKey) != wire.SizeX25519Key {
		t.Fatalf("message approval must expose the CLI ephemeral key (D16), got %d bytes",
			len(row.CLIEphemeralPublicKey))
	}
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
	var rq approvalRequestMessage
	dec := json.NewDecoder(bytes.NewReader(pt))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&rq); err != nil {
		t.Fatalf("owner: message approval transcript decode: %v\npayload: %.200q", err, pt)
	}
	if rq.MessageID != row.MessageID || rq.CLIDeviceID != o.cliDeviceID {
		t.Fatalf("message approval transcript identity: %+v", rq)
	}
	if !strings.Contains(rq.Injection, "env") {
		t.Fatalf("message approval transcript injection: %q", rq.Injection)
	}
	if rq.EphemeralKEM != wire.KEMX25519 || len(rq.EphemeralPublicKey) != 32 {
		t.Fatalf("message approval transcript ephemeral key: %s %d", rq.EphemeralKEM, len(rq.EphemeralPublicKey))
	}

	// The decision: the §3.9 message plaintext JSON, sealed under the
	// one-time-message-key binding (design §14.5, protocol §3.7).
	payload, err := json.Marshal(map[string]any{
		"v": 1, "sender": "10086", "body": body, "sim": "备用卡1",
		"received_at": time.Now().UnixMilli(),
	})
	if err != nil {
		t.Fatal(err)
	}
	wrapInfo, err := crypto.OneTimeMessageKeyInfo(o.vaultID, o.cliDeviceID, row.MessageID,
		row.ApprovalID, row.RequestCiphertext)
	if err != nil {
		t.Fatal(err)
	}
	oneEnc, wrapped, err := crypto.WrapKey(wire.KEMX25519, rq.EphemeralPublicKey, wrapInfo, payload)
	if err != nil {
		t.Fatal(err)
	}
	decision := wire.ApprovalDecisionRequest{
		Decision: wire.ApprovalStatusApproved, OneTimeEnc: oneEnc, OneTimeWrappedKey: wrapped,
	}
	o.signApprovalDecision(t, row, &decision)
	if resp := o.do(t, "POST", "/v1/approvals/"+row.ApprovalID+"/decision",
		decision, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("owner message decision: %d", resp.StatusCode)
	}
	o.lastApprovalID = row.ApprovalID
}

// TestSMSConsumptionFlow is the positive path: the body reaches the child
// through --env and is redacted in the child's output.
func TestSMSConsumptionFlow(t *testing.T) {
	o := setupPairedVault(t)
	src := o.registerSource(t)
	messageID := o.uploadSMS(t, src)
	ref := "sms:" + messageID

	done := o.serveOneMessageApproval(t, messageID, smsBody)
	ex := runCLI(t, "exec", "--env", "K="+ref, "--", helperBin, "print-env")
	done.Wait()
	if ex.code != 0 {
		t.Fatalf("sms exec exit %d\nstdout: %s\nstderr: %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stdout, "K=<redacted:"+ref+">") {
		t.Fatalf("sms exec output not redacted:\n%s\nstderr: %s", ex.stdout, ex.stderr)
	}
	for _, out := range []string{ex.stdout, ex.stderr} {
		if strings.Contains(out, smsBody) || strings.Contains(out, "482913") {
			t.Fatalf("sms body leaked: %.200q", out)
		}
	}

	// One-shot: the decision was consumed by this exec.
	assertApprovalStatus(t, o, o.lastApprovalID, wire.ApprovalStatusConsumed)
}

// TestSMSUnknownMessageExits11 covers the "unknown / expired / consumed"
// leg of §14.5: the server answers not_found and the CLI must exit 11
// without ever asking the phone.
func TestSMSUnknownMessageExits11(t *testing.T) {
	setupPairedVault(t) // paired CLI is all this test needs
	ref := "sms:" + newID(t)
	ex := runCLI(t, "exec", "--env", "K="+ref, "--", helperBin, "print-env")
	if ex.code != 11 {
		t.Fatalf("unknown sms ref exit %d, want 11\nstdout: %s\nstderr: %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stderr, "unknown, expired or already consumed") {
		t.Fatalf("unexpected stderr: %s", ex.stderr)
	}
}

// TestSMSRejectsArgvPlaceholder enforces §14.5's "no argv placeholder
// form": an sms: ref may only reach the child through an injection value.
func TestSMSRejectsArgvPlaceholder(t *testing.T) {
	setupPairedVault(t) // paired CLI is all this test needs
	ref := "sms:" + newID(t)
	ex := runCLI(t, "exec", "--allow-argv", "--", helperBin, "print-env", "{{keyref:"+ref+"}}")
	if ex.code != 10 {
		t.Fatalf("sms argv placeholder exit %d, want 10\nstdout: %s\nstderr: %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stderr, "sms: refs cannot be argv placeholders") {
		t.Fatalf("unexpected stderr: %s", ex.stderr)
	}
}

// TestSMSMalformedRefIsRejected keeps the syntax strict: sms: requires a
// full 32-hex message id.
func TestSMSMalformedRefIsRejected(t *testing.T) {
	setupPairedVault(t) // paired CLI is all this test needs
	ex := runCLI(t, "exec", "--env", "K=sms:not-an-id", "--", helperBin, "print-env")
	if ex.code != 10 {
		t.Fatalf("malformed sms ref exit %d, want 10\nstderr: %s", ex.code, ex.stderr)
	}
	if !strings.Contains(ex.stderr, "malformed sms ref") {
		t.Fatalf("unexpected stderr: %s", ex.stderr)
	}
}

// TestSMSListAndGetDoNotKnowIt: `list`/`get` never resolve message refs
// (§14.5 — the syntax only exists inside exec's injection position).
func TestSMSListAndGetDoNotKnowIt(t *testing.T) {
	setupPairedVault(t) // paired CLI is all this test needs
	// `get` must not resolve a message ref: the syntax only exists inside
	// exec's injection position. (`list` takes no ref at all.)
	ex := runCLI(t, "get", "sms:"+newID(t))
	if ex.code == 0 {
		t.Fatalf("get accepted an sms: ref: %s", ex.stdout)
	}
}

// TestSMSApprovalDeniedExits13: a refused consumption is exit 13, not 11.
func TestSMSApprovalDeniedExits13(t *testing.T) {
	o := setupPairedVault(t)
	src := o.registerSource(t)
	messageID := o.uploadSMS(t, src)

	done := o.serveOneMessageDenial(t, messageID)
	ex := runCLI(t, "exec", "--env", "K=sms:"+messageID, "--", helperBin, "print-env")
	done.Wait()
	if ex.code != 13 {
		t.Fatalf("denied sms exec exit %d, want 13\nstdout: %s\nstderr: %s", ex.code, ex.stdout, ex.stderr)
	}
}

// serveOneMessageDenial answers the message approval with a denial.
func (o *owner) serveOneMessageDenial(t *testing.T, messageID string) *sync.WaitGroup {
	t.Helper()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		deadline := time.Now().Add(60 * time.Second)
		for time.Now().Before(deadline) {
			var list wire.ApprovalListResponse
			if resp := o.do(t, "GET", "/v1/approvals?status=pending", nil, &list); resp.StatusCode != 200 {
				time.Sleep(300 * time.Millisecond)
				continue
			}
			for _, row := range list.Approvals {
				if row.MessageID != messageID {
					continue
				}
				denial := wire.ApprovalDecisionRequest{Decision: wire.ApprovalStatusDenied}
				o.signApprovalDecision(t, &row, &denial)
				if resp := o.do(t, "POST", "/v1/approvals/"+row.ApprovalID+"/decision",
					denial, nil); resp.StatusCode != http.StatusNoContent {
					t.Errorf("owner denial decision: %d", resp.StatusCode)
				}
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
		t.Error("message approval request never appeared in the owner queue")
	}()
	return &wg
}
