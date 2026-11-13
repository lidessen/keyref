//go:build e2e

package e2e

// The §14.8 delegation path, end to end against the real server:
//
//	source uploads → owner installs a signed delegation and backfills the
//	message wrap to a decider (D17) → CLI asks to consume → the decider
//	opens the message, passes every gate, gets a "pass" from the review
//	API and answers in the phone's exact shape → the CLI's child sees the
//	body.
//
// The negative legs (no delegation, review veto, sender outside the
// policy) are covered by the decider package's unit tests; this one proves
// the wiring — especially that a decider can only read what was explicitly
// backfilled to it.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/audit"
	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/decider"
	"github.com/lidessen/keyref/cli/internal/device"
)

// deciderDevice is a paired kind=decider device whose private keys the
// test keeps, so it can play the decider in-process.
type deciderDevice struct {
	deviceID string
	identity *device.Identity
	nonce    string
	token    string
}

// registerDecider pairs a kind=decider device (§14.8: same flow as a CLI,
// no grants).
func (o *owner) registerDecider(t *testing.T) *deciderDevice {
	t.Helper()
	hpkePub, hpkePriv, err := crypto.GenerateHPKEKeyPair(wire.KEMX25519)
	if err != nil {
		t.Fatal(err)
	}
	// The e2e helper binary signs with ed25519; reuse the source helper's
	// shape by generating the key pair here.
	signPubRaw, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub := wire.Blob(signPubRaw)
	d := &deciderDevice{
		deviceID: newID(t),
		identity: &device.Identity{HPKEPublic: hpkePub, HPKEPrivate: hpkePriv,
			SignPublic: signPub, SignPrivate: signPriv},
		nonce: newID(t),
	}
	label := "sms-decider"
	nonceRaw, err := hex.DecodeString(d.nonce)
	if err != nil {
		t.Fatal(err)
	}
	rtb, err := wire.BuildPairRegisterTranscript(nonceRaw, label)
	if err != nil {
		t.Fatal(err)
	}
	rsig, err := wire.SignEd25519(rtb, signPriv)
	if err != nil {
		t.Fatal(err)
	}
	if resp := apiDo(t, "", "POST", "/v1/pair/register", wire.PairRegisterRequest{
		Nonce: d.nonce, HPKEKEM: wire.KEMX25519, HPKEPublicKey: hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: signPub,
		ProposedName: label, Signature: rsig,
	}, nil); resp.StatusCode != http.StatusCreated {
		t.Fatalf("decider pair register: %d", resp.StatusCode)
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
			DeviceID: d.deviceID, Kind: wire.DeviceKindDecider,
			HPKEKEM: wire.KEMX25519, HPKEPublicKey: hpkePub,
			SignAlg: wire.SignAlgEd25519, SignPublicKey: signPub, Label: label,
		},
		Grants: nil, Signature: o.sign(ptb),
	}, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("decider pair complete: %d", resp.StatusCode)
	}
	d.token = o.openSessionFor(t, d.deviceID, func(tb []byte) ([]byte, error) {
		return wire.SignEd25519(tb, signPriv)
	})
	return d
}

// directoryDevice renders a paired device as a signed-directory record
// (§3.3). The decider trusts only what the owner signs here.
func (o *owner) ownerDirectoryDevice() wire.DirectoryDevice {
	return wire.DirectoryDevice{
		DeviceID: o.deviceID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
		HPKEKEM: wire.KEMP256, HPKEPublicKey: o.hpkePub,
		SignAlg: wire.SignAlgECDSAP256, SignPublicKey: o.signPub,
		GrantsDigest: wire.EmptyGrantsDigest(),
	}
}

func (o *owner) cliDirectoryDevice() wire.DirectoryDevice {
	digest := o.cliGrants
	if len(digest) == 0 {
		digest = wire.EmptyGrantsDigest()
	}
	return wire.DirectoryDevice{
		DeviceID: o.cliDeviceID, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: o.cliHPKE,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: o.cliSign,
		GrantsDigest: digest,
	}
}

func (src *sourceDevice) directoryDevice() wire.DirectoryDevice {
	return wire.DirectoryDevice{
		DeviceID: src.deviceID, Kind: wire.DeviceKindSource, Status: wire.DeviceStatusActive,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: src.hpkePub,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: src.signPriv.Public().(ed25519.PublicKey),
		GrantsDigest: wire.EmptyGrantsDigest(),
	}
}

func (d *deciderDevice) directoryDevice() wire.DirectoryDevice {
	return wire.DirectoryDevice{
		DeviceID: d.deviceID, Kind: wire.DeviceKindDecider, Status: wire.DeviceStatusActive,
		HPKEKEM: wire.KEMX25519, HPKEPublicKey: d.identity.HPKEPublic,
		SignAlg: wire.SignAlgEd25519, SignPublicKey: d.identity.SignPublic,
		GrantsDigest: wire.EmptyGrantsDigest(),
	}
}

// putDelegation installs (or revokes, with an empty policy) the owner's
// delegation (§6.31).
func (o *owner) putDelegation(t *testing.T, revision uint64, policy wire.DelegationPolicy) {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := wire.BuildDelegationTranscript(wire.DelegationTranscript{
		VaultID: o.vaultID, DelegationRevision: revision, PolicyJSON: string(raw)})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := wire.SignOwnerECDSA(tb, o.signPriv)
	if err != nil {
		t.Fatal(err)
	}
	if resp := o.do(t, "PUT", "/v1/delegation", wire.DelegationPutRequest{
		DelegationRevision: revision, DelegationSigned: tb, Signature: sig,
	}, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("put delegation: %d", resp.StatusCode)
	}
}

// backfillMessage re-wraps one message key to the decider (§6.30, D17).
func (o *owner) backfillMessage(t *testing.T, messageID string, d *deciderDevice) {
	t.Helper()
	var list wire.MessageListResponse
	if resp := o.do(t, "GET", "/v1/messages?since=0", nil, &list); resp.StatusCode != 200 {
		t.Fatalf("list messages: %d", resp.StatusCode)
	}
	var row *wire.MessageRow
	for i := range list.Messages {
		if list.Messages[i].MessageID == messageID {
			row = &list.Messages[i]
			break
		}
	}
	if row == nil {
		t.Fatal("message row not found for backfill")
	}
	// The owner opens its own record to get the message key.
	key, err := crypto.OpenMessageKey(row.Envelope, o.vaultID, o.deviceID,
		func(info, enc, ct []byte) ([]byte, error) {
			return crypto.UnwrapKey(wire.KEMP256, o.hpkePriv, info, enc, ct)
		})
	if err != nil {
		t.Fatalf("owner open message key: %v", err)
	}
	defer crypto.WipeKey(key)
	enc, wrapped, err := crypto.SealMessageKey(o.vaultID, d.deviceID, d.identity.HPKEPublic, key)
	if err != nil {
		t.Fatalf("seal to decider: %v", err)
	}
	if resp := o.do(t, "PUT", "/v1/messages/"+messageID+"/wraps", wire.MessageWrapsRequest{
		Wraps: []wire.MessageWrap{{
			DeviceID: d.deviceID, HPKEEnc: enc, WrappedKey: wrapped,
		}},
	}, nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("backfill wraps: %d", resp.StatusCode)
	}
}

// TestDeciderAutoApproves is the positive delegation path.
func TestDeciderAutoApproves(t *testing.T) {
	o := setupPairedVault(t)
	src := o.registerSource(t)
	messageID := o.uploadSMS(t, src)

	dec := o.registerDecider(t)
	// The CLI verifies the decider's decision against the owner-signed
	// directory (protocol v2 B), so the decider and the requesting CLI
	// have to be in it before the CLI syncs.
	o.publishDirectory(t, 2, []wire.DirectoryDevice{
		o.ownerDirectoryDevice(), o.cliDirectoryDevice(),
		src.directoryDevice(), dec.directoryDevice(),
	})
	if sync := runCLI(t, "sync"); sync.code != 0 {
		t.Fatalf("sync after directory: %d: %s", sync.code, sync.stderr)
	}
	o.putDelegation(t, 1, wire.DelegationPolicy{
		V: 1, Senders: []string{"10086"}, MaxAgeMin: 5, PerCLIHourly: 10, PerCLIDaily: 50,
	})
	o.backfillMessage(t, messageID, dec)

	// A review API that always passes.
	var reviewed decider.ReviewInput
	review := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Untrusted struct {
				Body string `json:"body"`
			} `json:"untrusted"`
			Structured struct {
				Sender string `json:"sender"`
			} `json:"structured"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		reviewed.Body = req.Untrusted.Body
		reviewed.Sender = req.Structured.Sender
		_, _ = w.Write([]byte(`{"verdict":"pass","reason":"within policy"}`))
	}))
	defer review.Close()

	// The CLI asks to consume; it will wait for the decider's answer.
	type result struct {
		ex  cliRun
		err error
	}
	done := make(chan result, 1)
	go func() {
		r, err := execCLI("exec", "--env", "K=sms:"+messageID, "--", helperBin, "print-env")
		done <- result{ex: r, err: err}
	}()

	// Wait for the pending approval, then let the decider answer it.
	waitForMessageApproval(t, o, messageID)
	// The decider trusts the owner-signed directory (protocol v2 A): the
	// CLI device that asked to consume the SMS must be an active entry
	// there, otherwise the server could have put its own key in the row.
	dirTB, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID: o.vaultID, DirectoryRevision: 2,
		Devices: []wire.DirectoryDevice{
			{DeviceID: o.deviceID, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMP256, HPKEPublicKey: o.hpkePub,
				SignAlg: wire.SignAlgECDSAP256, SignPublicKey: o.signPub,
				GrantsDigest: wire.EmptyGrantsDigest()},
			{DeviceID: o.cliDeviceID, Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMX25519, HPKEPublicKey: o.cliHPKE,
				SignAlg: wire.SignAlgEd25519, SignPublicKey: o.cliSign,
				GrantsDigest: wire.EmptyGrantsDigest()},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dirSig := o.sign(dirTB)
	if err := wire.VerifyOwnerSignature(dirTB, dirSig, o.signPub); err != nil {
		t.Fatalf("directory signature: %v", err)
	}
	devices, err := audit.ParseDirectory(dirTB)
	if err != nil {
		t.Fatal(err)
	}

	d, err := decider.New(decider.Config{
		VaultID: o.vaultID, DeviceID: dec.deviceID, Identity: dec.identity,
		Client:             client.New(serverURL, func() (string, error) { return dec.token, nil }),
		OwnerSignPublicKey: o.signPub,
		Reviewer:           &decider.HTTPReviewer{URL: review.URL},
		Devices:            func() ([]audit.DeviceRecord, error) { return devices, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		n, err := d.RunOnce(context.Background())
		if err != nil {
			t.Fatalf("decider run: %v", err)
		}
		if n > 0 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}

	res := <-done
	if res.err != nil {
		t.Fatalf("run CLI: %v", res.err)
	}
	if res.ex.code != 0 {
		t.Fatalf("sms exec exit %d\nstdout: %s\nstderr: %s",
			res.ex.code, res.ex.stdout, res.ex.stderr)
	}
	if !strings.Contains(res.ex.stdout, "<redacted:sms:"+messageID+">") {
		t.Fatalf("output not redacted:\n%s", res.ex.stdout)
	}
	// The reviewer saw the SMS body in its untrusted block, not as a
	// top-level instruction field.
	if reviewed.Body != smsBody || reviewed.Sender != "10086" {
		t.Fatalf("review input: %+v", reviewed)
	}
}

// waitForMessageApproval polls the owner's approval queue until the CLI's
// consumption request for this message is pending.
func waitForMessageApproval(t *testing.T, o *owner, messageID string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		var list wire.ApprovalListResponse
		if resp := o.do(t, "GET", "/v1/approvals?status=pending", nil, &list); resp.StatusCode == 200 {
			for _, row := range list.Approvals {
				if row.MessageID == messageID {
					return
				}
			}
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatal("the CLI's consumption request never became pending")
}
