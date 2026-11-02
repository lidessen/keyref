package audit

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/testowner"
)

func buildDirectory(t *testing.T, owner *testowner.Owner, cliDev, cliHPKEPub, cliSignPub []byte) []byte {
	t.Helper()
	signed, err := wire.BuildDirectoryTranscript(wire.DirectoryTranscript{
		VaultID:           owner.VaultID,
		DirectoryRevision: 3,
		Devices: []wire.DirectoryDevice{
			{
				DeviceID: owner.OwnerDev, Kind: wire.DeviceKindIOS, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMP256, HPKEPublicKey: owner.HPKEPub,
				SignAlg: wire.SignAlgECDSAP256, SignPublicKey: owner.SignPub,
				RenewalSignPublicKey: bytes.Repeat([]byte{7}, 32),
				GrantsDigest:         bytes.Repeat([]byte{0}, 32),
			},
			{
				DeviceID: string(cliDev), Kind: wire.DeviceKindCLI, Status: wire.DeviceStatusActive,
				HPKEKEM: wire.KEMX25519, HPKEPublicKey: cliHPKEPub,
				SignAlg: wire.SignAlgEd25519, SignPublicKey: cliSignPub,
				GrantsDigest: bytes.Repeat([]byte{1}, 32),
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return signed
}

func TestOwnersFromDirectory(t *testing.T) {
	owner := testowner.New(t, "00112233445566778899aabbccddeeff", "99998888777766665555444433332222")
	cliDev := []byte("0123456789abcdef0123456789abcdef")
	cliHPKE := bytes.Repeat([]byte{3}, 32)
	cliSign := bytes.Repeat([]byte{4}, 32)

	signed := buildDirectory(t, owner, cliDev, cliHPKE, cliSign)
	owners, err := OwnersFromDirectory(signed)
	if err != nil {
		t.Fatal(err)
	}
	if len(owners) != 1 {
		t.Fatalf("owners %d, want 1 (ios active only)", len(owners))
	}
	if owners[0].DeviceID != owner.OwnerDev || owners[0].HPKEKEM != wire.KEMP256 ||
		!bytes.Equal(owners[0].HPKEPublicKey, owner.HPKEPub) {
		t.Fatalf("owner record %+v", owners[0])
	}

	// Structural tampering must fail the rebuild check.
	truncated := signed[:len(signed)-1]
	if _, err := OwnersFromDirectory(truncated); err == nil {
		t.Fatal("truncated directory parsed")
	}
	spliced := append([]byte(nil), signed[:20]...)
	spliced = append(spliced, signed[25:]...)
	if _, err := OwnersFromDirectory(spliced); err == nil {
		t.Fatal("spliced directory parsed")
	}
	// NOTE: a same-length content flip (e.g. inside a digest) parses
	// fine — the parser validates structure, not authenticity.
	// Authenticity comes from the owner signature the caller verified
	// on ingest (sync/pair) and re-verified before use (cmd exec).
}

func TestSealEnvelopeRoundtrip(t *testing.T) {
	owner := testowner.New(t, "00112233445566778899aabbccddeeff", "99998888777766665555444433332222")
	reporter := "0123456789abcdef0123456789abcdef"
	recip := OwnerRecipient{DeviceID: owner.OwnerDev, HPKEKEM: wire.KEMP256, HPKEPublicKey: owner.HPKEPub}

	evt := Event{Time: 1, DeviceID: reporter, Refs: []string{"openai-prod"},
		Injection: []string{"env"}, Argv: []string{"curl", "{{keyref:openai-prod}}"},
		PolicyResult: "allow", ChildExit: 0, Redactions: 2}
	evtJSON, err := json.Marshal(evt)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := SealEnvelope(evtJSON, owner.VaultID, reporter, []OwnerRecipient{recip})
	if err != nil {
		t.Fatal(err)
	}

	// Decode per §6.23: u8 wrap_count ‖ { u16be enc_len ‖ enc ‖ 48B } ‖ blob.
	if envelope[0] != 1 {
		t.Fatalf("wrap_count %d", envelope[0])
	}
	encLen := int(binary.BigEndian.Uint16(envelope[1:3]))
	enc := envelope[3 : 3+encLen]
	wrapped := envelope[3+encLen : 3+encLen+48]
	blob := envelope[3+encLen+48:]

	info, err := crypto.Info(crypto.PurposeAuditEventKey, owner.VaultID, owner.OwnerDev)
	if err != nil {
		t.Fatal(err)
	}
	eventKey, err := crypto.UnwrapKey(wire.KEMP256, owner.HPKEPriv, info, enc, wrapped)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := crypto.AuditAAD(owner.VaultID, reporter)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := crypto.OpenBlob(eventKey, aad, blob)
	if err != nil {
		t.Fatal(err)
	}
	var got Event
	if err := json.Unmarshal(pt, &got); err != nil {
		t.Fatal(err)
	}
	if got.Refs[0] != "openai-prod" || got.Argv[1] != "{{keyref:openai-prod}}" || got.Redactions != 2 {
		t.Fatalf("event roundtrip %+v", got)
	}
	if bytes.Contains(pt, []byte("sk-")) {
		t.Fatal("event plaintext must never carry secret values")
	}
}

// TestEventDecisionDeviceID pins the optional decision_device_id of the
// audit plaintext (design v0.8 §14.5/§14.8, protocol §6.23/D19): the key
// carries the deciding device when an approval decided the run and is
// omitted entirely otherwise. The consumed subject stays in refs as
// sms:<id> — no second message-id field.
func TestEventDecisionDeviceID(t *testing.T) {
	decider := "99998888777766665555444433332211"
	decided := Event{
		Time: 1, DeviceID: "0123456789abcdef0123456789abcdef",
		Refs:         []string{"sms:00112233445566778899aabbccddeeff"},
		Injection:    []string{"env"},
		Argv:         []string{"curl"},
		PolicyResult: "allow", ApprovalResult: "approved",
		DecisionDeviceID: decider, ChildExit: 0, Redactions: 1,
	}
	blob, err := json.Marshal(decided)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(blob, []byte(`"decision_device_id":"`+decider+`"`)) {
		t.Fatalf("event lost decision_device_id: %s", blob)
	}
	if !bytes.Contains(blob, []byte(`"refs":["sms:00112233445566778899aabbccddeeff"]`)) {
		t.Fatalf("subject must stay in refs: %s", blob)
	}
	if bytes.Contains(blob, []byte("message_id")) {
		t.Fatalf("event must not add a second message-id field: %s", blob)
	}

	// A run no approval decided omits the key (omitempty), and the
	// shape still decodes.
	plain := decided
	plain.ApprovalResult = ""
	plain.DecisionDeviceID = ""
	blob, err = json.Marshal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(blob, []byte("decision_device_id")) {
		t.Fatalf("event without a decision carried the key: %s", blob)
	}
	var back Event
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if back.DecisionDeviceID != "" || back.PolicyResult != "allow" {
		t.Fatalf("decoded event: %+v", back)
	}
}

func TestSealEnvelopeNeedsRecipient(t *testing.T) {
	evtJSON := []byte(`{}`)
	if _, err := SealEnvelope(evtJSON, "v", "d", nil); err == nil {
		t.Fatal("sealed without recipient")
	}
}

// TestSealEnvelopeMultipleRecipients pins the multi-owner shape of
// design.md §7.7: every owner gets its own HPKE wrap of the same event
// key (wrap_count = number of owners, §6.23 envelope).
func TestSealEnvelopeMultipleRecipients(t *testing.T) {
	vaultID := "00112233445566778899aabbccddeeff"
	owner1 := testowner.New(t, vaultID, "99998888777766665555444433332222")
	owner2 := testowner.New(t, vaultID, "88887777666655554444333322221111")
	reporter := "0123456789abcdef0123456789abcdef"
	recips := []OwnerRecipient{
		{DeviceID: owner1.OwnerDev, HPKEKEM: wire.KEMP256, HPKEPublicKey: owner1.HPKEPub},
		{DeviceID: owner2.OwnerDev, HPKEKEM: wire.KEMP256, HPKEPublicKey: owner2.HPKEPub},
	}
	evtJSON := []byte(`{"policy_result":"deny:policy-command"}`)
	envelope, err := SealEnvelope(evtJSON, vaultID, reporter, recips)
	if err != nil {
		t.Fatal(err)
	}
	if envelope[0] != 2 {
		t.Fatalf("wrap_count %d, want 2", envelope[0])
	}
	// Both owners must be able to unwrap the same event key. The AES
	// blob follows ALL wraps, so parse the wrap section first.
	off := 1
	type wrap struct {
		enc, wrapped []byte
	}
	wraps := make([]wrap, 2)
	for i := range wraps {
		encLen := int(binary.BigEndian.Uint16(envelope[off : off+2]))
		wraps[i].enc = envelope[off+2 : off+2+encLen]
		wraps[i].wrapped = envelope[off+2+encLen : off+2+encLen+48]
		off += 2 + encLen + 48
	}
	blob := envelope[off:]
	var blobs [][]byte
	for i, owner := range []*testowner.Owner{owner1, owner2} {
		info, err := crypto.Info(crypto.PurposeAuditEventKey, vaultID, recips[i].DeviceID)
		if err != nil {
			t.Fatal(err)
		}
		eventKey, err := crypto.UnwrapKey(wire.KEMP256, owner.HPKEPriv, info, wraps[i].enc, wraps[i].wrapped)
		if err != nil {
			t.Fatalf("owner %d unwrap failed: %v", i, err)
		}
		aad, err := crypto.AuditAAD(vaultID, reporter)
		if err != nil {
			t.Fatal(err)
		}
		pt, err := crypto.OpenBlob(eventKey, aad, blob)
		if err != nil {
			t.Fatalf("owner %d open failed: %v", i, err)
		}
		blobs = append(blobs, pt)
		if !bytes.Contains(pt, []byte("deny:policy-command")) {
			t.Fatalf("owner %d wrong plaintext %q", i, pt)
		}
	}
	if !bytes.Equal(blobs[0], blobs[1]) {
		t.Fatal("owners unwrapped different events")
	}
}
