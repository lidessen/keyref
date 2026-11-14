package main

import (
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/lidessen/keyref/cli/internal/audit"
	"github.com/lidessen/keyref/cli/internal/exec"
	"github.com/lidessen/keyref/cli/internal/testowner"
	"github.com/lidessen/keyref/proto/crypto"
	"github.com/lidessen/keyref/proto/wire"
)

func TestApprovalResultForRedactionFailure(t *testing.T) {
	for _, tc := range []struct {
		name, state string
		used        bool
		want        string
	}{
		{"approved-redaction-failure", "deny:redaction", true, "approved"},
		{"no-approval-redaction-failure", "deny:redaction", false, ""},
		{"approved-success", "allow", true, "approved"},
		{"denied-approval", "deny:approval-denied", true, "denied"},
		{"failure-before-approval", "deny:internal", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := approvalResultOf(tc.state, tc.used); got != tc.want {
				t.Fatalf("approval result %q, want %q", got, tc.want)
			}
		})
	}
}

func TestRedactionFailureAuditEnvelope(t *testing.T) {
	owner := testowner.New(t, "00112233445566778899aabbccddeeff", "99998888777766665555444433332222")
	reporter := "0123456789abcdef0123456789abcdef"
	recips := []audit.OwnerRecipient{{DeviceID: owner.OwnerDev, HPKEKEM: wire.KEMP256, HPKEPublicKey: owner.HPKEPub}}
	for _, childExit := range []int{7, 137} {
		outcome := &exec.Outcome{
			ChildExit:        childExit,
			Redactions:       1,
			Refs:             []string{"entry"},
			Argv:             []string{"consumer"},
			PolicyState:      "deny:redaction",
			ApprovalResult:   approvalResultOf("deny:redaction", true),
			DecisionDeviceID: owner.OwnerDev,
		}
		envelope := buildAuditEnvelope(outcome, owner.VaultID, reporter, recips)
		if len(envelope) < 3 || envelope[0] != 1 {
			t.Fatal("audit envelope is missing its recipient")
		}
		encLen := int(binary.BigEndian.Uint16(envelope[1:3]))
		if len(envelope) < 3+encLen+48 {
			t.Fatal("audit envelope is truncated")
		}
		enc := envelope[3 : 3+encLen]
		wrapped := envelope[3+encLen : 3+encLen+48]
		blob := envelope[3+encLen+48:]
		info, err := crypto.Info(crypto.PurposeAuditEventKey, owner.VaultID, owner.OwnerDev)
		if err != nil {
			t.Fatal(err)
		}
		key, err := crypto.UnwrapKey(wire.KEMP256, owner.HPKEPriv, info, enc, wrapped)
		if err != nil {
			t.Fatal(err)
		}
		aad, err := crypto.AuditAAD(owner.VaultID, reporter)
		if err != nil {
			clear(key)
			t.Fatal(err)
		}
		plaintext, err := crypto.OpenBlob(key, aad, blob)
		clear(key)
		if err != nil {
			t.Fatal(err)
		}
		var event audit.Event
		err = json.Unmarshal(plaintext, &event)
		clear(plaintext)
		if err != nil {
			t.Fatal(err)
		}
		if event.PolicyResult != "deny:redaction" || event.ApprovalResult != "approved" || event.DecisionDeviceID != owner.OwnerDev || event.ChildExit != childExit || event.Redactions != 1 {
			t.Fatalf("redaction failure audit has incorrect fields: %+v", event)
		}
	}
}
