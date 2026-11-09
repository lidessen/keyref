//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/lidessen/keyref/proto/wire"
)

func TestStdinLoginApprovalFlow(t *testing.T) {
	// An ordinary progress message or replacement marker must not echo
	// the reference when it also happens to be the username.
	const username = refApproval
	o := setupPairedVault(t)
	o.putItemFields(t, itemApproval, refApproval, "****", username, secretApprov, map[string]any{
		"sensitivity": "approval", "commandPolicy": "deny-shells",
		"allowCommands": []string{"helper"}, "allowedHosts": []string{"api.example.com"},
		"allowArgv": false,
	})
	o.grantLater(t, itemApproval, wire.GrantKindView)
	if sync := runCLI(t, "sync"); sync.code != 0 {
		t.Fatalf("sync after grant exited %d", sync.code)
	}
	digest := sha256.Sum256([]byte(username + "\n" + secretApprov + "\n"))
	done := o.serveOneApproval(t, decideApprove, nil)
	result := runCLI(t, "exec", "--stdin-login", refApproval, "--", helperBin, "login", hex.EncodeToString(digest[:]))
	done.Wait()
	if result.code != 0 {
		t.Fatalf("login exec exited %d", result.code)
	}
	if result.stdout != "***\n***\n" ||
		strings.Contains(result.stderr, username) || strings.Contains(result.stderr, secretApprov) {
		t.Fatal("login result was not fully redacted")
	}
	assertApprovalStatus(t, o, o.lastApprovalID, wire.ApprovalStatusConsumed)

	batch := o.do(t, "GET", "/v1/sync?cursor=0", nil, nil)
	if batch.StatusCode != 200 {
		t.Fatalf("owner sync exited %d", batch.StatusCode)
	}
	raw, err := io.ReadAll(batch.Body)
	if err != nil {
		t.Fatal("could not read approval sync fixture")
	}
	var snapshot wire.SyncResponse
	if json.Unmarshal(raw, &snapshot) != nil {
		t.Fatal("could not decode approval sync fixture")
	}
	approvals := make(map[string]bool)
	for _, change := range snapshot.Changes {
		if change.Entity != wire.EntityApproval {
			continue
		}
		var status wire.ApprovalStatusData
		if json.Unmarshal(change.Data, &status) != nil {
			t.Fatal("could not decode approval status")
		}
		approvals[status.ApprovalID] = true
	}
	if len(approvals) != 1 {
		t.Fatalf("got %d approvals for one login execution", len(approvals))
	}
}
