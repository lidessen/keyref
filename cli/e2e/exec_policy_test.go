//go:build e2e

package e2e

import (
	"strings"
	"testing"

	"github.com/lidessen/keyref/proto/wire"
)

// The protocol-v2 H/I additions (design.md §7.3, §6.6), end to
// end against the real server and CLI:
//
//   - H: a paired-vault item must name its commands. An empty
//     allowCommands list allows nothing unless the owner turned shell
//     refusal off (commandPolicy = allow-all); the built-in deny list is
//     never a fallback there.
//   - I: approval is orthogonal to where the secret lives. A standard
//     item this device holds no use grant for goes through the approval
//     round, and the one-time item key is not cached.

const (
	itemBare     = "b00b0000b00b0000b00b0000b00b0000"
	refBare      = "bare-prod"
	secretBare   = "{{API_KEY_bare0001}}"
	itemOpenAll  = "0bee00000bee00000bee00000bee0000"
	refOpenAll   = "open-prod"
	secretOpen   = "{{API_KEY_open0002}}"
	itemNoGrant  = "a0a00000a0a00000a0a00000a0a00000"
	refNoGrant   = "nogrant-prod"
	secretNoGrnt = "{{API_KEY_nogr0003}}"
)

// TestPairedVaultRequiresAllowCommands pins §H: an item with an empty
// allowCommands list and the default commandPolicy is unusable, even for
// a command the built-in deny list would never have caught. The refusal
// is exit 10 before the child exists and names iOS as the place to fix
// it.
func TestPairedVaultRequiresAllowCommands(t *testing.T) {
	o := setupPairedVault(t)
	o.putItemPolicy(t, itemBare, refBare, "sk-****bbbb", secretBare, map[string]any{
		"sensitivity": "standard", "commandPolicy": "deny-shells",
		"allowCommands": []string{}, "allowedHosts": []string{}, "allowArgv": false,
	})
	o.grantLater(t, itemBare, wire.GrantKindView)
	o.grantLater(t, itemBare, wire.GrantKindUse)
	if sync := runCLI(t, "sync"); sync.code != 0 {
		t.Fatalf("sync exit %d: %s", sync.code, sync.stderr)
	}

	ex := runCLI(t, "exec", "--env", "K="+refBare, "--", helperBin, "print-env")
	if ex.code != 10 {
		t.Fatalf("empty allowCommands exec exit %d, want 10\nstdout: %s\nstderr: %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stderr, "iOS") || !strings.Contains(ex.stderr, "allowCommands") {
		t.Fatalf("denial must point at allowCommands on iOS: %s", ex.stderr)
	}
	if strings.Contains(ex.stdout, "K=") {
		t.Fatalf("the child ran despite the policy rejection: %q", ex.stdout)
	}
	assertNotContains(t, "bare item exec", secretBare, ex.stdout, ex.stderr)

	// No approval request was created: the policy check precedes it
	// (design §15).
	var list wire.ApprovalListResponse
	o.do(t, "GET", "/v1/approvals?status=pending", nil, &list)
	if len(list.Approvals) != 0 {
		t.Fatalf("a policy-rejected exec created %d pending approvals", len(list.Approvals))
	}
}

// TestAllowAllCommandPolicyOptsOut pins the other half of §H:
// commandPolicy = allow-all is the owner's explicit opt-out, so an empty
// allowCommands list runs the command. A whitelist still tightens it.
func TestAllowAllCommandPolicyOptsOut(t *testing.T) {
	o := setupPairedVault(t)
	o.putItemPolicy(t, itemOpenAll, refOpenAll, "sk-****cccc", secretOpen, map[string]any{
		"sensitivity": "standard", "commandPolicy": "allow-all",
		"allowCommands": []string{}, "allowedHosts": []string{}, "allowArgv": false,
	})
	o.grantLater(t, itemOpenAll, wire.GrantKindView)
	o.grantLater(t, itemOpenAll, wire.GrantKindUse)
	if sync := runCLI(t, "sync"); sync.code != 0 {
		t.Fatalf("sync exit %d: %s", sync.code, sync.stderr)
	}

	ex := runCLI(t, "exec", "--env", "K="+refOpenAll, "--", helperBin, "print-env")
	if ex.code != 0 {
		t.Fatalf("allow-all exec exit %d: %s %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stdout, "K=<redacted:"+refOpenAll+">") {
		t.Fatalf("allow-all exec output not redacted:\n%s", ex.stdout)
	}
	assertNotContains(t, "allow-all exec", secretOpen, ex.stdout, ex.stderr)
}

// TestStandardItemWithoutUseGrantRequiresApproval pins §I: an item whose
// meta says standard but for which this device holds no use grant takes
// the approval round. The decision delivers a one-time item key, the
// value is injected and redacted, and nothing is cached: a second exec
// with no responder times out with exit 13.
func TestStandardItemWithoutUseGrantRequiresApproval(t *testing.T) {
	o := setupPairedVault(t)
	o.putItemPolicy(t, itemNoGrant, refNoGrant, "sk-****dddd", secretNoGrnt, map[string]any{
		"sensitivity": "standard", "commandPolicy": "deny-shells",
		"allowCommands": []string{"helper"}, "allowedHosts": []string{"api.example.com"},
		"allowArgv": false,
	})
	// View only: no long-lived item key, so exec must ask the phone.
	o.grantLater(t, itemNoGrant, wire.GrantKindView)
	if sync := runCLI(t, "sync"); sync.code != 0 {
		t.Fatalf("sync exit %d: %s", sync.code, sync.stderr)
	}

	done := o.serveOneApprovalFor(t, itemNoGrant, refNoGrant, decideApprove, nil)
	ex := runCLI(t, "exec", "--env", "K="+refNoGrant, "--", helperBin, "print-env")
	done.Wait()
	if ex.code != 0 {
		t.Fatalf("no-grant exec exit %d: %s %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stdout, "K=<redacted:"+refNoGrant+">") {
		t.Fatalf("no-grant exec output not redacted:\n%s", ex.stdout)
	}
	assertNotContains(t, "no-grant exec", secretNoGrnt, ex.stdout, ex.stderr)
	if o.lastApprovalID == "" {
		t.Fatal("no approval request was recorded")
	}
	assertApprovalStatus(t, o, o.lastApprovalID, wire.ApprovalStatusConsumed)

	// The one-time key is not cached: with no responder the second exec
	// must ask again and time out.
	ex2 := runCLI(t, "exec", "--timeout", "3", "--env", "K="+refNoGrant, "--", helperBin, "print-env")
	if ex2.code != 13 {
		t.Fatalf("second no-grant exec exit %d, want 13\nstdout: %s\nstderr: %s", ex2.code, ex2.stdout, ex2.stderr)
	}
	assertNotContains(t, "second no-grant exec", secretNoGrnt, ex2.stdout, ex2.stderr)
}

// assertNotContains fails when any output carries the fixture secret.
func assertNotContains(t *testing.T, where, secret string, outputs ...string) {
	t.Helper()
	for _, out := range outputs {
		if strings.Contains(out, secret) {
			t.Fatalf("%s leaked its fixture secret: %.120q", where, out)
		}
	}
}
