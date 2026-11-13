package exec

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/lidessen/keyref/cli/internal/itemcrypt"
	"github.com/lidessen/keyref/cli/internal/secret"
)

// ---- review fix: audit outcome for every attempted exec (§7.7) ----

func TestRejectionProducesDenyOutcome(t *testing.T) {
	var got *Outcome
	req := &Request{
		EnvRefs: []string{"K=openai-prod"},
		Argv:    []string{"echo", "hi"},
		Refs: map[string]*ResolvedRef{
			"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false),
		},
	}
	req.OnOutcome = func(o *Outcome) { got = o }
	var stdout, stderr bytes.Buffer
	req.Stdout, req.Stderr = &stdout, &stderr
	req.ParentEnv = []string{"PATH=" + os.Getenv("PATH")}
	if code := Run(req); code != 10 {
		t.Fatalf("exit %d, want 10", code)
	}
	if got == nil {
		t.Fatal("no audit outcome for rejected exec")
	}
	if got.PolicyState != "deny:policy-command" {
		t.Fatalf("policy state %q", got.PolicyState)
	}
	if got.ChildExit != -1 {
		t.Fatalf("child exit %d, want -1 (never started)", got.ChildExit)
	}
	if len(got.Refs) != 1 || got.Refs[0] != "openai-prod" {
		t.Fatalf("outcome refs %v", got.Refs)
	}
}

func TestNotInjectableProducesDenyOutcome(t *testing.T) {
	var got *Outcome
	req := &Request{
		EnvRefs: []string{"K=note-1"},
		Argv:    []string{testBinary(t), "helper", "print-env"},
		Refs: map[string]*ResolvedRef{
			"note-1": mkRef(t, "note-1", fxSecret, false, false),
		},
	}
	req.OnOutcome = func(o *Outcome) { got = o }
	code, _, stderr := runReq(req)
	if code != 15 {
		t.Fatalf("exit %d, want 15", code)
	}
	if got == nil || got.PolicyState != "deny:not-injectable" || got.ChildExit != -1 {
		t.Fatalf("outcome %+v", got)
	}
	_ = stderr
}

// ---- review fix: lazy secret resolution (§12.2, §7.3) ----

func metaOnly(t *testing.T, ref string) *ResolvedRef {
	t.Helper()
	return &ResolvedRef{Ref: ref, Meta: &itemcrypt.Meta{
		Ref: ref, Injectable: true, Policy: itemcrypt.MetaPolicy{},
	}}
}

func plainOf(t *testing.T, value string) *secret.Plaintext {
	t.Helper()
	pt, err := secret.ExtractStringField([]byte(`{"value":"`+value+`"}`), "value")
	if err != nil {
		t.Fatal(err)
	}
	return pt
}

func TestLazyResolutionSkippedOnPolicyRejection(t *testing.T) {
	resolved := false
	req := &Request{
		EnvRefs: []string{"K=openai-prod"},
		Argv:    []string{"echo", "hi"}, // policy-rejected below
		Refs:    map[string]*ResolvedRef{"openai-prod": metaOnly(t, "openai-prod")},
		ResolveValue: func(ref string) (*secret.Plaintext, int, string) {
			resolved = true
			return nil, 16, "unwrap-failed"
		},
	}
	if code, _, _ := runReq(req); code != 10 {
		t.Fatalf("exit %d, want 10", code)
	}
	if resolved {
		t.Fatal("secret was decrypted for a policy-rejected exec")
	}
}

func TestLazyResolutionUsedOnSuccess(t *testing.T) {
	resolvedCount := 0
	req := &Request{
		EnvRefs: []string{"K=openai-prod"},
		Argv:    []string{testBinary(t), "helper", "print-env"},
		Refs:    map[string]*ResolvedRef{"openai-prod": metaOnly(t, "openai-prod")},
		ResolveValue: func(ref string) (*secret.Plaintext, int, string) {
			resolvedCount++
			return plainOf(t, fxSecret), 0, ""
		},
	}
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, stderr)
	}
	if resolvedCount != 1 {
		t.Fatalf("resolver called %d times, want 1", resolvedCount)
	}
	if !strings.Contains(stdout, "K=<redacted:openai-prod>") {
		t.Fatalf("output %q", stdout)
	}
}

// ---- review fix: per-item policy intersection (§7.3) ----

func TestMultiItemCommandPolicyIsIntersection(t *testing.T) {
	// Item a whitelists echo; item b has the default deny-shells
	// policy. Both secrets injected → echo must be rejected: a's
	// whitelist never unlocks b's secret.
	req := &Request{
		EnvRefs: []string{"KA=a", "KB=b"},
		Argv:    []string{"echo", "hi"},
		Refs: map[string]*ResolvedRef{
			"a": mkRefPolicy(t, "a", fxSecret, []string{"echo"}, nil),
			"b": mkRefPolicy(t, "b", fxSecret, nil, nil),
		},
	}
	if code, _, _ := runReq(req); code != 10 {
		t.Fatalf("union semantics: exit %d, want 10", code)
	}
	// Only the permissive item: the whitelist override works
	// (design.md §7.3).
	req2 := &Request{
		EnvRefs: []string{"KA=a"},
		Argv:    []string{"echo"},
		Refs: map[string]*ResolvedRef{
			"a": mkRefPolicy(t, "a", fxSecret, []string{"echo"}, nil),
		},
	}
	if code, _, _ := runReq(req2); code != 0 {
		t.Fatalf("single whitelisted item rejected: exit %d", code)
	}
}

func TestMultiItemHostsPolicyIsIntersection(t *testing.T) {
	// Both items restrict hosts; a host allowed by one item only is
	// not allowed overall.
	req := &Request{
		EnvRefs: []string{"KA=a", "KB=b"},
		Argv:    []string{testBinary(t), "helper", "print-env", "https://api.openai.com/v1"},
		Refs: map[string]*ResolvedRef{
			"a": mkRefPolicy(t, "a", fxSecret, nil, []string{"api.openai.com"}),
			"b": mkRefPolicy(t, "b", fxSecret, nil, []string{"other.example"}),
		},
	}
	if code, _, _ := runReq(req); code != 10 {
		t.Fatalf("host union semantics: exit %d, want 10", code)
	}
	// An item with an EMPTY host list imposes no check of its own
	// (§7.3); the other item's restriction still applies.
	req2 := &Request{
		EnvRefs: []string{"KA=a", "KB=b"},
		Argv:    []string{testBinary(t), "helper", "print-env", "https://api.openai.com/v1"},
		Refs: map[string]*ResolvedRef{
			"a": mkRefPolicy(t, "a", fxSecret, nil, []string{"api.openai.com"}),
			"b": mkRefPolicy(t, "b", fxSecret, nil, nil),
		},
	}
	if code, _, _ := runReq(req2); code != 0 {
		t.Fatalf("empty-list item wrongly restricts: exit %d", code)
	}
}

// ---- review fix: case-insensitive URL scheme (§7.3) ----

func TestAllowedHostsUppercaseSchemeBypassClosed(t *testing.T) {
	argv := []string{"tool", "HTTPS://evil.example/x"}
	if err := allowedHostsFromArgv(argv, []string{"api.openai.com"}); err == nil {
		t.Fatal("uppercase HTTPS:// scheme bypassed the host check")
	}
	if err := allowedHostsFromArgv([]string{"tool", "HTTPS://api.openai.com/x"}, []string{"api.openai.com"}); err != nil {
		t.Fatalf("uppercase allowed host rejected: %v", err)
	}
}

// ---- review fix: --allow-argv local-visibility warning (§7.1) ----

func TestAllowArgvWarnsAboutProcessVisibility(t *testing.T) {
	req := &Request{
		AllowArgv: true,
		Argv:      []string{testBinary(t), "helper", "print-argv", "{{keyref:openai-prod}}"},
		Refs: map[string]*ResolvedRef{
			"openai-prod": mkRef(t, "openai-prod", fxSecret, true, true),
		},
	}
	code, _, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr, "ps, Activity Monitor") {
		t.Fatalf("missing local-visibility warning: %q", stderr)
	}
}

// ---- review fix: lowercase percent encoding matched (§7.4) ----

func TestRedactLowercasePercentEncoding(t *testing.T) {
	secret := []byte("sk-PERCENT-lower-99")
	secrets := map[string][]byte{"p": secret}
	lower := percentEncodeInto(make([]byte, 0, 3*len(secret)), secret, false)
	if lower[3] >= 'A' && lower[3] <= 'F' {
		t.Fatalf("fixture not lowercase: %q", lower)
	}
	got, _ := oneShot(t, secrets, []byte("x "+string(lower)+" y"))
	if got != "x <redacted:p> y" {
		t.Fatalf("lowercase percent form not redacted: %q", got)
	}
}

// ---- review fix: fd staging unlinks while open (§7.1) ----

func TestStageFdFileUnlinksImmediately(t *testing.T) {
	dir := t.TempDir()
	f, ok := stageFdFile(dir, 3, []byte("payload-bytes"))
	if !ok {
		t.Fatal("staging failed")
	}
	defer f.Close()
	// The path is gone while the fd stays readable: no on-disk window
	// after the write (design.md §7.1: unlink immediately).
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("%d files remain in the staging directory", len(entries))
	}
	b, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "payload-bytes" {
		t.Fatalf("fd payload %q", b)
	}
	// A staging failure reports false (Run maps it to exit 18, not
	// the redaction-specific 14 — §7.6 semantics). The fallback is
	// tested directly: where memfd exists the directory is not used at
	// all, so only the file landing can fail on a missing directory
	// (issue #4).
	if _, ok := stageFdFallback("/nonexistent-staging-dir-xyz", 3, []byte("x")); ok {
		t.Fatal("the file fallback succeeded in a missing directory")
	}
}

// ---- helper ----

func mkRefPolicy(t *testing.T, ref, value string, allowCommands, allowedHosts []string) *ResolvedRef {
	t.Helper()
	rr := mkRef(t, ref, value, true, false)
	rr.Meta.Policy.AllowCommands = allowCommands
	rr.Meta.Policy.AllowedHosts = allowedHosts
	return rr
}
