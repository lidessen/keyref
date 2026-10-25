package exec

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestParseReply(t *testing.T) {
	for _, tc := range []struct {
		spec, pattern, ref string
		ok                 bool
	}{
		{"Password:=wifi-home", "Password:", "wifi-home", true},
		{"token=abc=ref-1", "token=abc", "ref-1", true}, // '=' inside the pattern
		{"x=a", "x", "a", true},
		{"no-ref", "", "", false},
		{"=ref", "", "", false},
		{"pattern=", "", "", false},
		{"", "", "", false},
	} {
		rp, err := ParseReply(tc.spec)
		if tc.ok != (err == nil) {
			t.Errorf("ParseReply(%q) err=%v, want ok=%v", tc.spec, err, tc.ok)
			continue
		}
		if tc.ok && (rp.Pattern != tc.pattern || rp.Ref != tc.ref) {
			t.Errorf("ParseReply(%q) = %+v, want {%q %q}", tc.spec, rp, tc.pattern, tc.ref)
		}
	}
}

func TestValidateReplyPattern(t *testing.T) {
	bad := []string{
		"",              // empty
		".*",            // matches everything, including ""
		"(?s).*",        // ditto, dotall
		"[\\s\\S]*",     // ditto
		".+",            // matches any non-empty output
		"[\\s\\S]+",     // ditto
		"[\x00-\\xff]+", // ditto, every byte
		"a(",            // does not compile
		"(?P<",          // does not compile
	}
	for _, p := range bad {
		if err := ValidateReplyPattern(p); err == nil {
			t.Errorf("ValidateReplyPattern(%q) accepted a dangerous pattern", p)
		}
	}
	good := []string{
		"Password:",
		"(?i)password\\s*:",
		"Enter passphrase( for key .*)?:",
		"Token\\s*\\[?\\]?",
	}
	for _, p := range good {
		if err := ValidateReplyPattern(p); err != nil {
			t.Errorf("ValidateReplyPattern(%q) rejected a legitimate prompt: %v", p, err)
		}
	}
}

func TestReplyMatcherFiresOnceAndAcrossChunks(t *testing.T) {
	m, err := newReplyMatcher([]Reply{{Pattern: "Password:", Ref: "wifi"}})
	if err != nil {
		t.Fatal(err)
	}
	// Split the prompt across three feeds: no single feed contains it.
	if fired := m.Feed([]byte("Enter your Pass")); len(fired) != 0 {
		t.Fatalf("fired early: %v", fired)
	}
	if fired := m.Feed([]byte("word")); len(fired) != 0 {
		t.Fatalf("fired mid-pattern: %v", fired)
	}
	fired := m.Feed([]byte(": "))
	if len(fired) != 1 || fired[0] != "wifi" {
		t.Fatalf("fired = %v, want [wifi]", fired)
	}
	// One-shot: a second match does not fire again.
	if fired := m.Feed([]byte("Password: again")); len(fired) != 0 {
		t.Fatalf("fired twice: %v", fired)
	}
}

func TestReplyMatcherMultiplePatterns(t *testing.T) {
	m, err := newReplyMatcher([]Reply{
		{Pattern: "Username:", Ref: "user-ref"},
		{Pattern: "Password:", Ref: "pass-ref"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if fired := m.Feed([]byte("Username: ")); len(fired) != 1 || fired[0] != "user-ref" {
		t.Fatalf("fired = %v, want [user-ref]", fired)
	}
	if fired := m.Feed([]byte("admin\nPassword: ")); len(fired) != 1 || fired[0] != "pass-ref" {
		t.Fatalf("fired = %v, want [pass-ref]", fired)
	}
}

func TestNewReplyMatcherRejectsDangerous(t *testing.T) {
	if _, err := newReplyMatcher([]Reply{{Pattern: ".*", Ref: "x"}}); err == nil {
		t.Fatal("newReplyMatcher accepted a match-anything pattern")
	}
}

// mkRefApproval builds a ResolvedRef whose policy satisfies the --reply
// double gate (sensitivity=approval, allowCommands containing argv0).
func mkRefApproval(t *testing.T, ref, value, argv0 string) *ResolvedRef {
	t.Helper()
	rr := mkRef(t, ref, value, true, false)
	rr.Meta.Policy.Sensitivity = "approval"
	rr.Meta.Policy.AllowCommands = []string{filepath.Base(argv0)}
	return rr
}

// TestReplyGateRejectsStandardItem pins the sensitivity half of the
// double gate: --reply on a standard item is exit 10 before anything
// runs (design.md §7.1).
func TestReplyGateRejectsStandardItem(t *testing.T) {
	rr := mkRefApproval(t, "wifi", fxSecret, testBinary(t))
	rr.Meta.Policy.Sensitivity = "standard" // one gate half missing
	req := &Request{
		Pty:     true,
		Replies: []Reply{{Pattern: "Password:", Ref: "wifi"}},
		Argv:    []string{testBinary(t), "helper", "prompt"},
		Refs:    map[string]*ResolvedRef{"wifi": rr},
	}
	code, stdout, stderr := runReq(req)
	if code != 10 {
		t.Fatalf("exit %d, want 10 for --reply on a standard item", code)
	}
	if !strings.Contains(stderr, "sensitivity=approval") {
		t.Fatalf("stderr does not name the missing gate: %q", stderr)
	}
	assertNoLeak(t, stdout)
}

// TestReplyGateRejectsAllowCommandsMissing pins the allowCommands half.
func TestReplyGateRejectsAllowCommandsMissing(t *testing.T) {
	rr := mkRefApproval(t, "wifi", fxSecret, testBinary(t))
	rr.Meta.Policy.AllowCommands = []string{"other-tool"}
	req := &Request{
		Pty:     true,
		Replies: []Reply{{Pattern: "Password:", Ref: "wifi"}},
		Argv:    []string{testBinary(t), "helper", "prompt"},
		Refs:    map[string]*ResolvedRef{"wifi": rr},
	}
	code, stdout, _ := runReq(req)
	if code != 10 {
		t.Fatalf("exit %d, want 10 when allowCommands does not contain argv0", code)
	}
	assertNoLeak(t, stdout)
}

func TestReplyWithoutPtyRejected(t *testing.T) {
	req := &Request{
		Replies: []Reply{{Pattern: "Password:", Ref: "wifi"}},
		Argv:    []string{testBinary(t), "helper", "prompt"},
		Refs:    map[string]*ResolvedRef{"wifi": mkRefApproval(t, "wifi", fxSecret, testBinary(t))},
	}
	if code, _, _ := runReq(req); code != 10 {
		t.Fatalf("exit %d, want 10 for --reply without --pty", code)
	}
}
