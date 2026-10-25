package exec

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/lidessen/keyref/cli/internal/itemcrypt"
	"github.com/lidessen/keyref/cli/internal/secret"
)

// The fixture secret: every assertion below greps for it and its
// common encodings in captured output.
const fxSecret = "sk-EXEC-PLAINTEXT-fixture-42"

// TestMain turns the test binary into a controllable child process
// when KEYREF_EXEC_HELPER is set: the child prints exactly what the
// test asks for, so the parent's injection and redaction paths run
// against a real spawn.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "helper" {
		helperMain(os.Args[2:])
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func helperMain(args []string) {
	switch {
	case len(args) > 0 && args[0] == "print-env":
		fmt.Printf("K=%s\n", os.Getenv("K"))
	case len(args) > 0 && args[0] == "print-pass":
		fmt.Printf("P=%s\n", os.Getenv("PASSED_THROUGH"))
	case len(args) > 0 && args[0] == "print-stdin":
		b, _ := io.ReadAll(os.Stdin)
		fmt.Printf("STDIN=%s\n", strings.TrimRight(string(b), "\n"))
	case len(args) > 0 && args[0] == "print-fd3":
		b, _ := io.ReadAll(os.NewFile(3, "/dev/fd/3"))
		fmt.Printf("FD3=%s\n", string(b))
	case len(args) > 0 && args[0] == "print-argv":
		fmt.Printf("ARGV=%s\n", strings.Join(args[1:], ","))
	case len(args) > 0 && args[0] == "exit42":
		os.Exit(42)
	}
}

func mkRef(t *testing.T, ref, value string, injectable, allowArgv bool) *ResolvedRef {
	t.Helper()
	return mkRefJSON(t, ref, `{"value":"`+value+`"}`, injectable, allowArgv)
}

func mkRefJSON(t *testing.T, ref, doc string, injectable, allowArgv bool) *ResolvedRef {
	t.Helper()
	pt, err := secret.ExtractStringField([]byte(doc), "value")
	if err != nil {
		t.Fatal(err)
	}
	return &ResolvedRef{
		Ref:   ref,
		Meta:  &itemcrypt.Meta{Ref: ref, Injectable: injectable, Policy: itemcrypt.MetaPolicy{AllowArgv: allowArgv}},
		Value: pt,
	}
}

func encodingsOf(s string) []string {
	return []string{
		s,
		base64Std(s), strings.TrimRight(base64Std(s), "="),
		hexLower(s), strings.ToUpper(hexLower(s)),
	}
}

func base64Std(s string) string { return b64encode(s) }
func hexLower(s string) string  { return hexencode(s) }

// assertNoLeak fails when out contains the fixture secret or any of
// its common encodings (design.md §12.2 acceptance).
func assertNoLeak(t *testing.T, out string) {
	t.Helper()
	for _, enc := range encodingsOf(fxSecret) {
		if strings.Contains(out, enc) {
			t.Fatalf("output leaked the fixture secret (encoding %q): %.80q", enc[:min(12, len(enc))], out)
		}
	}
}

func testBinary(t *testing.T) string {
	t.Helper()
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

func runReq(req *Request) (int, string, string) {
	var stdout, stderr bytes.Buffer
	req.Stdout = &stdout
	req.Stderr = &stderr
	if req.ParentEnv == nil {
		req.ParentEnv = []string{"PATH=" + os.Getenv("PATH")}
	}
	code := Run(req)
	return code, stdout.String(), stderr.String()
}

func TestRunEnvInjectionIsRedacted(t *testing.T) {
	req := &Request{
		EnvRefs: []string{"K=openai-prod"},
		Argv:    []string{testBinary(t), "helper", "print-env"},
		Refs: map[string]*ResolvedRef{
			"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false),
		},
	}
	var outcome *Outcome
	req.OnOutcome = func(o *Outcome) { outcome = o }
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d, stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "K=<redacted:openai-prod>") {
		t.Fatalf("redaction missing: %q", stdout)
	}
	assertNoLeak(t, stdout)
	assertNoLeak(t, stderr)
	if outcome == nil || outcome.Redactions != 1 || outcome.ChildExit != 0 {
		t.Fatalf("outcome %+v", outcome)
	}
	if len(outcome.Refs) != 1 || outcome.Refs[0] != "openai-prod" {
		t.Fatalf("outcome refs %v", outcome.Refs)
	}
}

func TestRunPassThroughEnv(t *testing.T) {
	req := &Request{
		PassNames: []string{"PASSED_THROUGH"},
		ParentEnv: []string{"PATH=" + os.Getenv("PATH"), "PASSED_THROUGH=forwarded-value", "STRAY=dropped"},
		Argv:      []string{testBinary(t), "helper", "print-pass"},
		Refs:      map[string]*ResolvedRef{},
	}
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, stderr)
	}
	if !strings.Contains(stdout, "P=forwarded-value") {
		t.Fatalf("pass-through missing: %q", stdout)
	}
}

func TestRunStdinInjectionIsRedacted(t *testing.T) {
	req := &Request{
		StdinRef: "openai-prod",
		Argv:     []string{testBinary(t), "helper", "print-stdin"},
		Refs: map[string]*ResolvedRef{
			"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false),
		},
	}
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, stderr)
	}
	if !strings.Contains(stdout, "STDIN=<redacted:openai-prod>") {
		t.Fatalf("stdin redaction missing: %q", stdout)
	}
	assertNoLeak(t, stdout)
}

func TestRunFdInjectionIsRedacted(t *testing.T) {
	req := &Request{
		FdRefs:     []string{"3=openai-prod"},
		FdTemplate: `header "Authorization: Bearer {{keyref}}"`,
		Argv:       []string{testBinary(t), "helper", "print-fd3"},
		Refs: map[string]*ResolvedRef{
			"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false),
		},
	}
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, stderr)
	}
	if !strings.Contains(stdout, `FD3=header "Authorization: Bearer <redacted:openai-prod>"`) {
		t.Fatalf("fd redaction missing: %q", stdout)
	}
	assertNoLeak(t, stdout)
}

func TestRunFdTemplateValidationFails(t *testing.T) {
	// A template that renders CR/LF must be refused with exit 15
	// BEFORE any spawn (design.md §7.1, §15).
	req := &Request{
		FdRefs:     []string{"3=openai-prod"},
		FdTemplate: "{{keyref}}",
		Argv:       []string{testBinary(t), "helper", "print-fd3"},
		Refs: map[string]*ResolvedRef{
			// JSON-escaped CR/LF decode to real CR/LF in the value,
			// which the header-value charset must reject.
			"openai-prod": mkRefJSON(t, "openai-prod", `{"value":"line\r\nbreak"}`, true, false),
		},
	}
	code, stdout, _ := runReq(req)
	if code != 15 {
		t.Fatalf("exit %d, want 15", code)
	}
	if stdout != "" {
		t.Fatalf("child output despite refusal: %q", stdout)
	}
}

func TestRunExitCodePassthrough(t *testing.T) {
	req := &Request{
		Argv: []string{testBinary(t), "helper", "exit42"},
		Refs: map[string]*ResolvedRef{},
	}
	code, _, _ := runReq(req)
	if code != 42 {
		t.Fatalf("exit %d, want 42 (child's own code, §7.6)", code)
	}
}

func TestRunPolicyRefusalNeverStartsChild(t *testing.T) {
	req := &Request{
		EnvRefs: []string{"K=openai-prod"},
		Argv:    []string{"echo", "SHOULD-NOT-RUN"},
		Refs: map[string]*ResolvedRef{
			"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false),
		},
	}
	code, stdout, _ := runReq(req)
	if code != 10 {
		t.Fatalf("exit %d, want 10", code)
	}
	if strings.Contains(stdout, "SHOULD-NOT-RUN") {
		t.Fatal("denied command ran")
	}
}

func TestRunUnknownRef(t *testing.T) {
	req := &Request{
		EnvRefs: []string{"K=no-such-ref"},
		Argv:    []string{testBinary(t), "helper", "print-env"},
		Refs:    map[string]*ResolvedRef{},
	}
	code, _, _ := runReq(req)
	if code != 11 {
		t.Fatalf("exit %d, want 11", code)
	}
}

func TestRunNotInjectable(t *testing.T) {
	req := &Request{
		EnvRefs: []string{"K=note-1"},
		Argv:    []string{testBinary(t), "helper", "print-env"},
		Refs: map[string]*ResolvedRef{
			"note-1": mkRef(t, "note-1", fxSecret, false, false),
		},
	}
	code, _, _ := runReq(req)
	if code != 15 {
		t.Fatalf("exit %d, want 15", code)
	}
}

func TestRunAllowArgvDoubleGate(t *testing.T) {
	// Placeholder without the flag → 10.
	req := &Request{
		Argv: []string{testBinary(t), "helper", "print-argv", "{{keyref:openai-prod}}"},
		Refs: map[string]*ResolvedRef{
			"openai-prod": mkRef(t, "openai-prod", fxSecret, true, true),
		},
	}
	if code, _, _ := runReq(req); code != 10 {
		t.Fatalf("no-flag exit %d, want 10", code)
	}
	// Flag without item policy → 10.
	req.AllowArgv = true
	req.Refs["openai-prod"] = mkRef(t, "openai-prod", fxSecret, true, false)
	if code, _, _ := runReq(req); code != 10 {
		t.Fatalf("no-policy exit %d, want 10", code)
	}
	// Both gates pass → substitution reaches argv, output redacted.
	req.Refs["openai-prod"] = mkRef(t, "openai-prod", fxSecret, true, true)
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d: %q", code, stderr)
	}
	if !strings.Contains(stdout, "ARGV=<redacted:openai-prod>") {
		t.Fatalf("argv substitution/redaction wrong: %q", stdout)
	}
	assertNoLeak(t, stdout)
}

func TestRunUnresolvableArgv0(t *testing.T) {
	req := &Request{
		Argv: []string{"/definitely/not/a/real/binary"},
		Refs: map[string]*ResolvedRef{},
	}
	if code, _, _ := runReq(req); code != 18 {
		t.Fatal("want 18 for unresolvable argv0")
	}
}

func TestRunEnvNameRejection(t *testing.T) {
	req := &Request{
		EnvRefs: []string{"LD_PRELOAD=openai-prod"},
		Argv:    []string{testBinary(t), "helper", "print-env"},
		Refs: map[string]*ResolvedRef{
			"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false),
		},
	}
	if code, _, _ := runReq(req); code != 10 {
		t.Fatal("want 10 for LD_* injection")
	}
}
