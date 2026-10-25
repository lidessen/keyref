package exec

import (
	"strings"
	"testing"
)

// ptyAvailable reports whether this environment can allocate a
// pseudo-terminal at all. CI containers without /dev/ptmx skip the
// integration tests; macOS and normal Linux hosts run them.
func ptyAvailable(t *testing.T) {
	t.Helper()
	m, s, err := openPty()
	if err != nil {
		t.Skipf("pty allocation unavailable in this environment: %v", err)
	}
	m.Close()
	s.Close()
}

// TestPtyReplyTypesSecretAndRedacts is the full §7.1 pty integration:
// the child prints a prompt, the --reply pattern matches the RAW output
// (before redaction), keyref types the secret into the pty input, the
// child echoes and re-prints it — and the caller only ever sees the
// redacted stream.
func TestPtyReplyTypesSecretAndRedacts(t *testing.T) {
	ptyAvailable(t)
	ptySecret := "pty-passphrase-7788!"
	argv := []string{testBinary(t), "helper", "prompt"}
	req := &Request{
		Pty:     true,
		Replies: []Reply{{Pattern: `Password:`, Ref: "wifi"}},
		Argv:    argv,
		Refs:    map[string]*ResolvedRef{"wifi": mkRefApproval(t, "wifi", ptySecret, argv[0])},
	}
	var outcome *Outcome
	req.OnOutcome = func(o *Outcome) { outcome = o }
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "Password:") {
		t.Fatalf("pty prompt missing from output: %q", stdout)
	}
	if !strings.Contains(stdout, "got:<redacted:wifi>") {
		t.Fatalf("child never received the typed secret (redacted form missing): %q", stdout)
	}
	// The typed secret (echoed by the pty) and the child's own echo are
	// both redacted — the caller never sees the raw value.
	for _, enc := range encodingsOf(ptySecret) {
		if strings.Contains(stdout, enc) {
			t.Fatalf("pty output leaked the secret: %.120q", stdout)
		}
	}
	if outcome == nil || outcome.PolicyState != "allow" || outcome.ChildExit != 0 {
		t.Fatalf("outcome %+v", outcome)
	}
	if outcome.Redactions == 0 {
		t.Fatal("pty output was not redacted (echo or child copy escaped)")
	}
}

// TestPtyForwardsCallerStdin: the caller's stdin flows into the pty
// input after any injected secret.
func TestPtyForwardsCallerStdin(t *testing.T) {
	ptyAvailable(t)
	argv := []string{testBinary(t), "helper", "read-line"}
	req := &Request{
		Pty:   true,
		Stdin: strings.NewReader("typed-line-42\n"),
		Argv:  argv,
		Refs:  map[string]*ResolvedRef{},
	}
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "LINE=typed-line-42") {
		t.Fatalf("caller stdin did not reach the pty child: %q", stdout)
	}
}

// TestPtyStdinSecretTyped: --stdin on a pty writes the secret as typed
// keystrokes (no EOF follows — a pty cannot close its input side).
func TestPtyStdinSecretTyped(t *testing.T) {
	ptyAvailable(t)
	argv := []string{testBinary(t), "helper", "read-line"}
	ptySecret := "stdin-typed-pass-99"
	req := &Request{
		Pty:      true,
		StdinRef: "wifi",
		Argv:     argv,
		Refs:     map[string]*ResolvedRef{"wifi": mkRefApproval(t, "wifi", ptySecret, argv[0])},
	}
	// A --stdin secret write is not gated by --reply (only --reply is);
	// the item is injectable, which the generic checks cover.
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "LINE=<redacted:wifi>") {
		t.Fatalf("stdin secret did not reach the child in redacted echo: %q", stdout)
	}
	for _, enc := range encodingsOf(ptySecret) {
		if strings.Contains(stdout, enc) {
			t.Fatalf("pty output leaked the secret: %.120q", stdout)
		}
	}
}

// TestPtyChildExitPassthrough: the child's exit code crosses the pty
// unchanged (§7.6 first row).
func TestPtyChildExitPassthrough(t *testing.T) {
	ptyAvailable(t)
	req := &Request{
		Pty:  true,
		Argv: []string{testBinary(t), "helper", "exit42"},
		Refs: map[string]*ResolvedRef{},
	}
	code, stdout, _ := runReq(req)
	if code != 42 {
		t.Fatalf("exit %d, want 42 through the pty (stdout %.80q)", code, stdout)
	}
}

// TestPtySessionEndsWhenChildExits: the pty session must terminate
// cleanly once the child exits — the master is drained (output already
// written is still redacted and delivered), the process group is
// reaped, and Run returns instead of hanging on the never-EOF pty.
func TestPtySessionEndsWhenChildExits(t *testing.T) {
	ptyAvailable(t)
	req := &Request{
		Pty:  true,
		Argv: []string{testBinary(t), "helper", "banner"},
		Refs: map[string]*ResolvedRef{},
	}
	code, stdout, stderr := runReq(req)
	if code != 0 {
		t.Fatalf("exit %d, stderr: %s", code, stderr)
	}
	if !strings.Contains(stdout, "hello-from-pty") || !strings.Contains(stdout, "bye") {
		t.Fatalf("banner output missing after session end: %q", stdout)
	}
}
