package exec

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
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

func TestPtyPumpTimesOutWhenSlaveHeld(t *testing.T) {
	ptyAvailable(t)
	master, slave, err := openPty()
	if err != nil {
		t.Fatal("could not allocate pty")
	}
	defer master.Close()
	defer slave.Close()
	matcher, err := newReplyMatcher(nil)
	if err != nil {
		t.Fatal("could not create reply matcher")
	}
	red := NewRedactor(map[string][]byte{"ref": []byte(fxSecret)})
	defer red.Destroy()
	red.Attach(io.Discard)
	sess := &ptySession{master: master, matcher: matcher, red: red}
	childExited := make(chan struct{})
	close(childExited)
	done := make(chan error, 1)
	go func() { done <- sess.pump(childExited) }()
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("pump error %v, want a read deadline", err)
		}
	case <-time.After(5 * time.Second):
		_ = master.Close()
		<-done
		t.Fatal("pump did not stop when a slave remained open")
	}
}

func TestPtyPumpBoundsPostExitOutput(t *testing.T) {
	for _, tc := range []struct {
		name string
		slow bool
		want error
	}{
		{"continuous", true, os.ErrDeadlineExceeded},
		{"volume", false, errPtyDrainLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reader, writer, err := os.Pipe()
			if err != nil {
				t.Fatal("could not create output pipe")
			}
			matcher, err := newReplyMatcher(nil)
			if err != nil {
				t.Fatal("could not create reply matcher")
			}
			red := NewRedactor(nil)
			red.Attach(io.Discard)
			sess := &ptySession{master: reader, matcher: matcher, red: red}
			childExited := make(chan struct{})
			close(childExited)
			done := make(chan error, 1)
			go func() { done <- sess.pump(childExited) }()
			stop := make(chan struct{})
			writerDone := make(chan struct{})
			go func() {
				defer close(writerDone)
				chunk := bytes.Repeat([]byte{'x'}, 16*1024)
				if tc.slow {
					chunk = chunk[:1]
				}
				ticker := time.NewTicker(100 * time.Millisecond)
				defer ticker.Stop()
				for {
					if tc.slow {
						select {
						case <-ticker.C:
						case <-stop:
							return
						}
					}
					if _, err := writer.Write(chunk); err != nil {
						return
					}
				}
			}()
			finished := false
			defer func() {
				close(stop)
				_ = writer.Close()
				_ = reader.Close()
				<-writerDone
				if !finished {
					<-done
				}
				red.Destroy()
			}()
			select {
			case err := <-done:
				finished = true
				if !errors.Is(err, tc.want) {
					t.Fatalf("pump error %v, want %v", err, tc.want)
				}
			case <-time.After(8 * time.Second):
				t.Fatal("pump did not bound output after child exit")
			}
		})
	}
}

func TestPtyHeldSlaveFailsClosed(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the escaped holder does not keep this PTY open on Darwin")
	}
	ptyAvailable(t)
	marker := filepath.Join(t.TempDir(), "release-holder")
	defer func() {
		if _, err := os.Stat(marker + ".started"); err != nil {
			return
		}
		if err := os.WriteFile(marker, nil, 0o600); err != nil {
			t.Error("could not release the pty holder")
			return
		}
		deadline := time.NewTimer(3 * time.Second)
		defer deadline.Stop()
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			if _, err := os.Stat(marker + ".done"); err == nil {
				return
			}
			select {
			case <-ticker.C:
			case <-deadline.C:
				t.Error("pty holder did not acknowledge release")
				return
			}
		}
	}()
	req := &Request{
		Pty:     true,
		EnvRefs: []string{"K=openai-prod"},
		Argv:    []string{testBinary(t), "helper", "out-escaped-pty", marker},
		Refs:    map[string]*ResolvedRef{"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false)},
	}
	var stdout, stderr bytes.Buffer
	var outcome *Outcome
	req.Stdout, req.Stderr = &stdout, &stderr
	req.OnOutcome = func(o *Outcome) { outcome = o }
	code := Run(req)
	if code != 14 || outcome == nil || outcome.ChildExit != 7 || outcome.PolicyState != "deny:redaction" || outcome.Redactions != 1 {
		t.Fatalf("exit %d, outcome %+v", code, outcome)
	}
	if !strings.Contains(stderr.String(), "pty output incomplete") {
		t.Fatal("incomplete output diagnostic missing")
	}
	if !strings.Contains(stdout.String(), "<redacted:openai-prod>") {
		t.Fatal("output produced before the timeout was not redacted")
	}
	for _, value := range encodingsOf(fxSecret) {
		if strings.Contains(stdout.String(), value) || strings.Contains(stderr.String(), value) {
			t.Fatal("pty timeout output leaked a secret")
		}
	}
}
