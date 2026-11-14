package exec

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/lidessen/keyref/cli/internal/itemcrypt"
	"github.com/lidessen/keyref/cli/internal/secret"
)

// symlinkedTool links dir/name -> the test binary and returns dir.
func symlinkedTool(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Symlink(testBinary(t), filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The spawn uses the PATH-resolved candidate that was checked, and the
// child still sees the caller's argv0 (multi-call binaries key off it).
func TestSpawnUsesCheckedPathAndKeepsArgv0(t *testing.T) {
	dir := symlinkedTool(t, "mytool")
	req := &Request{
		EnvRefs:   []string{"K=openai-prod"},
		Argv:      []string{"mytool", "helper", "print-argv0"},
		ParentEnv: []string{"PATH=" + dir},
		Refs:      map[string]*ResolvedRef{"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false)},
	}
	code, stdout, stderr := runReq(req)
	if code != 0 || !strings.Contains(stdout, "ARGV0=mytool") {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestResolveCommandRecordsFirstHop(t *testing.T) {
	dir := symlinkedTool(t, "mytool")
	rc, err := ResolveCommand([]string{"mytool"}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if rc.First != filepath.Join(dir, "mytool") || rc.FirstReal == rc.First || !stillResolvesTo(rc) {
		t.Fatalf("first %q real %q", rc.First, rc.FirstReal)
	}
	// Retarget the symlink after the check: the spawn guard must notice.
	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	os.Remove(rc.First)
	if err := os.Symlink(other, rc.First); err != nil {
		t.Fatal(err)
	}
	if stillResolvesTo(rc) {
		t.Fatal("retargeted symlink still passed the pre-spawn check")
	}
}

func TestArgv0PlaceholderRejectedInEveryMode(t *testing.T) {
	resolved := false
	req := &Request{
		EnvRefs: []string{"K=openai-prod"},
		Argv:    []string{"{{keyref:openai-prod}}", "x"},
		Refs:    map[string]*ResolvedRef{"openai-prod": metaOnly(t, "openai-prod")},
		ResolveValue: func(string) (*secret.Plaintext, int, string) {
			resolved = true
			return nil, 16, "unwrap-failed"
		},
	}
	var got *Outcome
	req.OnOutcome = func(o *Outcome) { got = o }
	code, _, stderr := runReq(req)
	if code != 10 || resolved || got == nil || got.PolicyState != "deny:argv0-placeholder" {
		t.Fatalf("exit %d resolved=%v outcome %+v stderr %q", code, resolved, got, stderr)
	}
}

func TestStartErrorIsRedacted(t *testing.T) {
	secrets := map[string][]byte{"k": []byte(fxSecret)}
	msg := redactStartError(secrets, errors.New("fork/exec /bin/"+fxSecret+": no such file"))
	if strings.Contains(msg, fxSecret) {
		t.Fatalf("start error leaked the secret: %q", msg)
	}
}

func TestUnknownRefWithAllowArgvDoesNotPanic(t *testing.T) {
	req := &Request{
		AllowArgv: true,
		EnvRefs:   []string{"X="},
		Argv:      []string{"awk", "BEGIN{}"},
		Refs:      map[string]*ResolvedRef{},
	}
	code, _, stderr := runReq(req)
	if code != 11 || !strings.Contains(stderr, "unknown ref") {
		t.Fatalf("exit %d stderr %q", code, stderr)
	}
}

type controlledWriter struct {
	writes    atomic.Int32
	leaked    atomic.Bool
	redacted  atomic.Bool
	started   chan struct{}
	startOnce sync.Once
	release   chan struct{}
	accept    bool
	accepted  bytes.Buffer
}

func (w *controlledWriter) Write(p []byte) (int, error) {
	w.writes.Add(1)
	if bytes.Contains(p, []byte("<redacted:openai-prod>")) {
		w.redacted.Store(true)
	}
	for _, value := range encodingsOf(fxSecret) {
		if bytes.Contains(p, []byte(value)) {
			w.leaked.Store(true)
		}
	}
	if w.started != nil {
		w.startOnce.Do(func() { close(w.started) })
		<-w.release
	}
	if w.accept {
		return w.accepted.Write(p)
	}
	return 0, errors.New("sink closed")
}

func waitForReapedChild(t *testing.T, marker string) {
	t.Helper()
	data, err := os.ReadFile(marker)
	if err != nil {
		t.Fatal("child did not record its process ID")
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil || pid <= 1 {
		t.Fatal("child recorded an invalid process ID")
	}
	deadline := time.NewTimer(8 * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		err := syscall.Kill(pid, 0)
		if errors.Is(err, syscall.ESRCH) {
			return
		}
		if err != nil {
			t.Fatal("could not inspect child status")
		}
		select {
		case <-ticker.C:
		case <-deadline.C:
			t.Fatal("child did not exit and get reaped")
		}
	}
}

func TestRedactionFailureChildTermination(t *testing.T) {
	for _, tc := range []struct {
		name      string
		pty       bool
		natural   bool
		slowSink  bool
		accept    bool
		childExit int
	}{
		{"ordinary-natural", false, true, false, false, 7},
		{"ordinary-killed", false, false, false, false, 128 + int(syscall.SIGKILL)},
		{"pty-natural", true, true, false, false, 7},
		{"pty-killed", true, false, false, false, 128 + int(syscall.SIGKILL)},
		{"pty-slow-failure", true, true, true, false, 7},
		{"pty-slow-success", true, true, true, true, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.pty {
				ptyAvailable(t)
			}
			argv := []string{testBinary(t), "helper", "out-hold"}
			marker := filepath.Join(t.TempDir(), "child-pid")
			if tc.natural {
				argv = []string{testBinary(t), "helper", "out-natural-exit7", marker}
			}
			req := &Request{
				Pty:       tc.pty,
				EnvRefs:   []string{"K=openai-prod"},
				Argv:      argv,
				ParentEnv: []string{"PATH=" + os.Getenv("PATH")},
				Refs:      map[string]*ResolvedRef{"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false)},
			}
			stdout := controlledWriter{accept: tc.accept}
			var release sync.Once
			if tc.natural {
				stdout.started = make(chan struct{})
				stdout.release = make(chan struct{})
			}
			unblock := func() {
				if stdout.release != nil {
					release.Do(func() { close(stdout.release) })
				}
			}
			var stderr bytes.Buffer
			req.Stdout, req.Stderr = &stdout, &stderr
			var outcome *Outcome
			outcomeCalls := 0
			req.OnOutcome = func(o *Outcome) { outcome, outcomeCalls = o, outcomeCalls+1 }
			type result struct {
				code    int
				outcome *Outcome
				calls   int
			}
			done := make(chan result, 1)
			go func() {
				code := Run(req)
				done <- result{code, outcome, outcomeCalls}
			}()
			received := false
			defer func() {
				unblock()
				if !received {
					select {
					case <-done:
					case <-time.After(8 * time.Second):
						t.Error("runner did not finish after releasing the output sink")
					}
				}
			}()
			if tc.natural {
				select {
				case <-stdout.started:
				case <-done:
					received = true
					t.Fatal("runner returned before delivering child output")
				case <-time.After(8 * time.Second):
					t.Fatal("child output did not reach the sink")
				}
				// The sink cannot fail until Wait has reaped the natural exit.
				waitForReapedChild(t, marker)
				if tc.slowSink {
					select {
					case <-done:
						received = true
						t.Fatal("runner returned while the output sink was blocked")
					case <-time.After(2300 * time.Millisecond):
					}
				}
				unblock()
			}
			var got result
			select {
			case got = <-done:
				received = true
			case <-time.After(8 * time.Second):
				t.Fatal("runner did not report redaction failure")
			}
			if stdout.writes.Load() == 0 || stdout.leaked.Load() {
				t.Fatalf("sink writes %d, leaked %t", stdout.writes.Load(), stdout.leaked.Load())
			}
			if got.calls != 1 || got.outcome == nil || got.outcome.ChildExit != tc.childExit {
				t.Fatalf("outcome %+v, calls %d, expected child exit %d", got.outcome, got.calls, tc.childExit)
			}
			if !tc.natural && (!stdout.redacted.Load() || got.outcome.Redactions != 1) {
				t.Fatal("redaction failure did not record the replacement")
			}
			if tc.accept {
				if got.code != 7 || got.outcome.PolicyState != "allow" || !strings.Contains(stdout.accepted.String(), "ready") || stderr.Len() != 0 {
					t.Fatal("slow output sink did not complete the natural exit")
				}
			} else {
				if got.code != 14 || got.outcome.PolicyState != "deny:redaction" || stdout.writes.Load() != 1 {
					t.Fatalf("exit %d, outcome %+v, sink writes %d", got.code, got.outcome, stdout.writes.Load())
				}
				if !strings.Contains(stderr.String(), "redaction failed") {
					t.Fatal("redaction failure diagnostic missing")
				}
			}
			for _, value := range encodingsOf(fxSecret) {
				if strings.Contains(stderr.String(), value) {
					t.Fatal("redaction failure diagnostic leaked a secret")
				}
			}
		})
	}
}

func TestDenyListMatchesVersionedInterpreters(t *testing.T) {
	local := itemcrypt.MetaPolicy{Sensitivity: "standard", CommandPolicy: "deny-shells"}
	for _, name := range []string{"python3.13", "python3", "perl5.36.0", "lua5.4", "node18", "ruby3.2", "php8.2", "bash"} {
		if ItemAllowsCommand(name, local, false) {
			t.Errorf("%s passed the default deny list", name)
		}
	}
	for _, name := range []string{"curl", "gh", "aws", "git", "s3cmd"} {
		if !ItemAllowsCommand(name, local, false) {
			t.Errorf("%s rejected by the default deny list", name)
		}
	}
	// An explicit allowCommands entry stays an exact-name whitelist.
	exact := itemcrypt.MetaPolicy{AllowCommands: []string{"python3"}}
	if ItemAllowsCommand("python3.13", exact, false) {
		t.Error("whitelist matched a versioned name it does not list")
	}
}
