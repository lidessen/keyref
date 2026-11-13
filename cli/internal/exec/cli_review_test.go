package exec

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

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

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("sink closed") }

func TestRedactionFailureRecordsRealChildExit(t *testing.T) {
	req := &Request{
		EnvRefs:   []string{"K=openai-prod"},
		Argv:      []string{testBinary(t), "helper", "out-exit7"},
		ParentEnv: []string{"PATH=" + os.Getenv("PATH")},
		Refs:      map[string]*ResolvedRef{"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false)},
	}
	var got *Outcome
	req.OnOutcome = func(o *Outcome) { got = o }
	var stderr bytes.Buffer
	req.Stdout, req.Stderr = failWriter{}, &stderr
	if code := Run(req); code != 14 {
		t.Fatalf("exit %d stderr %q", code, stderr.String())
	}
	if got == nil || got.PolicyState != "deny:redaction" || got.ChildExit != 7 {
		t.Fatalf("outcome %+v", got)
	}
}

func TestPtyRedactionFailureRecordsChildExit(t *testing.T) {
	ptyAvailable(t)
	req := &Request{
		Pty:       true,
		EnvRefs:   []string{"K=openai-prod"},
		Argv:      []string{testBinary(t), "helper", "out-exit7"},
		ParentEnv: []string{"PATH=" + os.Getenv("PATH")},
		Refs:      map[string]*ResolvedRef{"openai-prod": mkRef(t, "openai-prod", fxSecret, true, false)},
	}
	var got *Outcome
	req.OnOutcome = func(o *Outcome) { got = o }
	var stderr bytes.Buffer
	req.Stdout, req.Stderr = failWriter{}, &stderr
	if code := Run(req); code != 14 {
		t.Fatalf("exit %d stderr %q", code, stderr.String())
	}
	if got == nil || got.PolicyState != "deny:redaction" || got.ChildExit != 7 {
		t.Fatalf("outcome %+v", got)
	}
}

func TestDenyListMatchesVersionedInterpreters(t *testing.T) {
	for _, name := range []string{"python3.13", "python3", "perl5.36.0", "lua5.4", "node18", "ruby3.2", "php8.2", "bash"} {
		if ItemAllowsCommand(name, nil) {
			t.Errorf("%s passed the default deny list", name)
		}
	}
	for _, name := range []string{"curl", "gh", "aws", "git", "s3cmd"} {
		if !ItemAllowsCommand(name, nil) {
			t.Errorf("%s rejected by the default deny list", name)
		}
	}
	// An explicit allowCommands entry stays an exact-name whitelist.
	if ItemAllowsCommand("python3.13", []string{"python3"}) {
		t.Error("whitelist matched a versioned name it does not list")
	}
}
