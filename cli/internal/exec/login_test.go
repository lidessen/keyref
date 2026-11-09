package exec

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	osexec "os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lidessen/keyref/cli/internal/exitcode"
	"github.com/lidessen/keyref/cli/internal/itemcrypt"
	"github.com/lidessen/keyref/cli/internal/secret"
)

const (
	loginFixtureRef = "login-fixture"
	usernameFixture = "tester-72a9c7"
	passwordFixture = "p4ss-74d6c8!"
	providerFixture = "provider-24e93c"
)

func checkLoginStdin() {
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		os.Exit(30)
	}
	input, err := io.ReadAll(io.LimitReader(os.Stdin, 2051))
	digest := sha256.Sum256(input)
	if err != nil || hex.EncodeToString(digest[:]) != os.Getenv("LOGIN_TEST_DIGEST") {
		os.Exit(31)
	}
	if strconv.Itoa(syscall.Getpgrp()) != os.Getenv("LOGIN_TEST_GROUP") {
		os.Exit(32)
	}
	lines := bytes.Split(input, []byte("\n"))
	if len(lines) != 3 || len(lines[2]) != 0 || os.Getenv("PROVIDER_CREDENTIAL") != providerFixture {
		os.Exit(33)
	}
	for _, text := range append(os.Environ(), os.Args...) {
		if strings.Contains(text, string(lines[0])) || strings.Contains(text, string(lines[1])) {
			os.Exit(34)
		}
	}
	// Exercise the stream redactors, including an encoded echo.
	fmt.Fprintf(os.Stdout, "username=%s\n", lines[0])
	fmt.Fprintf(os.Stderr, "value=%s\n", base64.StdEncoding.EncodeToString(lines[1]))
}

func loginRequest(t *testing.T, username string, password string) (*Request, *int) {
	t.Helper()
	bin := testBinary(t)
	login := &ResolvedRef{
		Ref: loginFixtureRef,
		Meta: &itemcrypt.Meta{
			Injectable: true,
			Policy:     itemcrypt.MetaPolicy{AllowCommands: []string{filepath.Base(bin)}},
		},
	}
	var calls int
	return &Request{
		Argv:     []string{bin, "helper", "check-login"},
		LoginRef: loginFixtureRef,
		Refs:     map[string]*ResolvedRef{loginFixtureRef: login},
		ResolveValue: func(ref string) (*secret.Plaintext, int, string) {
			calls++
			if ref != loginFixtureRef {
				t.Error("unexpected login reference")
				return nil, 1, "internal"
			}
			var err error
			login.Username, err = secret.NewPlaintextFromBytes([]byte(username))
			if err != nil {
				t.Error("could not allocate username fixture")
				return nil, 1, "internal"
			}
			value, err := secret.NewPlaintextFromBytes([]byte(password))
			if err != nil {
				t.Error("could not allocate value fixture")
				return nil, 1, "internal"
			}
			return value, 0, ""
		},
	}, &calls
}

func TestStdinLoginPipeAndRedaction(t *testing.T) {
	// A reference that equals the username must not reappear in a marker.
	req, calls := loginRequest(t, loginFixtureRef, passwordFixture)
	expected := sha256.Sum256([]byte(loginFixtureRef + "\n" + passwordFixture + "\n"))
	req.PassNames = []string{"LOGIN_TEST_DIGEST", "LOGIN_TEST_GROUP"}
	req.ParentEnv = []string{"LOGIN_TEST_DIGEST=" + hex.EncodeToString(expected[:]), "LOGIN_TEST_GROUP=" + strconv.Itoa(syscall.Getpgrp())}
	provider, err := secret.NewPlaintextFromBytes([]byte(providerFixture))
	if err != nil {
		t.Fatal("could not allocate provider fixture")
	}
	req.EnvRefs = []string{"PROVIDER_CREDENTIAL=provider"}
	req.Refs["provider"] = &ResolvedRef{Meta: &itemcrypt.Meta{Injectable: true}, Value: provider}
	code, stdout, stderr := runReq(req)
	if code != 0 || *calls != 1 {
		t.Fatalf("login process exit %d with %d login resolutions", code, *calls)
	}
	if stdout != "username=***\n" || stderr != "value=***\n" {
		t.Fatal("login output did not redact each field independently")
	}
	if len(req.Refs[loginFixtureRef].Username.Bytes()) != 0 || len(req.Refs[loginFixtureRef].Value.Bytes()) != 0 {
		t.Fatal("login buffers remained allocated after child exit")
	}
}

func TestStdinLoginRejectsInvalidFields(t *testing.T) {
	cases := []struct {
		name     string
		username string
		value    string
	}{
		{"missing-username", "", passwordFixture},
		{"empty-value", usernameFixture, ""},
		{"embedded-newline", usernameFixture, "line\nbreak"},
		{"trailing-carriage-return", usernameFixture + "\r", passwordFixture},
		{"nul", usernameFixture, "bad\x00value"},
		{"invalid-utf8", usernameFixture, "\xff"},
		{"oversize", strings.Repeat("x", 1025), passwordFixture},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, calls := loginRequest(t, tc.username, tc.value)
			var outcome *Outcome
			req.OnOutcome = func(o *Outcome) { outcome = o }
			code, stdout, _ := runReq(req)
			if code != exitcode.InjectionInvalid || stdout != "" || *calls != 1 || outcome.ChildExit != childNotStarted {
				t.Fatalf("invalid login reached child or used wrong exit code (%d)", code)
			}
		})
	}
}

func TestStdinLoginChecksPolicyBeforeResolving(t *testing.T) {
	cases := map[string]func(*Request){
		"no-explicit-allow": func(req *Request) { req.Refs[loginFixtureRef].Meta.Policy.AllowCommands = nil },
		"relative-child":    func(req *Request) { req.Argv[0] = filepath.Base(req.Argv[0]) },
		"same-stdin":        func(req *Request) { req.StdinRef = "other" },
		"same-env-value":    func(req *Request) { req.EnvRefs = []string{"K=" + loginFixtureRef} },
		"same-fd-value":     func(req *Request) { req.FdRefs = []string{"3=" + loginFixtureRef} },
		"same-argv-value":   func(req *Request) { req.Argv = append(req.Argv, "{{keyref:"+loginFixtureRef+"}}") },
		"pty":               func(req *Request) { req.Pty = true },
	}
	for name, alter := range cases {
		t.Run(name, func(t *testing.T) {
			req, calls := loginRequest(t, usernameFixture, passwordFixture)
			alter(req)
			code, stdout, _ := runReq(req)
			if code != exitcode.PolicyRejection || stdout != "" || *calls != 0 {
				t.Fatalf("policy rejection returned %d and performed %d resolutions", code, *calls)
			}
		})
	}
}

func runLoginForCancellation(marker string) {
	bin, err := os.Executable()
	if err != nil {
		os.Exit(35)
	}
	username, err := secret.NewPlaintextFromBytes([]byte(usernameFixture))
	if err != nil {
		os.Exit(36)
	}
	value, err := secret.NewPlaintextFromBytes([]byte(passwordFixture))
	if err != nil {
		username.Destroy()
		os.Exit(37)
	}
	code := Run(&Request{
		Argv:     []string{bin, "helper", "hold-login", marker},
		LoginRef: loginFixtureRef,
		Refs: map[string]*ResolvedRef{loginFixtureRef: {
			Username: username,
			Value:    value,
			Meta: &itemcrypt.Meta{
				Injectable: true,
				Policy:     itemcrypt.MetaPolicy{AllowCommands: []string{filepath.Base(bin)}},
			},
		}},
		Stdout: io.Discard,
		Stderr: io.Discard,
	})
	os.Exit(code)
}

func holdLoginForCancellation(marker string) {
	if _, err := io.Copy(io.Discard, os.Stdin); err != nil {
		os.Exit(38)
	}
	if err := os.WriteFile(marker, []byte(strconv.Itoa(os.Getpid())), 0o600); err != nil {
		os.Exit(39)
	}
	time.Sleep(time.Minute)
}

func TestStdinLoginCancellationReapsDirectChild(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "child-pid")
	cmd := osexec.Command(testBinary(t), "helper", "run-login", marker)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal("could not launch login cancellation fixture")
	}
	defer func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	deadline := time.Now().Add(5 * time.Second)
	var pid int
	for time.Now().Before(deadline) && pid == 0 {
		if raw, err := os.ReadFile(marker); err == nil {
			pid, _ = strconv.Atoi(string(raw))
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("login cancellation child did not start")
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal("could not cancel login parent")
	}
	select {
	case err := <-done:
		ee, ok := err.(*osexec.ExitError)
		if !ok || ee.ExitCode() != 128+int(syscall.SIGKILL) {
			t.Fatal("login parent did not return the cancelled child status")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("login parent did not settle cancellation")
	}
	if err := syscall.Kill(pid, 0); err != syscall.ESRCH {
		t.Fatal("login child still exists after parent returned")
	}
}
