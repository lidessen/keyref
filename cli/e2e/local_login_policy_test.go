//go:build e2e

package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLocalLoginAndPolicyOptIn(t *testing.T) {
	_, _, env := localHome(t)
	if r := localRun(t, env, "", "init"); r.code != 0 {
		t.Fatalf("init: %s", r.stderr)
	}
	const user, password = "fixture-user", "fixture-password"
	if r := localRun(t, env, password, "set", "login", "--username", user, "--url", "https://example.test", "--allow-command", filepath.Base(helperBin), "--allow-argv"); r.code != 0 {
		t.Fatalf("set: %s", r.stderr)
	}
	for _, args := range [][]string{{"get", "login", "--format", "json"}, {"list", "--format", "json"}} {
		r := localRun(t, env, "", args...)
		if r.code != 0 || !json.Valid([]byte(r.stdout)) || !strings.Contains(r.stdout, user) || !strings.Contains(r.stdout, "https://example.test") || strings.Contains(r.stdout, password) {
			t.Fatalf("metadata: exit %d %s %s", r.code, r.stdout, r.stderr)
		}
	}
	digest := sha256.Sum256([]byte(user + "\n" + password + "\n"))
	r := localRun(t, env, "", "exec", "--stdin-login", "login", "--", helperBin, "login", hex.EncodeToString(digest[:]))
	if r.code != 0 || r.stdout != "***\n***\n" || strings.Contains(r.stderr, user) || strings.Contains(r.stderr, password) {
		t.Fatalf("login exit %d: %q %q", r.code, r.stdout, r.stderr)
	}
	r = localRun(t, env, "", "exec", "--env", "K=login", "--", helperBin, "print-env")
	if r.code != 0 || !strings.Contains(r.stdout, "<redacted:login>") || strings.Contains(r.stdout, password) {
		t.Fatalf("env: %d %q %q", r.code, r.stdout, r.stderr)
	}
	r = localRun(t, env, "", "exec", "--allow-argv", "--", helperBin, "{{keyref:login}}")
	if r.code != 0 || strings.Contains(r.stdout, password) {
		t.Fatalf("argv: %d %q %q", r.code, r.stdout, r.stderr)
	}
	r = localRun(t, env, "", "exec", "--", helperBin, "{{keyref:login}}")
	if r.code != 10 {
		t.Fatalf("argv without consent: %d", r.code)
	}
	r = localRun(t, env, "", "exec", "--stdin-login", "login", "--", filepath.Base(helperBin), "login", hex.EncodeToString(digest[:]))
	if r.code != 10 {
		t.Fatalf("relative login path: %d", r.code)
	}
	if python, err := exec.LookPath("python3"); err == nil {
		if r = localRun(t, env, password, "set", "python-secret", "--allow-command", "python3"); r.code != 0 {
			t.Fatal(r.stderr)
		}
		r = localRun(t, env, "", "exec", "--env", "K=python-secret", "--", python, "-c", "import os; print(os.environ['K'])")
		if r.code != 0 || !strings.Contains(r.stdout, "<redacted:python-secret>") || strings.Contains(r.stdout, password) {
			t.Fatalf("python: %d %q %q", r.code, r.stdout, r.stderr)
		}
		r = localRun(t, env, "", "exec", "--allow-argv", "--", python, "-c", "pass", "{{keyref:python-secret}}")
		if r.code != 10 {
			t.Fatalf("argv without item consent: %d", r.code)
		}
	}
	if r = localRun(t, env, password, "set", "plain", "--allow-command", filepath.Base(helperBin)); r.code != 0 {
		t.Fatal(r.stderr)
	}
	r = localRun(t, env, "", "exec", "--stdin-login", "plain", "--", helperBin, "login", hex.EncodeToString(digest[:]))
	if r.code != 15 {
		t.Fatalf("non-login: %d %s", r.code, r.stderr)
	}
}

func TestLocalLoginFields(t *testing.T) {
	_, _, env := localHome(t)
	if r := localRun(t, env, "", "init"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	const user, password = "fixture-user", "fixture-password"
	if r := localRun(t, env, password, "set", "login", "--type", "login", "--username", user, "--url", "https://example.test", "--allow-command", filepath.Base(helperBin), "--allow-argv"); r.code != 0 {
		t.Fatal(r.stderr)
	}
	r := localRun(t, env, "", "get", "login")
	if r.code != 0 || !strings.Contains(r.stdout, "username: "+user) || !strings.Contains(r.stdout, "url: https://example.test") {
		t.Fatalf("get: %d %q %q", r.code, r.stdout, r.stderr)
	}
	digest := sha256.Sum256([]byte(user + "\n" + password))
	hash := hex.EncodeToString(digest[:])
	for _, args := range [][]string{
		{"exec", "--env", "USER=login.username", "--env", "PASS=login.password", "--", helperBin, "fields", "env", hash},
		{"exec", "--fd", "3=login.username", "--fd", "4=login.password", "--fd-raw", "--", helperBin, "fields", "fd", hash},
		{"exec", "--stdin", "login.username", "--env", "PASS=login.password", "--", helperBin, "fields", "stdin", hash},
		{"exec", "--allow-argv", "--", helperBin, "fields-argv", "{{keyref:login.username}}", "{{keyref:login.password}}", hash},
	} {
		r := localRun(t, env, "", args...)
		if r.code != 0 || strings.Contains(r.stdout+r.stderr, user) || strings.Contains(r.stdout+r.stderr, password) || !strings.Contains(r.stdout, "redacted") || !strings.Contains(r.stderr, "redacted") {
			t.Fatalf("%v: exit %d stdout %q stderr %q", args, r.code, r.stdout, r.stderr)
		}
	}
	// Even a field not selected for injection must be a redaction target.
	one := localRun(t, env, "", "exec", "--env", "USER=login.username", "--", helperBin, "echo-env-and-arg", password)
	if one.code != 0 || strings.Contains(one.stdout+one.stderr, user) || strings.Contains(one.stdout+one.stderr, password) || !strings.Contains(one.stdout, "redacted") || !strings.Contains(one.stderr, "redacted") {
		t.Fatalf("single field: %d %q %q", one.code, one.stdout, one.stderr)
	}
	if r := localRun(t, env, password, "set", "plain", "--allow-command", filepath.Base(helperBin)); r.code != 0 {
		t.Fatal(r.stderr)
	}
	for _, field := range []string{"username", "password"} {
		r := localRun(t, env, "", "exec", "--env", "K=plain."+field, "--", helperBin, "exit42")
		if r.code != 15 || !strings.Contains(r.stderr, "requires a login item") {
			t.Fatalf("non-login %s: %d %q", field, r.code, r.stderr)
		}
	}
	for _, args := range [][]string{{"set", "invalid", "--type", "unknown"}, {"set", "invalid", "--type", "login"}, {"set", "invalid", "--type", "secret", "--username", user}} {
		if r := localRun(t, env, password, args...); r.code != 2 {
			t.Fatalf("%v: %d %q", args, r.code, r.stderr)
		}
	}
	m := startLocalMCP(t, env)
	m.call(t, "initialize", map[string]any{"protocolVersion": "2024-11-05"})
	text := mcpText(t, m.tool(t, "exec", map[string]any{"argv": []any{helperBin, "fields", "env", hash}, "env": map[string]any{"USER": "login.username", "PASS": "login.password"}}))
	if !strings.Contains(text, "exit_code: 0") || strings.Contains(text, user) || strings.Contains(text, password) {
		t.Fatalf("MCP exec: %q", text)
	}
}
