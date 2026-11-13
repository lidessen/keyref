//go:build e2e

package e2e

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The local source: one command surface over an offline vault. No
// server, no pairing, no grants, no approval round — the secret never
// leaves the machine except as an injected value for a child process.

const localSecret = "{{API_KEY_localref42}}"

// assertNoLocalLeak is assertNoLeak for the local fixture: the secret
// must not appear in any output, in any of its common encodings.
func assertNoLocalLeak(t *testing.T, where string, outputs ...string) {
	t.Helper()
	encodings := []string{
		localSecret,
		base64.StdEncoding.EncodeToString([]byte(localSecret)),
		strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(localSecret)), "="),
		base64.URLEncoding.EncodeToString([]byte(localSecret)),
		hex.EncodeToString([]byte(localSecret)),
	}
	for _, enc := range encodings {
		for _, out := range outputs {
			if strings.Contains(out, enc) {
				t.Fatalf("%s leaked the local fixture secret (%q…): %.120q", where, enc[:12], out)
			}
		}
	}
}

// localEnv points the CLI at a private data directory and keyring.
func localEnv(home, keyringDir string, extra ...string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"KEYREF_HOME=" + home,
		"KEYREF_KEYRING_DIR=" + keyringDir,
	}
	return append(env, extra...)
}

// localRun drives the real CLI binary with a given environment and stdin.
func localRun(t *testing.T, env []string, stdin string, args ...string) cliRun {
	t.Helper()
	cmd := exec.Command(cliBin, args...)
	cmd.Env = env
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err := cmd.Run()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("run keyref %v: %v", args, err)
	}
	return cliRun{stdout: out.String(), stderr: errBuf.String(), code: code}
}

func localHome(t *testing.T) (home, keyringDir string, env []string) {
	t.Helper()
	root := t.TempDir()
	home = filepath.Join(root, "home")
	keyringDir = filepath.Join(root, "keyring")
	return home, keyringDir, localEnv(home, keyringDir)
}

func TestLocalSourceLifecycle(t *testing.T) {
	home, _, env := localHome(t)

	// The source list names both sources, with the local one active.
	list := localRun(t, env, "", "source", "list")
	if list.code != 0 {
		t.Fatalf("source list exit %d: %s", list.code, list.stderr)
	}
	if !strings.Contains(list.stdout, "local") || !strings.Contains(list.stdout, "sync") {
		t.Fatalf("source list:\n%s", list.stdout)
	}
	if !strings.Contains(list.stdout, "(default)") {
		t.Fatalf("the local source is not the default:\n%s", list.stdout)
	}

	// init creates the vault and keeps the key in the keyring.
	init := localRun(t, env, "", "init")
	if init.code != 0 {
		t.Fatalf("init exit %d: %s", init.code, init.stderr)
	}
	if _, err := os.Stat(filepath.Join(home, "local.db")); err != nil {
		t.Fatalf("no vault file: %v", err)
	}

	// set stores the secret read from stdin; the output never carries it.
	set := localRun(t, env, localSecret, "set", "my-ref")
	if set.code != 0 {
		t.Fatalf("set exit %d: %s", set.code, init.stderr)
	}
	if strings.Contains(set.stdout, localSecret) || strings.Contains(set.stderr, localSecret) {
		t.Fatalf("set leaked the secret: %q %q", set.stdout, set.stderr)
	}

	// get shows a mask, never the value.
	get := localRun(t, env, "", "get", "my-ref")
	if get.code != 0 {
		t.Fatalf("get exit %d: %s", get.code, get.stderr)
	}
	if strings.Contains(get.stdout, localSecret) {
		t.Fatalf("get leaked the secret: %q", get.stdout)
	}
	if !strings.Contains(get.stdout, "masked:") || !strings.Contains(get.stdout, "my-ref") {
		t.Fatalf("get output:\n%s", get.stdout)
	}

	// The JSON view carries the mask and the size, not the value.
	getJSON := localRun(t, env, "", "get", "my-ref", "--format", "json")
	if getJSON.code != 0 {
		t.Fatalf("get --format json exit %d: %s", getJSON.code, getJSON.stderr)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(getJSON.stdout), &doc); err != nil {
		t.Fatalf("get --format json is not JSON: %v (%q)", err, getJSON.stdout)
	}
	if doc["ref"] != "my-ref" || doc["masked"] == "" {
		t.Fatalf("get --format json = %v", doc)
	}
	if _, ok := doc["value"]; ok {
		t.Fatalf("the JSON view carries a value field: %v", doc)
	}

	// --reveal is the explicit plaintext path, and it is byte-exact.
	reveal := localRun(t, env, "", "get", "my-ref", "--reveal")
	if reveal.code != 0 {
		t.Fatalf("get --reveal exit %d: %s", reveal.code, reveal.stderr)
	}
	if reveal.stdout != localSecret {
		t.Fatalf("get --reveal = %q, want %q", reveal.stdout, localSecret)
	}

	// --reveal and --format json are mutually exclusive.
	both := localRun(t, env, "", "get", "my-ref", "--reveal", "--format", "json")
	if both.code != 2 {
		t.Fatalf("get --reveal --format json exit %d, want 2", both.code)
	}

	// exec injects the value into the child and redacts it back out.
	ex := localRun(t, env, "", "exec", "--env", "K=my-ref", "--", helperBin, "print-env")
	if ex.code != 0 {
		t.Fatalf("exec exit %d: %s %s", ex.code, ex.stdout, ex.stderr)
	}
	if !strings.Contains(ex.stdout, "K=<redacted:my-ref>") {
		t.Fatalf("exec output is not redacted:\n%s", ex.stdout)
	}
	assertNoLocalLeak(t, "local exec", ex.stdout, ex.stderr)

	// The child's own exit code passes through.
	ex42 := localRun(t, env, "", "exec", "--env", "K=my-ref", "--", helperBin, "exit42")
	if ex42.code != 42 {
		t.Fatalf("exec exit code %d, want 42", ex42.code)
	}

	// An unknown ref is exit 11, in get and in exec alike.
	unknown := localRun(t, env, "", "get", "nope")
	if unknown.code != 11 {
		t.Fatalf("get of an unknown ref exit %d, want 11", unknown.code)
	}
	unknownExec := localRun(t, env, "", "exec", "--env", "K=nope", "--", helperBin, "print-env")
	if unknownExec.code != 11 {
		t.Fatalf("exec with an unknown ref exit %d, want 11", unknownExec.code)
	}

	// delete removes the entry.
	del := localRun(t, env, "", "delete", "my-ref")
	if del.code != 0 {
		t.Fatalf("delete exit %d: %s", del.code, del.stderr)
	}
	gone := localRun(t, env, "", "get", "my-ref")
	if gone.code != 11 {
		t.Fatalf("get after delete exit %d, want 11", gone.code)
	}
}

// A local vault keeps its refs one-way, so there is nothing to list.
func TestLocalSourceCannotBeListed(t *testing.T) {
	_, _, env := localHome(t)
	list := localRun(t, env, "", "list")
	if list.code != 2 {
		t.Fatalf("list on a local source exit %d, want 2", list.code)
	}
	if !strings.Contains(list.stderr, "one-way") {
		t.Fatalf("list did not explain itself: %q", list.stderr)
	}
}

// The paired vault is read-only for the CLI, and it has no reveal path
// at all.
func TestPairedSourceRejectsWritesAndReveal(t *testing.T) {
	_, _, env := localHome(t)
	set := localRun(t, env, localSecret, "set", "my-ref", "--source", "sync")
	if set.code != 2 {
		t.Fatalf("set on the paired vault exit %d, want 2", set.code)
	}
	if !strings.Contains(set.stderr, "read-only") {
		t.Fatalf("set did not explain itself: %q", set.stderr)
	}
	del := localRun(t, env, "", "delete", "my-ref", "--source", "sync")
	if del.code != 2 {
		t.Fatalf("delete on the paired vault exit %d, want 2", del.code)
	}
	reveal := localRun(t, env, "", "get", "my-ref", "--reveal", "--source", "sync")
	if reveal.code != 2 {
		t.Fatalf("get --reveal on the paired vault exit %d, want 2", reveal.code)
	}
}

// The deny-shells policy and the argv rules apply to local sources too.
func TestLocalSourceKeepsTheExecPolicy(t *testing.T) {
	_, _, env := localHome(t)
	if run := localRun(t, env, "", "init"); run.code != 0 {
		t.Fatalf("init exit %d: %s", run.code, run.stderr)
	}
	if run := localRun(t, env, localSecret, "set", "my-ref"); run.code != 0 {
		t.Fatalf("set exit %d: %s", run.code, run.stderr)
	}
	shell := localRun(t, env, "", "exec", "--env", "K=my-ref", "--", "/bin/sh", "-c", "echo hi")
	if shell.code != 10 {
		t.Fatalf("exec through a shell exit %d, want 10", shell.code)
	}
	argv := localRun(t, env, "", "exec", "--allow-argv", "--env", "K=my-ref", "--",
		helperBin, "{{keyref:my-ref}}")
	if argv.code != 10 {
		t.Fatalf("exec with an argv placeholder exit %d, want 10", argv.code)
	}
}

// The headless path: KEYREF_LOCAL_MASTER replaces the keyring entirely,
// and keyref copies no key material into it.
func TestLocalSourceWithAnEnvironmentKey(t *testing.T) {
	home, keyringDir, env := localHome(t)
	master := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 32))
	env = localEnv(home, keyringDir, "KEYREF_LOCAL_MASTER="+master)

	if run := localRun(t, env, "", "init"); run.code != 0 {
		t.Fatalf("init exit %d: %s", run.code, run.stderr)
	}
	if run := localRun(t, env, localSecret, "set", "my-ref"); run.code != 0 {
		t.Fatalf("set exit %d: %s", run.code, run.stderr)
	}
	reveal := localRun(t, env, "", "get", "my-ref", "--reveal")
	if reveal.code != 0 || reveal.stdout != localSecret {
		t.Fatalf("get --reveal = %q (exit %d): %s", reveal.stdout, reveal.code, reveal.stderr)
	}
	entries, err := os.ReadDir(keyringDir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("an environment-provided key was copied into the keyring: %v", entries)
	}
}

// Several local vaults can coexist; --source, KEYREF_SOURCE and the
// configured default each pick one.
func TestLocalSourceSelection(t *testing.T) {
	_, _, env := localHome(t)
	workDir := t.TempDir()
	// A local vault's parent directory must be private.
	if err := os.Chmod(workDir, 0o700); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(workDir, "work.db")

	add := localRun(t, env, "", "source", "add", "work", "--path", other)
	if add.code != 0 {
		t.Fatalf("source add exit %d: %s", add.code, add.stderr)
	}
	if run := localRun(t, env, "", "init", "--source", "work"); run.code != 0 {
		t.Fatalf("init --source work exit %d: %s", run.code, run.stderr)
	}
	if run := localRun(t, env, localSecret, "set", "my-ref", "--source", "work"); run.code != 0 {
		t.Fatalf("set --source work exit %d: %s", run.code, run.stderr)
	}

	// The default source is still the built-in local vault, which has
	// no vault file yet in this data directory.
	missing := localRun(t, env, "", "get", "my-ref")
	if missing.code != 1 {
		t.Fatalf("get on the uninitialized default source exit %d, want 1", missing.code)
	}
	if !strings.Contains(missing.stderr, "keyref init") {
		t.Fatalf("get did not say how to fix it: %q", missing.stderr)
	}
	// --source finds it.
	byFlag := localRun(t, env, "", "get", "my-ref", "--source", "work", "--reveal")
	if byFlag.code != 0 || byFlag.stdout != localSecret {
		t.Fatalf("get --source work = %q (exit %d): %s", byFlag.stdout, byFlag.code, byFlag.stderr)
	}
	// KEYREF_SOURCE finds it too.
	byEnv := localRun(t, append(env, "KEYREF_SOURCE=work"), "", "get", "my-ref", "--reveal")
	if byEnv.code != 0 || byEnv.stdout != localSecret {
		t.Fatalf("get with KEYREF_SOURCE = %q (exit %d): %s", byEnv.stdout, byEnv.code, byEnv.stderr)
	}
	// And so does the configured default.
	if run := localRun(t, env, "", "source", "default", "work"); run.code != 0 {
		t.Fatalf("source default exit %d: %s", run.code, run.stderr)
	}
	byDefault := localRun(t, env, "", "get", "my-ref", "--reveal")
	if byDefault.code != 0 || byDefault.stdout != localSecret {
		t.Fatalf("get on the new default = %q (exit %d): %s", byDefault.stdout, byDefault.code, byDefault.stderr)
	}
	// Removing the source drops it from the configuration; the vault
	// file itself stays.
	if run := localRun(t, env, "", "source", "remove", "work"); run.code != 0 {
		t.Fatalf("source remove exit %d: %s", run.code, run.stderr)
	}
	if _, err := os.Stat(other); err != nil {
		t.Fatalf("removing a source deleted its vault file: %v", err)
	}
}
