package exec

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	osexec "os/exec"

	"github.com/lidessen/keyref/cli/internal/itemcrypt"
)

// localPolicy is the synthetic policy a local source gets: no per-item
// record, the built-in deny list applies (design.md §7.3).
func localPolicy() itemcrypt.MetaPolicy {
	return itemcrypt.MetaPolicy{Sensitivity: "standard", CommandPolicy: "deny-shells"}
}

// truePath resolves a real, allowed binary for interpreter chains
// (macOS has /usr/bin/true, Linux /bin/true).
func truePath(t *testing.T) string {
	t.Helper()
	p, err := osexec.LookPath("true")
	if err != nil {
		t.Skip("no true binary on PATH")
	}
	return p
}

func writeScript(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestDenyListRejectsShellsAndDumps(t *testing.T) {
	// Use the test binary's own directory structure: resolve real
	// system tools through PATH.
	for _, name := range []string{"sh", "echo", "cat", "env", "base64"} {
		_, err := CheckCommand([]string{name}, os.Getenv("PATH"), localPolicy(), false)
		if !isPolicyErr(err) {
			t.Fatalf("%s: expected policy rejection, got %v", name, err)
		}
	}
}

func TestAllowCommandsWhitelistOverridesDeny(t *testing.T) {
	// A whitelisted name overrides the default denial
	// (design.md §7.3).
	echoOnly := itemcrypt.MetaPolicy{AllowCommands: []string{"echo"}}
	_, err := CheckCommand([]string{"echo"}, os.Getenv("PATH"), echoOnly, false)
	if err != nil {
		t.Fatalf("whitelisted echo rejected: %v", err)
	}
	// A non-empty whitelist excludes everything else.
	_, err = CheckCommand([]string{"ls"}, os.Getenv("PATH"), echoOnly, false)
	if !isPolicyErr(err) {
		t.Fatalf("non-whitelisted ls accepted: %v", err)
	}
}

// TestPairedVaultRequiresExplicitAllowCommands pins protocol v2 §H: the
// built-in deny list is no longer a fallback on the paired vault.
func TestPairedVaultRequiresExplicitAllowCommands(t *testing.T) {
	// Empty allowCommands + the default commandPolicy: nothing runs,
	// including commands the deny list would never have caught.
	if ItemAllowsCommand("curl", localPolicy(), true) {
		t.Fatal("paired vault: an empty allowCommands list must allow nothing")
	}
	if ItemAllowsCommand("sh", localPolicy(), true) {
		t.Fatal("paired vault: sh must not pass an empty allowCommands list")
	}
	// The refusal names iOS as the place to fix it.
	_, err := CheckCommand([]string{"true"}, os.Getenv("PATH"), localPolicy(), true)
	var pe *PolicyError
	if !errors.As(err, &pe) || !strings.Contains(pe.Reason, "iOS") {
		t.Fatalf("paired-vault denial must point at iOS: %v", err)
	}

	// A non-empty list stays an exact whitelist.
	curlOnly := itemcrypt.MetaPolicy{CommandPolicy: "deny-shells", AllowCommands: []string{"curl"}}
	if !ItemAllowsCommand("curl", curlOnly, true) || ItemAllowsCommand("sh", curlOnly, true) {
		t.Fatal("paired vault: allowCommands must stay an exact whitelist")
	}

	// commandPolicy = allow-all is the owner's explicit opt-out: any
	// command passes an empty list.
	open := itemcrypt.MetaPolicy{CommandPolicy: CommandPolicyAllowAll}
	if !ItemAllowsCommand("sh", open, true) {
		t.Fatal("paired vault: commandPolicy=allow-all must allow any command")
	}
	// A whitelist still tightens an allow-all item: listing can only
	// narrow.
	openButListed := itemcrypt.MetaPolicy{CommandPolicy: CommandPolicyAllowAll, AllowCommands: []string{"curl"}}
	if ItemAllowsCommand("sh", openButListed, true) {
		t.Fatal("allowCommands must still win over allow-all")
	}
	// Unknown or missing commandPolicy values fail closed.
	if ItemAllowsCommand("curl", itemcrypt.MetaPolicy{}, true) {
		t.Fatal("an empty commandPolicy must keep the paired vault strict")
	}

	// The local source keeps the built-in deny list.
	if ItemAllowsCommand("sh", localPolicy(), false) || !ItemAllowsCommand("curl", localPolicy(), false) {
		t.Fatal("local source must keep the built-in deny list")
	}
}

func TestShebangFollowedAndDenied(t *testing.T) {
	dir := t.TempDir()
	shScript := writeScript(t, dir, "innocent", "#!/bin/sh\necho hi\n", 0o755)
	_, err := CheckCommand([]string{shScript}, "", localPolicy(), false)
	if !isPolicyErr(err) {
		t.Fatalf("#!/bin/sh script accepted: %v", err)
	}

	// /usr/bin/env python3 indirection checks env AND python3
	// (design.md §7.3 step 2).
	if _, err := os.Stat("/usr/bin/env"); err == nil {
		if _, err := osexec.LookPath("python3"); err == nil {
			pyScript := writeScript(t, dir, "pyscript", "#!/usr/bin/env python3\nprint(1)\n", 0o755)
			_, err := CheckCommand([]string{pyScript}, os.Getenv("PATH"), localPolicy(), false)
			if !isPolicyErr(err) {
				t.Fatalf("#!/usr/bin/env python3 script accepted: %v", err)
			}
		}
	}

	// A harmless custom interpreter chain is allowed: owninterp runs
	// under `true` (not in the deny list).
	ownInterp := writeScript(t, dir, "owninterp", "#!"+truePath(t)+"\n", 0o755)
	_ = ownInterp
	benign := writeScript(t, dir, "benign", "#!"+filepath.Join(dir, "owninterp")+"\n", 0o755)
	if _, err := CheckCommand([]string{benign}, "", localPolicy(), false); err != nil {
		t.Fatalf("benign script chain rejected: %v", err)
	}
}

func TestSetgidRejected(t *testing.T) {
	dir := t.TempDir()
	p := writeScript(t, dir, "setgidtool", "#!"+truePath(t)+"\n", 0o755)
	// The setgid bit only sticks when the file's group is one of ours
	// (macOS chgrp to the login group makes chmod 2755 effective).
	if err := os.Chown(p, -1, ownGroupID(t)); err != nil {
		t.Skipf("cannot chgrp test file: %v", err)
	}
	if err := os.Chmod(p, 0o2755); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(p); err != nil || fi.Mode()&os.ModeSetgid == 0 {
		t.Skip("platform dropped the setgid bit; nothing to test")
	}
	_, err := CheckCommand([]string{p}, "", localPolicy(), false)
	if !isStartErr(err) {
		t.Fatalf("setgid file accepted: %v", err)
	}
}

func ownGroupID(t *testing.T) int {
	t.Helper()
	fi, err := os.Stat(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Gid)
	}
	t.Skip("cannot determine group id")
	return 0
}

func TestUnresolvableFailsClosed(t *testing.T) {
	_, err := CheckCommand([]string{"definitely-not-a-real-binary-xyz"}, os.Getenv("PATH"), localPolicy(), false)
	if !isStartErr(err) {
		t.Fatalf("unresolvable argv0 accepted: %v", err)
	}
	dir := t.TempDir()
	_, err = CheckCommand([]string{filepath.Join(dir, "missing")}, "", localPolicy(), false)
	if !isStartErr(err) {
		t.Fatalf("missing path accepted: %v", err)
	}
	// Non-executable files are rejected too.
	p := writeScript(t, dir, "noexec", "#!"+truePath(t)+"\n", 0o644)
	_, err = CheckCommand([]string{p}, "", localPolicy(), false)
	if !isStartErr(err) {
		t.Fatalf("non-executable accepted: %v", err)
	}
}

func TestSymlinkDisguiseResolved(t *testing.T) {
	dir := t.TempDir()
	target := writeScript(t, dir, "realtarget", "#!"+truePath(t)+"\n", 0o755)
	link := filepath.Join(dir, "mytool")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckCommand([]string{link}, "", localPolicy(), false); err != nil {
		t.Fatalf("symlinked benign tool rejected: %v", err)
	}
	// A symlink named innocently but pointing at a denied binary is
	// judged by the real path (design.md §7.3 step 3).
	shLink := filepath.Join(dir, "not-a-shell")
	if err := os.Symlink("/bin/sh", shLink); err != nil {
		t.Skip("/bin/sh not present")
	}
	_, err := CheckCommand([]string{shLink}, "", localPolicy(), false)
	if !isPolicyErr(err) {
		t.Fatalf("disguised sh accepted: %v", err)
	}
}

func TestPATHSearchMatchesExecvp(t *testing.T) {
	dir := t.TempDir()
	writeScript(t, dir, "pathsearched", "#!"+truePath(t)+"\n", 0o755)
	if _, err := CheckCommand([]string{"pathsearched"}, dir, localPolicy(), false); err != nil {
		t.Fatalf("PATH search failed: %v", err)
	}
}

func TestAllowedHostsExactMatchOnly(t *testing.T) {
	argv := []string{"tool", "https://api.openai.com/v1"}
	if err := allowedHostsFromArgv(argv, []string{"api.openai.com"}); err != nil {
		t.Fatalf("exact host rejected: %v", err)
	}
	if err := allowedHostsFromArgv(argv, nil); err != nil {
		t.Fatalf("empty host list must mean no check: %v", err)
	}
	bad := []string{"tool", "https://api.openai.com.evil.example/x"}
	if err := allowedHostsFromArgv(bad, []string{"api.openai.com"}); err == nil {
		t.Fatal("suffix-spoofed host accepted")
	}
	other := []string{"tool", "https://evil.example/x"}
	if err := allowedHostsFromArgv(other, []string{"api.openai.com"}); err == nil {
		t.Fatal("foreign host accepted")
	}
	creds := []string{"tool", "https://user@api.openai.com/x"}
	if err := allowedHostsFromArgv(creds, []string{"api.openai.com"}); err != nil {
		t.Fatalf("host with credentials rejected: %v", err)
	}
}
