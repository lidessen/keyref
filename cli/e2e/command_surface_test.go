//go:build e2e

package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalOnlyInstallNeverCreatesCache pins issue #7: the `keyref
// lock` flag is separate state in the data directory, and a local-only
// installation never grows the paired vault's cache.sqlite.
func TestLocalOnlyInstallNeverCreatesCache(t *testing.T) {
	home, _, env := localHome(t)
	if r := localRun(t, env, "", "init"); r.code != 0 {
		t.Fatalf("init exit %d: %s", r.code, r.stderr)
	}
	if r := localRun(t, env, localSecret, "set", "tok"); r.code != 0 {
		t.Fatalf("set exit %d: %s", r.code, r.stderr)
	}
	if r := localRun(t, env, "", "get", "tok"); r.code != 0 {
		t.Fatalf("get exit %d: %s", r.code, r.stderr)
	}

	// status reports the selected source and where its master key comes
	// from (design v0.10 §17.8).
	status := localRun(t, env, "", "status")
	if status.code != 0 {
		t.Fatalf("status exit %d: %s", status.code, status.stderr)
	}
	for _, want := range []string{"source: local (local)", "vault:", "(exists)", "key: keyring", "locked: no"} {
		if !strings.Contains(status.stdout, want) {
			t.Fatalf("status output missing %q:\n%s", want, status.stdout)
		}
	}

	// lock writes its flag outside the sync cache.
	if r := localRun(t, env, "", "lock"); r.code != 0 {
		t.Fatalf("lock exit %d: %s", r.code, r.stderr)
	}
	if _, err := os.Stat(filepath.Join(home, "locked")); err != nil {
		t.Fatalf("lock flag file missing from the data directory: %v", err)
	}
	lockedStatus := localRun(t, env, "", "status")
	if lockedStatus.code != 0 || !strings.Contains(lockedStatus.stdout, "locked: yes") {
		t.Fatalf("locked status: %d\n%s", lockedStatus.code, lockedStatus.stdout)
	}
	if r := localRun(t, env, "", "unlock"); r.code != 0 {
		t.Fatalf("unlock exit %d: %s", r.code, r.stderr)
	}

	// --all reports every configured source, still without a cache.
	all := localRun(t, env, "", "status", "--all")
	if all.code != 0 {
		t.Fatalf("status --all exit %d: %s", all.code, all.stderr)
	}
	for _, want := range []string{"source: local (local)", "source: sync (sync)", "pairing: not paired"} {
		if !strings.Contains(all.stdout, want) {
			t.Fatalf("status --all output missing %q:\n%s", want, all.stdout)
		}
	}

	if _, err := os.Stat(filepath.Join(home, "cache.sqlite")); !os.IsNotExist(err) {
		t.Fatalf("a local-only installation grew cache.sqlite (stat error: %v)", err)
	}
}

// TestHelpAndVersionAreSuccess pins issue #7: an explicit -h / --help
// prints help to stdout and exits 0, and the CLI reports one version
// value (design v0.10 §17.8).
func TestHelpAndVersionAreSuccess(t *testing.T) {
	_, _, env := localHome(t)
	for _, args := range [][]string{
		{"--help"}, {"help"},
		{"get", "--help"}, {"set", "-h"}, {"delete", "--help"}, {"init", "--help"},
		{"list", "--help"}, {"exec", "--help"}, {"status", "--help"},
		{"lock", "--help"}, {"unlock", "--help"}, {"mcp", "--help"},
		{"source", "add", "--help"},
	} {
		r := localRun(t, env, "", args...)
		if r.code != 0 {
			t.Fatalf("keyref %v exit %d, want 0: %s", args, r.code, r.stderr)
		}
		if strings.TrimSpace(r.stdout) == "" {
			t.Fatalf("keyref %v printed no help on stdout", args)
		}
	}

	// A real usage error is still exit 2, and stays on stderr.
	if r := localRun(t, env, "", "get", "--bogus"); r.code != 2 || r.stdout != "" {
		t.Fatalf("unknown flag: exit %d stdout %q, want 2 and empty stdout", r.code, r.stdout)
	}

	versionRun := localRun(t, env, "", "--version")
	if versionRun.code != 0 || !strings.HasPrefix(versionRun.stdout, "keyref ") {
		t.Fatalf("--version: exit %d stdout %q", versionRun.code, versionRun.stdout)
	}
}
