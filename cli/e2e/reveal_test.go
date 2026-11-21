//go:build e2e

package e2e

import "testing"

// --reveal confirms on the controlling terminal and never on
// stdin/stdout. Without a terminal it refuses before decrypting; a
// terminal that answers anything but yes cancels (design §17.4).
func TestRevealRequiresControllingTerminal(t *testing.T) {
	_, _, env := localHome(t)
	if r := localRun(t, env, "", "init"); r.code != 0 {
		t.Fatalf("init exit %d: %s", r.code, r.stderr)
	}
	if r := localRun(t, env, localSecret, "set", "my-ref"); r.code != 0 {
		t.Fatalf("set exit %d: %s", r.code, r.stderr)
	}

	// No controlling terminal: refuse with the policy exit code and
	// print nothing.
	noTTY := localRunNoTTY(t, env, "get", "my-ref", "--reveal")
	if noTTY.code != 10 {
		t.Fatalf("reveal without a terminal exit %d, want 10: %s", noTTY.code, noTTY.stderr)
	}
	if noTTY.stdout != "" {
		t.Fatalf("refused reveal wrote to stdout: %q", noTTY.stdout)
	}
	assertNoLocalLeak(t, "reveal without a terminal", noTTY.stdout, noTTY.stderr)

	// A declined confirmation cancels the same way.
	declined := localRunTTY(t, env, "n\n", "get", "my-ref", "--reveal")
	if declined.code != 10 {
		t.Fatalf("declined reveal exit %d, want 10: %s", declined.code, declined.stderr)
	}
	if declined.stdout != "" {
		t.Fatalf("declined reveal wrote to stdout: %q", declined.stdout)
	}
	assertNoLocalLeak(t, "declined reveal", declined.stdout, declined.stderr)

	// An explicit yes still prints the raw bytes exactly once.
	confirmed := localRevealRun(t, env, "get", "my-ref", "--reveal")
	if confirmed.code != 0 || confirmed.stdout != localSecret {
		t.Fatalf("confirmed reveal = %q (exit %d): %s", confirmed.stdout, confirmed.code, confirmed.stderr)
	}
}
