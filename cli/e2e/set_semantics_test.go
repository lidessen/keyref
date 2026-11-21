//go:build e2e

package e2e

import (
	"strings"
	"testing"
)

// TestSetValueSemantics pins design §17.4: `set` strips exactly one
// trailing newline by default, `--raw` keeps every byte, and the output
// says whether the row was created or replaced.
func TestSetValueSemantics(t *testing.T) {
	_, _, env := localHome(t)
	if r := localRun(t, env, "", "init"); r.code != 0 {
		t.Fatalf("init exit %d: %s", r.code, r.stderr)
	}

	// `echo "$TOKEN" | keyref set tok` stores the token itself.
	set := localRun(t, env, localSecret+"\n", "set", "trimmed")
	if set.code != 0 {
		t.Fatalf("set exit %d: %s", set.code, set.stderr)
	}
	if !strings.Contains(set.stdout, `created "trimmed"`) {
		t.Fatalf("set did not report creation: %q", set.stdout)
	}
	reveal := localRevealRun(t, env, "get", "trimmed", "--reveal")
	if reveal.code != 0 || reveal.stdout != localSecret {
		t.Fatalf("stored value %q (exit %d), want the token without its newline", reveal.stdout, reveal.code)
	}

	// --raw keeps the trailing newline.
	raw := localRun(t, env, localSecret+"\n", "set", "--raw", "raw")
	if raw.code != 0 {
		t.Fatalf("set --raw exit %d: %s", raw.code, raw.stderr)
	}
	reveal = localRevealRun(t, env, "get", "raw", "--reveal")
	if reveal.code != 0 || reveal.stdout != localSecret+"\n" {
		t.Fatalf("--raw value %q (exit %d), want the newline preserved", reveal.stdout, reveal.code)
	}

	// A second set replaces, and a CRLF ending is also stripped.
	replace := localRun(t, env, localSecret+"\r\n", "set", "trimmed")
	if replace.code != 0 {
		t.Fatalf("second set exit %d: %s", replace.code, replace.stderr)
	}
	if !strings.Contains(replace.stdout, `replaced "trimmed"`) {
		t.Fatalf("second set did not report replacement: %q", replace.stdout)
	}
	reveal = localRevealRun(t, env, "get", "trimmed", "--reveal")
	if reveal.code != 0 || reveal.stdout != localSecret {
		t.Fatalf("CRLF value %q (exit %d), want the token without its newline", reveal.stdout, reveal.code)
	}
}

func TestSetRejectsMalformedRefs(t *testing.T) {
	_, _, env := localHome(t)
	if r := localRun(t, env, "", "init"); r.code != 0 {
		t.Fatalf("init exit %d: %s", r.code, r.stderr)
	}
	for _, ref := range []string{"Upper", "sms:abc", "with space", "a-", "1abc", "a_b"} {
		r := localRun(t, env, localSecret, "set", ref)
		if r.code != 2 {
			t.Errorf("set %q exit %d, want 2: %s", ref, r.code, r.stderr)
		}
		if !strings.Contains(r.stderr, "invalid ref") {
			t.Errorf("set %q did not explain the ref grammar: %q", ref, r.stderr)
		}
	}
}

func TestSetWarnsOnShortAndEmptyValues(t *testing.T) {
	_, _, env := localHome(t)
	if r := localRun(t, env, "", "init"); r.code != 0 {
		t.Fatalf("init exit %d: %s", r.code, r.stderr)
	}
	short := localRun(t, env, "sh0rt\n", "set", "shorty")
	if short.code != 0 {
		t.Fatalf("short set exit %d: %s", short.code, short.stderr)
	}
	if !strings.Contains(short.stderr, "shorter than 8 bytes") {
		t.Fatalf("short value was not warned about: %q", short.stderr)
	}
	if strings.Contains(short.stdout+short.stderr, "sh0rt") {
		t.Fatalf("short set leaked the value: %q %q", short.stdout, short.stderr)
	}

	// A lone newline trims to nothing: an empty secret is refused.
	empty := localRun(t, env, "\n", "set", "empty")
	if empty.code == 0 {
		t.Fatalf("empty secret accepted: %q", empty.stdout)
	}
	if !strings.Contains(empty.stderr, "1 to 1048576 bytes") {
		t.Fatalf("empty secret error: %q", empty.stderr)
	}
}
