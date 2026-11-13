package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// A fatalExit must unwind through the recoverFatal defer into a plain
// exit code — never skip the deferred secret.Purge in protectedMain the
// way a bare os.Exit would (design.md §12.2: explicit zeroing on every
// exit path).
func TestFatalExitBecomesExitCode(t *testing.T) {
	code := 0
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("fatalExit escaped recoverFatal: %v", r)
			}
		}()
		func() {
			defer recoverFatal(&code)
			panic(fatalExit{7})
		}()
	}()
	if code != 7 {
		t.Fatalf("exit code %d, want 7", code)
	}
}

// A panic that is not a fatalExit is a genuine bug: recoverFatal must
// re-raise it (after the purge) instead of swallowing the crash.
func TestGenuinePanicIsReraised(t *testing.T) {
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("genuine panic was swallowed")
		}
		if r != "boom" {
			t.Fatalf("re-raise lost the original value: %v", r)
		}
	}()
	code := 0
	func() {
		defer recoverFatal(&code)
		panic("boom")
	}()
}

func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	f()
	w.Close()
	os.Stderr = old
	b, _ := io.ReadAll(r)
	return string(b)
}

// `keyref decider` used to slice args[1:] twice: bare `decider`
// panicked and `decider run ...` never reached flag parsing.
func TestDeciderDispatch(t *testing.T) {
	var code int
	out := captureStderr(t, func() { code = dispatch("decider", nil) })
	if code != 2 || !strings.Contains(out, "usage: keyref decider run") {
		t.Fatalf("bare decider: code %d stderr %q", code, out)
	}
	out = captureStderr(t, func() { code = dispatch("decider", []string{"run", "--once"}) })
	if code != 2 || !strings.Contains(out, "--review-api is required") {
		t.Fatalf("decider run did not reach flag parsing: code %d stderr %q", code, out)
	}
}
