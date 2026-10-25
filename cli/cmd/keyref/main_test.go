package main

import "testing"

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
