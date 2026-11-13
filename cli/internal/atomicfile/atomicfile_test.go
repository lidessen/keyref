package atomicfile

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWriteReplacesAtomically(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "conf")
	if err := Write(path, []byte("one\n")); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("two\n")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil || string(raw) != "two\n" {
		t.Fatalf("content %q, %v", raw, err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("mode: %v %v", info, err)
	}
	// No temporary files are left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("leftover files: %v", entries)
	}
}

func TestWithLockSerializes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "conf")
	held := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		_ = WithLock(path, func() error {
			close(held)
			<-release
			return nil
		})
		close(done)
	}()
	<-held

	acquired := make(chan struct{})
	go func() {
		_ = WithLock(path, func() error {
			close(acquired)
			return nil
		})
	}()
	select {
	case <-acquired:
		t.Fatal("the lock was acquired while another writer held it")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case <-acquired:
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was never handed over")
	}
	<-done
}
