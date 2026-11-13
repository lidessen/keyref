// Package atomicfile replaces small configuration files atomically and
// serializes load-modify-save sequences with an advisory lock. A reader
// sees either the old file or the new one, never a truncated one
// (issue #6: sources.json and server.conf used truncate-then-write).
package atomicfile

import (
	"os"
	"path/filepath"
	"syscall"
)

// Write replaces path with data atomically: a temporary 0600 file in
// the same directory, fsync, then rename over path.
func Write(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	// Persist the rename itself; not every platform syncs directories.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

// WithLock runs fn while holding an exclusive advisory lock on
// path+".lock", serializing writers of the same file across processes.
// The lock file itself is left in place.
func WithLock(path string, fn func() error) error {
	f, err := os.OpenFile(path+".lock", os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return fn()
}
