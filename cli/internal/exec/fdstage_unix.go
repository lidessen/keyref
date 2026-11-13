//go:build darwin || linux

package exec

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
)

// stageFdFile delivers payload to the child as an open file descriptor
// (design.md §7.1 landing order): a Linux memfd when available, else a
// 0600 file in a 0700 directory that is unlinked IMMEDIATELY after the
// write while the descriptor stays open — no close-then-reopen window
// in which the plaintext exists on disk under a name.
func stageFdFile(dir string, fdnum int, payload []byte) (*os.File, bool) {
	// 1) memfd (Linux; macOS has no memfd_create).
	if f, ok := memfdFile(); ok {
		if writeAll(f, payload) && seekStart(f) {
			return f, true
		}
		f.Close()
	}
	// 2) O_CREAT|O_EXCL 0600, write, seek, unlink while still open.
	return stageFdFallback(dir, fdnum, payload)
}

// stageFdFallback is the file-based landing. It is split out so both
// platforms can test it directly whether or not memfd is available
// (issue #4).
func stageFdFallback(dir string, fdnum int, payload []byte) (*os.File, bool) {
	path := filepath.Join(dir, "fd"+strconv.Itoa(fdnum))
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		return nil, false
	}
	if !writeAll(f, payload) || !seekStart(f) {
		f.Close()
		return nil, false
	}
	if err := os.Remove(path); err != nil {
		f.Close()
		return nil, false
	}
	return f, true
}

func writeAll(f *os.File, b []byte) bool {
	for len(b) > 0 {
		n, err := f.Write(b)
		if err != nil || n <= 0 {
			return false
		}
		b = b[n:]
	}
	return true
}

func seekStart(f *os.File) bool {
	_, err := f.Seek(0, io.SeekStart)
	return err == nil
}
