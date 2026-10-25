//go:build linux

package exec

import (
	"os"

	"golang.org/x/sys/unix"
)

// memfdFile returns an anonymous sealed-by-unlink-equivalent file: a
// memfd never has a directory entry at all (design.md §7.1 landing
// option 1).
func memfdFile() (*os.File, bool) {
	fd, err := unix.MemfdCreate("keyref-fd", unix.MFD_CLOEXEC)
	if err != nil {
		return nil, false
	}
	return os.NewFile(uintptr(fd), "keyref-fd"), true
}
