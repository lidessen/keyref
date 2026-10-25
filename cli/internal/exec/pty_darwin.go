//go:build darwin

package exec

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPty allocates a pseudo-terminal pair (design.md §7.1: keyref owns
// the master end). macOS exposes the BSD /dev/ptmx multiplexer; the
// slave name comes back through TIOCPTYGNAME and the pair must be
// granted and unlocked before the child can open its side.
func openPty() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	fd := int(m.Fd())
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYGRANT, 0); err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("pty grant: %w", err)
	}
	if err := unix.IoctlSetInt(fd, unix.TIOCPTYUNLK, 0); err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("pty unlock: %w", err)
	}
	var nameBuf [128]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd),
		uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&nameBuf[0])))
	if errno != 0 {
		m.Close()
		return nil, nil, fmt.Errorf("pty name: %w", errno)
	}
	name := nameBuf[:]
	if i := indexByte0(name); i >= 0 {
		name = name[:i]
	}
	s, err := os.OpenFile(string(name), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}

func indexByte0(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}
