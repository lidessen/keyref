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
	// Fd changes the descriptor back to blocking mode. Control keeps the
	// master pollable so the output pump can use an idle read deadline.
	raw, err := m.SyscallConn()
	if err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("pty control: %w", err)
	}
	var nameBuf [128]byte
	var ioctlErr error
	err = raw.Control(func(fd uintptr) {
		if err := unix.IoctlSetInt(int(fd), unix.TIOCPTYGRANT, 0); err != nil {
			ioctlErr = fmt.Errorf("pty grant: %w", err)
			return
		}
		if err := unix.IoctlSetInt(int(fd), unix.TIOCPTYUNLK, 0); err != nil {
			ioctlErr = fmt.Errorf("pty unlock: %w", err)
			return
		}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd,
			uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&nameBuf[0])))
		if errno != 0 {
			ioctlErr = fmt.Errorf("pty name: %w", errno)
		}
	})
	if err == nil {
		err = ioctlErr
	}
	if err != nil {
		m.Close()
		return nil, nil, err
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
