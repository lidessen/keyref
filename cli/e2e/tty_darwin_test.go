//go:build e2e && darwin

package e2e

import (
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openTestPty allocates a pty pair through the BSD /dev/ptmx
// multiplexer. The slave name comes back through TIOCPTYGNAME, and the
// pair must be granted and unlocked before the slave can be opened.
func openTestPty() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	raw, err := m.SyscallConn()
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	var nameBuf [128]byte
	var ioctlErr error
	if err := raw.Control(func(fd uintptr) {
		if err := unix.IoctlSetInt(int(fd), unix.TIOCPTYGRANT, 0); err != nil {
			ioctlErr = err
			return
		}
		if err := unix.IoctlSetInt(int(fd), unix.TIOCPTYUNLK, 0); err != nil {
			ioctlErr = err
			return
		}
		_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd,
			uintptr(unix.TIOCPTYGNAME), uintptr(unsafe.Pointer(&nameBuf[0])))
		if errno != 0 {
			ioctlErr = errno
		}
	}); err != nil {
		m.Close()
		return nil, nil, err
	}
	if ioctlErr != nil {
		m.Close()
		return nil, nil, ioctlErr
	}
	name := nameBuf[:]
	for i, c := range name {
		if c == 0 {
			name = name[:i]
			break
		}
	}
	s, err := os.OpenFile(string(name), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("open pty slave: %w", err)
	}
	return m, s, nil
}
