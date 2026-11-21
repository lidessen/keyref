//go:build e2e && linux

package e2e

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openTestPty allocates a pty pair through /dev/ptmx. TIOCSPTLCK
// unlocks it and TIOCGPTN reports the slave number under /dev/pts.
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
	var n uint32
	var ioctlErr error
	if err := raw.Control(func(fd uintptr) {
		if err := unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); err != nil {
			ioctlErr = err
			return
		}
		n, ioctlErr = unix.IoctlGetUint32(int(fd), unix.TIOCGPTN)
	}); err != nil {
		m.Close()
		return nil, nil, err
	}
	if ioctlErr != nil {
		m.Close()
		return nil, nil, ioctlErr
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("open pty slave: %w", err)
	}
	return m, s, nil
}
