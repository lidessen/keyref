//go:build linux

package exec

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// openPty allocates a pseudo-terminal pair (design.md §7.1: keyref owns
// the master end). Linux exposes the /dev/ptmx multiplexer: TIOCSPTLCK
// unlocks the pair, TIOCGPTN reports the pty number of the slave under
// /dev/pts.
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
	var n uint32
	var ioctlErr error
	err = raw.Control(func(fd uintptr) {
		if err := unix.IoctlSetPointerInt(int(fd), unix.TIOCSPTLCK, 0); err != nil {
			ioctlErr = fmt.Errorf("pty unlock: %w", err)
			return
		}
		// TIOCGPTN writes through a pointer; IoctlRetInt passes NULL.
		n, ioctlErr = unix.IoctlGetUint32(int(fd), unix.TIOCGPTN)
		if ioctlErr != nil {
			ioctlErr = fmt.Errorf("pty number: %w", ioctlErr)
		}
	})
	if err == nil {
		err = ioctlErr
	}
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}
