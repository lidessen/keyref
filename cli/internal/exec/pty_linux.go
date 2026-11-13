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
	fd := int(m.Fd())
	if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0); err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("pty unlock: %w", err)
	}
	// TIOCGPTN writes the pty number through a pointer; IoctlRetInt
	// passes NULL and fails with EFAULT, so read it as a uint32.
	n, err := unix.IoctlGetUint32(fd, unix.TIOCGPTN)
	if err != nil {
		m.Close()
		return nil, nil, fmt.Errorf("pty number: %w", err)
	}
	s, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		m.Close()
		return nil, nil, err
	}
	return m, s, nil
}
