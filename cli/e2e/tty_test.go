//go:build e2e

package e2e

import (
	"bytes"
	"io"
	"os/exec"
	"syscall"
	"testing"
)

// localRunTTY runs the CLI with a pseudo-terminal as its controlling
// terminal, so /dev/tty works while stdout/stderr stay pipes. ttyInput
// is written to the terminal right after start (canonical mode buffers
// it until the child reads).
func localRunTTY(t *testing.T, env []string, ttyInput string, args ...string) cliRun {
	t.Helper()
	master, slave, err := openTestPty()
	if err != nil {
		t.Skipf("no pty available: %v", err)
	}
	defer master.Close()

	cmd := exec.Command(cliBin, args...)
	cmd.Env = env
	cmd.Stdin = slave
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	// Setsid gives the child its own session; Setctty makes the pty
	// slave (fd 0) its controlling terminal, which /dev/tty resolves to.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		slave.Close()
		t.Fatalf("could not start the CLI on a pty: %v", err)
	}
	slave.Close()
	// Drain the terminal side: the prompt and the echo go there, and a
	// full pty output queue would block the child inside its write.
	var ttyOut bytes.Buffer
	go func() { _, _ = io.Copy(&ttyOut, master) }()
	if _, err := io.WriteString(master, ttyInput); err != nil {
		t.Fatalf("could not write to the pty: %v", err)
	}
	return waitRun(t, cmd, &out, &errBuf)
}

// localRevealRun answers the reveal confirmation with "y" on a pty.
func localRevealRun(t *testing.T, env []string, args ...string) cliRun {
	t.Helper()
	return localRunTTY(t, env, "y\n", args...)
}

// localRunNoTTY runs the CLI detached from any controlling terminal.
func localRunNoTTY(t *testing.T, env []string, args ...string) cliRun {
	t.Helper()
	cmd := exec.Command(cliBin, args...)
	cmd.Env = env
	var out, errBuf bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start the CLI: %v", err)
	}
	return waitRun(t, cmd, &out, &errBuf)
}

func waitRun(t *testing.T, cmd *exec.Cmd, out, errBuf *bytes.Buffer) cliRun {
	t.Helper()
	err := cmd.Wait()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("could not run the CLI: %v", err)
	}
	return cliRun{stdout: out.String(), stderr: errBuf.String(), code: code}
}
