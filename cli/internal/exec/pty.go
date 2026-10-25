//go:build darwin || linux

package exec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"syscall"
	"time"

	osexec "os/exec"
)

// ptySession brokers the master end of the child's pseudo-terminal
// (design.md §7.1): raw output is matched by the --reply patterns
// BEFORE redaction and then redacted on its way to the caller; reply
// matches and --stdin write the secret into the pty input, exactly like
// typed keystrokes. All writes serialize on one mutex.
type ptySession struct {
	master  *os.File
	mu      sync.Mutex
	matcher *replyMatcher
	secrets map[string][]byte
	red     *Redactor
}

func (p *ptySession) writeToChild(b []byte) {
	p.mu.Lock()
	_, _ = p.master.Write(b)
	p.mu.Unlock()
}

func (p *ptySession) typeSecret(ref string) {
	v, ok := p.secrets[ref]
	if !ok {
		return
	}
	p.writeToChild(v)
	if len(v) == 0 || v[len(v)-1] != '\n' {
		p.writeToChild([]byte("\n"))
	}
}

// pump drains master → [reply match on raw bytes] → redactor → caller.
// It ends when the read side errors (EIO once every slave fd is closed)
// and reports completion on done.
func (p *ptySession) pump(done chan<- struct{}) {
	defer close(done)
	buf := make([]byte, 4096)
	for {
		n, err := p.master.Read(buf)
		if n > 0 {
			for _, ref := range p.matcher.Feed(buf[:n]) {
				p.typeSecret(ref)
			}
			if _, werr := p.red.Write(buf[:n]); werr != nil {
				return // redactor failure already killed the child
			}
		}
		if err != nil {
			return
		}
	}
}

// stdinWriter adapts the locked master write to io.Copy.
type stdinWriter struct{ p *ptySession }

func (w stdinWriter) Write(b []byte) (int, error) {
	w.p.writeToChild(b)
	return len(b), nil
}

// ptySysProcAttr gives the child its own session with the slave as the
// controlling terminal, so login-style prompts behave normally
// (design.md §7.1: keyref holds the master end).
func ptySysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
}

// runPtyChild spawns argv on the slave end of a fresh pty, brokers both
// directions and returns the exit code. It owns the tail of run() for
// the --pty path: secret values are already resolved and validated, fd
// payloads staged (extra) and the environment sanitized.
func runPtyChild(req *Request, cmd *osexec.Cmd, stdoutRed *Redactor, secrets map[string][]byte,
	extra []*os.File, outcome *Outcome, deny func(int, string) (int, *Outcome)) (int, *Outcome) {

	master, slave, err := openPty()
	if err != nil {
		return deny(18, "pty")
	}
	defer slave.Close()

	matcher, err := newReplyMatcher(req.Replies)
	if err != nil {
		master.Close()
		return deny(10, "reply-pattern")
	}
	sess := &ptySession{master: master, matcher: matcher, secrets: secrets, red: stdoutRed}

	cmd.Stdin = slave
	cmd.Stdout = slave
	cmd.Stderr = slave
	cmd.ExtraFiles = extra
	cmd.SysProcAttr = ptySysProcAttr()

	if serr := cmd.Start(); serr != nil {
		master.Close()
		fmt.Fprintf(req.Stderr, "keyref: cannot start child: %v\n", serr)
		return deny(18, "cannot-start")
	}
	kill := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		}
	}
	stdoutRed.OnFail = kill

	// --stdin types the secret into the pty input; a pty has no EOF, so
	// the write is not followed by a close (design.md §7.1 stdin notes).
	if req.StdinRef != "" {
		sess.typeSecret(req.StdinRef)
	}
	// Caller stdin is forwarded after the secret.
	if req.Stdin != nil {
		go func() { _, _ = io.Copy(stdinWriter{sess}, req.Stdin) }()
	}
	pumpDone := make(chan struct{})
	go sess.pump(pumpDone)

	werr := cmd.Wait()
	// End the whole session: grandchildren holding the slave would keep
	// the master readable forever (the child got its own session via
	// Setsid, so the group id is its pid).
	kill()
	select {
	case <-pumpDone:
	case <-time.After(2 * time.Second):
	}
	if ferr := stdoutRed.Flush(); ferr != nil {
		fmt.Fprintln(req.Stderr, "keyref: redaction failed; output discarded")
		master.Close()
		return deny(14, "redaction")
	}
	master.Close()

	childExit := 0
	if werr != nil {
		var ee *osexec.ExitError
		if errors.As(werr, &ee) {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				childExit = 128 + int(status.Signal())
			} else {
				childExit = ee.ExitCode()
			}
		} else {
			fmt.Fprintf(req.Stderr, "keyref: child wait failed: %v\n", werr)
			return deny(14, "wait")
		}
	}
	outcome.ChildExit = childExit
	outcome.Redactions = stdoutRed.Count()
	outcome.PolicyState = "allow"
	return childExit, outcome
}
