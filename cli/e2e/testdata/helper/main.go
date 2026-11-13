// Command helper is the e2e child fixture: an allowed argv0 that
// prints exactly one injected environment variable so the test can
// assert the child received the secret while the CLI's redacted output
// proves the model never sees it. The prompt mode serves the --pty /
// --reply path: it prints a password prompt, reads one line (a pty
// never EOFs) and echoes it back.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "print-env" {
		fmt.Printf("K=%s\n", os.Getenv("K"))
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "exit42" {
		os.Exit(42)
	}
	if len(os.Args) == 3 && os.Args[1] == "login" {
		info, err := os.Stdin.Stat()
		if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			os.Exit(29)
		}
		input, err := io.ReadAll(io.LimitReader(os.Stdin, 2051))
		digest := sha256.Sum256(input)
		if err != nil || hex.EncodeToString(digest[:]) != os.Args[2] {
			os.Exit(30)
		}
		// The test captures the echo only through Keyref's redactors.
		_, _ = os.Stdout.Write(input)
		return
	}
	if len(os.Args) >= 3 && os.Args[1] == "sleep" {
		// A long-running child for the interrupt tests: copies of system
		// binaries are killed by macOS code signing, so the fixture
		// sleeps on its own. The optional marker file proves the handler
		// (or the deliberate ignore) is installed before the test sends
		// a signal; issue #8 requires the signal to arrive, not SIGKILL.
		//   sleep <dur> <marker>          install handlers, then "ready"
		//   sleep <dur> ignore <marker>   ignore SIGINT, then "ignored"
		d, err := time.ParseDuration(os.Args[2])
		if err != nil {
			os.Exit(31)
		}
		if len(os.Args) >= 4 {
			if os.Args[3] == "ignore" {
				signal.Ignore(os.Interrupt)
				if len(os.Args) >= 5 {
					_ = os.WriteFile(os.Args[4], []byte("ignored"), 0o600)
				}
			} else {
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
				// "ready" tells the test the handler is installed, so
				// its signal cannot race the Notify call.
				_ = os.WriteFile(os.Args[3], []byte("ready"), 0o600)
				go func() {
					s := <-sigCh
					_ = os.WriteFile(os.Args[3], []byte(s.String()), 0o600)
					os.Exit(0)
				}()
			}
		}
		time.Sleep(d)
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "prompt" {
		fmt.Print("Password: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Printf("\ngot:%s\n", strings.TrimRight(line, "\r\n"))
		return
	}
}
