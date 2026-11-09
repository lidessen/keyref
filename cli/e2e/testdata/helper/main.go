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
	"strings"
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
	if len(os.Args) > 1 && os.Args[1] == "prompt" {
		fmt.Print("Password: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Printf("\ngot:%s\n", strings.TrimRight(line, "\r\n"))
		return
	}
}
