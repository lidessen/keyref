// Command helper is the e2e child fixture: an allowed argv0 that
// prints exactly one injected environment variable so the test can
// assert the child received the secret while the CLI's redacted output
// proves the model never sees it. The prompt mode serves the --pty /
// --reply path: it prints a password prompt, reads one line (a pty
// never EOFs) and echoes it back.
package main

import (
	"bufio"
	"fmt"
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
	if len(os.Args) > 1 && os.Args[1] == "prompt" {
		fmt.Print("Password: ")
		line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
		fmt.Printf("\ngot:%s\n", strings.TrimRight(line, "\r\n"))
		return
	}
}
