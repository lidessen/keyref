// Command helper is the e2e child fixture: an allowed argv0 that
// prints exactly one injected environment variable so the test can
// assert the child received the secret while the CLI's redacted output
// proves the model never sees it.
package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "print-env" {
		fmt.Printf("K=%s\n", os.Getenv("K"))
		return
	}
	if len(os.Args) > 1 && os.Args[1] == "exit42" {
		os.Exit(42)
	}
}
