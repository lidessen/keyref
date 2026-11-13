package main

import (
	"errors"
	"flag"
	"os"
)

// parseArgs parses a command line whose flags may appear before or
// after the positional arguments, and returns the positionals.
//
// Go's flag package stops at the first non-flag argument, so
// "keyref get ref --format json" would otherwise be read as three
// positional arguments and fail. Commands that take a "--" separator
// (exec) keep the plain flag package: everything after it is the
// child's argv, never keyref's flags.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			return positional, nil
		}
		positional = append(positional, rest[0])
		args = rest[1:]
	}
}

// prepareHelp sends the flag package's help text to stdout when the
// arguments ask for it. An explicit -h / --help is success, not a usage
// error (design v0.10 §17.8). Everything after "--" belongs to the
// child command and is not inspected.
func prepareHelp(fs *flag.FlagSet, args []string) {
	for _, a := range args {
		if a == "--" {
			return
		}
		if a == "-h" || a == "--help" {
			fs.SetOutput(os.Stdout)
			return
		}
	}
}

// parseExit maps a flag parse error to an exit code: an explicit help
// request exits 0, every other parse error is a usage error (§17.8).
func parseExit(err error) int {
	if errors.Is(err, flag.ErrHelp) {
		return 0
	}
	return 2
}
