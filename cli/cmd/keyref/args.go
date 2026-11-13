package main

import (
	"flag"
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
