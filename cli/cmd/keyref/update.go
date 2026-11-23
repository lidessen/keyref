package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"

	"github.com/lidessen/keyref/cli/internal/update"
)

func cmdUpdate(args []string) int {
	fs := flag.NewFlagSet("update", flag.ContinueOnError)
	check := fs.Bool("check", false, "report the latest stable release without installing it")
	prepareHelp(fs, args)
	if err := fs.Parse(args); err != nil {
		return parseExit(err)
	}
	if fs.NArg() != 0 {
		return fatalf(2, "usage: keyref update [--check]")
	}

	var path string
	var info os.FileInfo
	if !*check {
		var err error
		path, err = os.Executable()
		if err != nil {
			return fatalf(1, "locate the running executable: %v", err)
		}
		info, err = os.Lstat(path)
		if err != nil {
			return fatalf(1, "inspect the running executable: %v", err)
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	client := update.HTTPClient()
	tag, err := update.Latest(ctx, client)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if !update.IsNewer(tag, version) {
		fmt.Printf("keyref %s is up to date (latest release %s)\n", version, tag)
		return 0
	}
	if *check {
		fmt.Printf("keyref %s is available (installed %s)\n", tag, version)
		return 0
	}

	if err := update.Install(ctx, client, tag, path, info); err != nil {
		return fatalf(1, "update failed: %v", err)
	}
	fmt.Printf("Updated keyref from %s to %s\n", version, tag)
	return 0
}
