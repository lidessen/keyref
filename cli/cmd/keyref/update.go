package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"

	"github.com/lidessen/keyref/cli/internal/update"
	"golang.org/x/term"
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
	fmt.Fprintln(os.Stderr, "Checking for latest keyref release...")
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

	fmt.Fprintf(os.Stderr, "Downloading keyref %s (%s/%s)...\n", tag, runtime.GOOS, runtime.GOARCH)
	tty := term.IsTerminal(int(os.Stderr.Fd()))
	showingProgress := false
	progress := func(downloaded, total int64) {
		if !tty {
			return
		}
		showingProgress = true
		if total > 0 {
			fmt.Fprintf(os.Stderr, "\rDownloading... %.0f%% (%.1f / %.1f MiB)\x1b[K", float64(downloaded)*100/float64(total), float64(downloaded)/(1<<20), float64(total)/(1<<20))
		} else {
			fmt.Fprintf(os.Stderr, "\rDownloading... %.1f MiB\x1b[K", float64(downloaded)/(1<<20))
		}
	}
	finishProgress := func() {
		if showingProgress {
			fmt.Fprintln(os.Stderr)
			showingProgress = false
		}
	}
	err = update.InstallWithProgress(ctx, client, tag, path, info, progress, func() {
		finishProgress()
		fmt.Fprintf(os.Stderr, "Verifying SHA-256 and replacing %s...\n", path)
	})
	finishProgress()
	if err != nil {
		return fatalf(1, "update failed: %v", err)
	}
	fmt.Printf("Updated keyref from %s to %s\n", version, tag)
	return 0
}
