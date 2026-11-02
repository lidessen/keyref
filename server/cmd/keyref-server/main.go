// Command keyref-server runs the keyref sync server (design §12.3): one
// static binary, embedded SQLite, the same protocol for the hosted and
// the self-hosted deployment.
//
//	serve                  start the HTTP service (default)
//	backup --out FILE      consistent online backup via VACUUM INTO
//	version                print version and commit
//
// Configuration (design §10.4, §12.3):
//
//	KEYREF_DATA           data directory (default /data)
//	KEYREF_DOMAIN         enables ACME TLS on :443/:80 when set
//	KEYREF_ACME_EMAIL     ACME account email
//	KEYREF_LISTEN         plain-HTTP listen address (default 127.0.0.1:8080)
//	KEYREF_ENFORCE_QUOTAS set to 1 on the hosted deployment: plans, PoW
//	                      and the global budget; self-hosted runs unlimited
//
// APNs push (design §8.3, §12.3 — deployment-environment credentials
// only, never client-visible config):
//
//	KEYREF_APN_KEY_PATH   path to the .p8 signing key file
//	KEYREF_APN_KEY_ID     key id from the Apple developer console
//	KEYREF_TEAM_ID        Apple team id
//	KEYREF_APN_TOPIC      the iOS app bundle id
//	KEYREF_APN_ENV        sandbox | production
//
// When any of these is missing or unusable the process logs one
// "push disabled" line and serves everything else unchanged.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"

	"github.com/lidessen/keyref/server/internal/api"
	"github.com/lidessen/keyref/server/internal/apns"
	"github.com/lidessen/keyref/server/internal/httpserver"
	"github.com/lidessen/keyref/server/internal/pow"
	"github.com/lidessen/keyref/server/internal/quotas"
	"github.com/lidessen/keyref/server/internal/store"
)

// version and commit are set at build time; defaults cover go install.
var (
	version = "dev"
	commit  = "unknown"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "keyref-server:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	rest := []string{}
	if len(args) > 0 {
		cmd = args[0]
		rest = args[1:]
	}
	switch cmd {
	case "serve":
		return serve(rest)
	case "backup":
		return backup(rest)
	case "version":
		fmt.Printf("keyref-server %s (%s)\n", version, commit)
		return nil
	case "help", "-h", "--help":
		usage(os.Stdout)
		return nil
	default:
		usage(os.Stderr)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `usage: keyref-server [serve] [--listen ADDR]   start the sync server
       keyref-server backup --out FILE            consistent online backup
       keyref-server version                      print version and commit

environment: KEYREF_DATA, KEYREF_DOMAIN, KEYREF_ACME_EMAIL, KEYREF_LISTEN,
             KEYREF_ENFORCE_QUOTAS, KEYREF_APN_KEY_PATH, KEYREF_APN_KEY_ID,
             KEYREF_TEAM_ID, KEYREF_APN_TOPIC, KEYREF_APN_ENV
`)
}

func dataDir() string {
	if d := os.Getenv("KEYREF_DATA"); d != "" {
		return d
	}
	return "/data"
}

func openStore(ctx context.Context) (*store.Store, error) {
	return store.Open(ctx, filepath.Join(dataDir(), store.DBFileName))
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", os.Getenv("KEYREF_LISTEN"), "plain-HTTP listen address (default 127.0.0.1:8080)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *listen == "" {
		*listen = "127.0.0.1:8080"
	}
	ctx := context.Background()
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()

	origin := ""
	if domain := os.Getenv("KEYREF_DOMAIN"); domain != "" {
		origin = "https://" + domain
	}
	// APNs credentials are deployment-environment only (design §12.3):
	// missing or unusable ones disable push with one log line and leave
	// every other function untouched.
	push, pushWhy := apns.LoadFromEnv(os.Getenv)
	if push == nil {
		log.Printf("keyref-server: push disabled: %s", pushWhy)
	}
	pairLimit := 0
	if v := os.Getenv("KEYREF_PAIR_REGISTER_PER_MINUTE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			pairLimit = n
		}
	}
	handler := api.New(st, quotas.NewManager(st), pow.NewIssuer(), api.Config{
		EnforceQuotas:         os.Getenv("KEYREF_ENFORCE_QUOTAS") == "1",
		PairRegisterPerMinute: pairLimit,
		Version:               version,
		Commit:                commit,
		Origin:                origin,
		DataDir:               dataDir(),
		Push:                  push,
	}).Handler()

	return httpserver.Run(handler, st, httpserver.Options{
		DataDir:    dataDir(),
		Domain:     os.Getenv("KEYREF_DOMAIN"),
		ACMEEmail:  os.Getenv("KEYREF_ACME_EMAIL"),
		ListenAddr: *listen,
	})
}

func backup(args []string) error {
	fs := flag.NewFlagSet("backup", flag.ContinueOnError)
	out := fs.String("out", "", "backup destination file (must not exist)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" {
		return fmt.Errorf("backup: --out is required")
	}
	ctx := context.Background()
	st, err := openStore(ctx)
	if err != nil {
		return err
	}
	defer st.Close()
	n, err := st.Backup(ctx, *out)
	if err != nil {
		return err
	}
	fmt.Printf("%d bytes written to %s\n", n, *out)
	return nil
}
