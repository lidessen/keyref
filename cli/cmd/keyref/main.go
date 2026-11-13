// Command keyref is the CLI entry point (design.md §12.2): pair,
// status, lock, unlock, sync, list, get, exec, server. Machine-readable
// output is English; stdout never carries secret plaintext.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lidessen/keyref/cli/internal/approval"
	"github.com/lidessen/keyref/cli/internal/audit"
	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/decider"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/exec"
	"github.com/lidessen/keyref/cli/internal/exitcode"
	"github.com/lidessen/keyref/cli/internal/itemcrypt"
	"github.com/lidessen/keyref/cli/internal/meta"
	"github.com/lidessen/keyref/cli/internal/pair"
	"github.com/lidessen/keyref/cli/internal/secret"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/source"
	"github.com/lidessen/keyref/cli/internal/store"
	"github.com/lidessen/keyref/cli/internal/syncing"
)

func main() {
	// Rows skipped by the v2 F verification surface on stderr without
	// failing the sync (protocol.md §8.3).
	syncing.Warn = os.Stderr
	// Purge runs on every path out of protectedMain — normal returns
	// AND panic unwinding — and always BEFORE os.Exit, which would
	// otherwise skip deferred cleanup (design.md §12.2: guarded
	// buffers are explicitly zeroed at exit). Core dumps are disabled
	// up front for this process and all children (design.md §7.5).
	exec.DisableCoreDumps()
	os.Exit(protectedMain())
}

// fatalExit aborts a command through panic unwinding instead of
// os.Exit: unwinding still runs every deferred function in
// protectedMain — above all secret.Purge — while a bare os.Exit would
// skip them (design.md §12.2: guarded buffers are explicitly zeroed on
// every exit path).
type fatalExit struct{ code int }

func protectedMain() (code int) {
	defer secret.Purge()
	defer recoverFatal(&code)

	if len(os.Args) < 2 {
		usage(os.Stderr)
		return 2
	}
	return dispatch(os.Args[1], os.Args[2:])
}

// recoverFatal converts a fatalExit panic into the process exit code.
// Running inside deferred unwinding, it lets the secret.Purge defer
// registered above execute before control returns to os.Exit; a panic
// that is not a fatalExit is a genuine bug and is re-raised after the
// purge (crash, never silence).
func recoverFatal(code *int) {
	if r := recover(); r != nil {
		if fe, ok := r.(fatalExit); ok {
			*code = fe.code
			return
		}
		panic(r)
	}
}

func dispatch(cmd string, args []string) int {

	switch cmd {
	case "server":
		return cmdServer(args)
	case "source":
		return cmdSource(args)
	case "decider":
		return cmdDecider(args)
	case "pair":
		return cmdPair(args)
	case "session":
		return cmdSession(args)
	case "sync":
		return cmdSync(args)
	case "init":
		return cmdInit(args)
	case "set":
		return cmdSet(args)
	case "delete":
		return cmdDelete(args)
	case "list":
		return cmdList(args)
	case "get":
		return cmdGet(args)
	case "status":
		return cmdStatus(args)
	case "lock":
		return cmdLock()
	case "unlock":
		return cmdUnlock()
	case "exec":
		return cmdExec(args)
	case "mcp":
		return cmdMCP(args)
	case "help", "-h", "--help":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "keyref: unknown command %q\n", cmd)
		usage(os.Stderr)
		return 2
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `usage: keyref <command> [args]

commands:
  init [--source NAME]    create the local vault (key goes to the OS keyring)
  set <ref>               store a secret read from stdin
  get <ref> [--format json] [--reveal]
                          one entry; masked by default, --reveal prints the
                          raw secret bytes (local sources only)
  delete <ref>            delete an entry from a local source
  list [--format json]    refs, names, masks (paired vault only)
  exec [flags] -- <argv>  run a command with injected secrets
  source <list|default|add|remove>
                          show or configure credential sources
  server [set <origin>]   show or set the sync-server origin
  pair [--name <label>]   pair with the iOS vault (QR code + fingerprint)
                            --kind decider pairs an auto-approval delegate
  session                 establish or refresh the server session
  sync                    pull authorized ciphertext changes
  status                  pairing, session and grant expiry status
  lock | unlock           block or restore key unwrapping
  mcp                     serve list/get/exec over stdio as MCP JSON-RPC
  decider run             auto-approve SMS consumptions inside the owner's
                            delegation policy (design v0.8 §14.8)

sources:
  local                   the standalone offline vault (the default)
  sync                    the paired iOS vault (read-only for the CLI)
  Every data command takes --source NAME; KEYREF_SOURCE does the same, and
  "keyref source default NAME" persists the choice. The local master key
  lives in the OS keyring; KEYREF_LOCAL_MASTER (32 random bytes, standard
  base64) overrides it for headless use. A local vault stores refs one-way,
  so "list" works on the paired vault only.

exec flags:
  --env NAME=REF            inject the secret as an environment variable
  --pass NAME               forward NAME from the caller environment
  --stdin REF               write the secret to the child's stdin
  --stdin-login REF         write a synced item's username and value as two
                            stdin lines, in that order, to an absolute command
  --fd N=REF --fd-template T | --fd-raw
                            write the (rendered) secret to fd N
  --allow-argv              allow {{keyref:REF}} placeholders in argv;
                            injected args are visible to ps / Activity Monitor
  --pty                     run the child on a pty owned by keyref
  --reply REGEX=REF         type REF into the pty input when REGEX matches
                            the pre-redaction output (needs --pty; the item
                            must be sensitivity=approval and its allowCommands
                            must contain this argv0)
  --timeout SECONDS         approval wait timeout (default 120, max 120)

  REF is an item ref. --env, --stdin and --fd also accept sms:<message_id>:
                            inject a verification code's SMS body once, after
                            Face ID approval. Always approved (no standard
                            tier), never a {{keyref:...}} argv placeholder.

  On the paired vault an item must name the commands it may run
  (allowCommands on iOS; an empty list allows nothing, and commandPolicy
  allow-all is the owner's explicit opt-out). A local source keeps the
  built-in deny list instead.
`)
}

// ---- shared wiring ----

func fatalf(code int, format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "keyref: "+format+"\n", args...)
	return code
}

func mustPaths() config.Paths {
	p, err := config.Resolve()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyref:", err)
		panic(fatalExit{1})
	}
	return p
}

func mustStore() *store.Store {
	p := mustPaths()
	st, err := store.Open(p.Dir)
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyref:", err)
		panic(fatalExit{1})
	}
	return st
}

// mustIdentity loads (or creates) the device identity from the keyring.
func mustIdentity() *device.Identity {
	id, err := device.LoadOrCreate(secretStore())
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyref:", err)
		panic(fatalExit{1})
	}
	return id
}

// newClient builds the API client with a lazily refreshing token.
func newClient(st *store.Store, id *device.Identity) *client.Client {
	cl := client.New(config.Origin(mustPaths()), nil)
	mgr := session.New(st, cl, id)
	cl.SetTokenSource(mgr.TokenSource())
	return cl
}

func locked(st *store.Store) bool {
	v, ok, _ := st.GetKV(session.KVLocked)
	return ok && string(v) == "1"
}

// ---- server ----

func cmdServer(args []string) int {
	if len(args) == 0 {
		fmt.Println(config.Origin(mustPaths()))
		return 0
	}
	if args[0] != "set" || len(args) != 2 {
		return fatalf(2, "usage: keyref server [set <origin>]")
	}
	p := mustPaths()
	if err := config.SetOrigin(p, args[1]); err != nil {
		return fatalf(1, "%v", err)
	}
	fmt.Println(config.Origin(p))
	return 0
}

// ---- pair ----

func cmdPair(args []string) int {
	fs := flag.NewFlagSet("pair", flag.ContinueOnError)
	name := fs.String("name", defaultDeviceName(), "device label shown on iOS")
	printPayload := fs.Bool("print-payload", false, "also print the raw QR payload (debug/e2e)")
	kind := fs.String("kind", "cli", "device kind announced in the QR: cli | decider")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *kind != "cli" && *kind != "decider" {
		return fatalf(2, "--kind must be cli or decider")
	}
	st := mustStore()
	id := mustIdentity()
	cl := client.New(config.Origin(mustPaths()), nil)
	err := pair.Run(st, cl, id, pair.Options{
		Name:         *name,
		Kind:         *kind,
		PrintPayload: *printPayload,
		Stdout:       os.Stdout,
	})
	if err != nil {
		return fatalf(1, "%v", err)
	}
	// Pairing means this CLI is now backed by the iOS vault: make it
	// the default source, which is also what the commands did before
	// sources existed. `keyref source default local` switches back.
	if err := source.SetDefault(mustPaths(), source.SyncName); err != nil {
		fmt.Fprintf(os.Stderr, "keyref: paired, but could not set the default source: %v\n", err)
	}
	return 0
}

func defaultDeviceName() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "cli"
	}
	if len(host) > 32 {
		host = host[:32]
	}
	return host
}

// ---- session ----

// cmdSession runs the challenge→token flow once and reports the
// outcome (design.md §8.2); other commands do this lazily.
func cmdSession(args []string) int {
	st := mustStore()
	id := mustIdentity()
	cl := client.New(config.Origin(mustPaths()), nil)
	mgr := session.New(st, cl, id)
	cl.SetTokenSource(mgr.TokenSource())
	if _, err := mgr.DeviceID(); err != nil {
		return fatalf(1, "not paired; run keyref pair first")
	}
	tok, err := mgr.Token()
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if raw, ok, _ := st.GetKV(session.KVExpiresAt); ok {
		if ms, err := strconv.ParseInt(string(raw), 10, 64); err == nil {
			fmt.Printf("session: ok, expires %s (token %s…)\n",
				time.UnixMilli(ms).Format(time.RFC3339), tok[:4])
			return 0
		}
	}
	fmt.Println("session: ok")
	return 0
}

// ---- sync ----

func cmdSync(args []string) int {
	st := mustStore()
	id := mustIdentity()
	cl := newClient(st, id)
	mgr := session.New(st, cl, id)
	deviceID, err := mgr.DeviceID()
	if err != nil {
		return fatalf(1, "not paired; run keyref pair first")
	}
	res, err := syncing.Run(st, cl, deviceID)
	if err != nil {
		if errors.Is(err, syncing.ErrRevoked) {
			fmt.Fprintln(os.Stderr, "keyref: this device is revoked; local cache cleared")
			return exitcode.DeviceRevoked
		}
		if errors.Is(err, syncing.ErrTampered) {
			return fatalf(1, "%v (keeping previous local state)", err)
		}
		return fatalf(1, "%v", err)
	}
	fmt.Printf("synced: %d applied, %d removed\n", res.Applied, res.Deleted)
	return 0
}

// ---- list / get ----

func cmdList(args []string) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	format := fs.String("format", "text", "text | json")
	sourceName := fs.String("source", "", "source to operate on")
	if _, err := parseArgs(fs, args); err != nil {
		return 2
	}
	spec, err := resolveSource(*sourceName)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if spec.Kind == source.KindLocal {
		return fatalf(2, "local sources store refs one-way (HMAC), so they cannot be listed; use keyref get <ref>")
	}
	st := mustStore()
	if locked(st) {
		return fatalf(exitcode.SessionLocked, "session is locked; run keyref unlock")
	}
	id := mustIdentity()
	entries, err := meta.Items(st, id)
	if err != nil {
		return unwrapOrGeneric(err)
	}
	if *format == "json" {
		out := make([]meta.Entry, len(entries))
		copy(out, entries)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			return fatalf(1, "%v", err)
		}
		return 0
	}
	fmt.Printf("%-24s %-28s %-10s %s\n", "REF", "NAME", "TYPE", "MASKED")
	for _, e := range entries {
		fmt.Printf("%-24s %-28s %-10s %s\n", e.Ref, truncate(e.Name, 28), e.Type, e.Masked)
	}
	return 0
}

func cmdGet(args []string) int {
	fs := flag.NewFlagSet("get", flag.ContinueOnError)
	format := fs.String("format", "text", "text | json")
	reveal := fs.Bool("reveal", false, "print the raw secret bytes (local sources only)")
	sourceName := fs.String("source", "", "source to operate on")
	rest, err := parseArgs(fs, args)
	if err != nil || len(rest) != 1 {
		return fatalf(2, "usage: keyref get <ref> [--format json] [--reveal] [--source NAME]")
	}
	ref := rest[0]
	spec, err := resolveSource(*sourceName)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if spec.Kind == source.KindLocal {
		return runLocalGet(spec, ref, *format, *reveal)
	}
	if *reveal {
		return fatalf(2, "--reveal is not available on the paired vault: the CLI never prints a synced secret")
	}
	st := mustStore()
	if locked(st) {
		return fatalf(exitcode.SessionLocked, "session is locked; run keyref unlock")
	}
	id := mustIdentity()
	e, err := meta.Lookup(st, id, ref)
	if err != nil {
		if errors.Is(err, meta.ErrUnknownRef) || errors.Is(err, meta.ErrNoViewGrant) {
			// Unknown ref and no-view share one code, and the error
			// never enumerates other refs (design.md §12.2).
			return fatalf(exitcode.UnknownRef, "unknown ref %q", ref)
		}
		return unwrapOrGeneric(err)
	}
	if *format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(e); err != nil {
			return fatalf(1, "%v", err)
		}
		return 0
	}
	fmt.Printf("ref: %s\nname: %s\ndescription: %s\ntype: %s\nmasked: %s\nsensitivity: %s\ninjectable: %v\n",
		e.Ref, e.Name, e.Description, e.Type, e.Masked, e.Sensitivity, e.Injectable)
	return 0
}

func unwrapOrGeneric(err error) int {
	if errors.Is(err, itemcrypt.ErrBadGrantSignature) {
		return fatalf(exitcode.UnwrapFailed, "%v", err)
	}
	return fatalf(1, "%v", err)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

// ---- status ----

func cmdStatus(args []string) int {
	st := mustStore()
	if spec, err := resolveSource(""); err == nil {
		fmt.Printf("source: %s\n", spec.Name)
	}
	fmt.Printf("server: %s\n", config.Origin(mustPaths()))
	if vault, ok, _ := st.GetKV(session.KVVaultID); ok && len(vault) > 0 {
		fmt.Printf("pairing: vault %s\n", string(vault))
	} else {
		fmt.Println("pairing: not paired")
	}
	if last, ok, _ := st.GetKV(pair.KVLastSync); ok {
		if ms, err := strconv.ParseInt(string(last), 10, 64); err == nil {
			fmt.Printf("last sync: %s\n", time.UnixMilli(ms).Format(time.RFC3339))
		}
	}
	if locked(st) {
		fmt.Println("session: locked")
	} else {
		fmt.Println("session: unlocked")
	}
	grants, err := st.Grants()
	if err != nil {
		return fatalf(1, "%v", err)
	}
	for _, g := range grants {
		if g.Kind != "use" {
			continue
		}
		if g.ExpiresAt == 0 {
			fmt.Printf("grant: item %s use (no expiry)\n", shortID(g.ItemID))
			continue
		}
		remaining := time.Until(time.UnixMilli(g.ExpiresAt))
		fmt.Printf("grant: item %s use expires in %s\n", shortID(g.ItemID), remaining.Round(time.Second))
		// Expiry warnings on stderr within 7 days (design.md §8.4).
		if remaining <= 0 {
			fmt.Fprintf(os.Stderr, "keyref: grant for item %s has expired\n", shortID(g.ItemID))
		} else if remaining < 7*24*time.Hour {
			fmt.Fprintf(os.Stderr, "keyref: grant for item %s expires in less than 7 days\n", shortID(g.ItemID))
		}
	}
	return 0
}

func shortID(id string) string {
	if len(id) <= 10 {
		return id
	}
	return id[:8] + "…"
}

// ---- lock / unlock ----

func cmdLock() int {
	st := mustStore()
	if err := st.SetKV(session.KVLocked, []byte("1")); err != nil {
		return fatalf(1, "%v", err)
	}
	fmt.Fprintln(os.Stderr, "locked: item keys will not be unwrapped until keyref unlock")
	return 0
}

func cmdUnlock() int {
	st := mustStore()
	if err := st.SetKV(session.KVLocked, []byte("0")); err != nil {
		return fatalf(1, "%v", err)
	}
	fmt.Fprintln(os.Stderr, "unlocked")
	return 0
}

// ---- exec ----

func cmdExec(args []string) int {
	fs := flag.NewFlagSet("exec", flag.ContinueOnError)
	envs := multiFlag{}
	fs.Var(&envs, "env", "NAME=REF inject the secret as an environment variable (repeatable)")
	passes := multiFlag{}
	fs.Var(&passes, "pass", "NAME forward a caller environment variable (repeatable)")
	stdinRef := fs.String("stdin", "", "REF written to the child's stdin")
	loginRefs := multiFlag{}
	fs.Var(&loginRefs, "stdin-login", "REF whose username and value are written as two stdin lines")
	fds := multiFlag{}
	fs.Var(&fds, "fd", "N=REF write the (rendered) secret to fd N (repeatable)")
	fdTemplate := fs.String("fd-template", "", "template with one {{keyref}} token (RFC 7230 header-value charset)")
	fdRaw := fs.Bool("fd-raw", false, "write the fd payload raw, without a template")
	allowArgv := fs.Bool("allow-argv", false, "allow {{keyref:REF}} placeholders in argv (needs item policy; args visible to ps / Activity Monitor)")
	pty := fs.Bool("pty", false, "run the child on a pty owned by keyref (output still redacted)")
	replies := multiFlag{}
	fs.Var(&replies, "reply", "REGEX=REF type REF into the pty input when REGEX matches the pre-redaction output (needs --pty, approval item, allowCommands)")
	timeoutSecs := fs.Int64("timeout", 120, "approval wait timeout in seconds (approval items)")
	sourceName := fs.String("source", "", "source to operate on")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	argv := fs.Args()
	if len(argv) > 0 && argv[0] == "--" {
		argv = argv[1:]
	}
	if len(argv) == 0 {
		return fatalf(2, "usage: keyref exec [flags] -- <argv>")
	}
	var loginRef string
	if len(loginRefs) > 0 {
		if len(loginRefs) != 1 || loginRefs[0] == "" || *stdinRef != "" || *pty {
			return fatalf(exitcode.PolicyRejection, "--stdin-login requires one ref and cannot be combined with --stdin or --pty")
		}
		if *timeoutSecs < 1 || *timeoutSecs > 120 {
			return fatalf(exitcode.PolicyRejection, "--stdin-login requires an approval timeout of 1 to 120 seconds")
		}
		loginRef = loginRefs[0]
	}
	var parsedReplies []exec.Reply
	for _, spec := range replies {
		rp, err := exec.ParseReply(spec)
		if err != nil {
			return fatalf(exitcode.PolicyRejection, "%v", err)
		}
		parsedReplies = append(parsedReplies, rp)
	}
	return runExecCore(execOptions{
		EnvRefs: envs, PassNames: passes, StdinRef: *stdinRef, LoginRef: loginRef,
		FdRefs: fds, FdTemplate: *fdTemplate, FdRaw: *fdRaw,
		AllowArgv: *allowArgv, Pty: *pty, Replies: parsedReplies,
		Timeout: time.Duration(*timeoutSecs) * time.Second,
		Argv:    argv,
		Source:  *sourceName,
		Stdout:  os.Stdout, Stderr: os.Stderr, Stdin: os.Stdin,
	})
}

// execOptions is one exec invocation, shared by the CLI command and the
// MCP exec tool (design.md §7.8: `keyref mcp` is semantically identical
// to the CLI and reuses the same implementation layer — one policy, one
// spawn path, one redactor).
type execOptions struct {
	EnvRefs    []string
	PassNames  []string
	StdinRef   string
	LoginRef   string
	FdRefs     []string
	FdTemplate string
	FdRaw      bool
	AllowArgv  bool
	Pty        bool
	Replies    []exec.Reply
	Timeout    time.Duration
	Argv       []string
	// Source selects the credential source; empty means the configured
	// default (local, unless a paired vault predates sources).
	Source string
	Stdout io.Writer
	Stderr io.Writer
	Stdin  io.Reader
}

// runExecCore executes one exec end to end: audit wiring, meta
// resolution, policy checks (inside exec.Run), lazy secret resolution —
// standard grants or, for approval items, the per-exec approval flow —
// and the redacted run.
func runExecCore(opts execOptions) int {
	spec, err := resolveSource(opts.Source)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if spec.Kind == source.KindLocal {
		return runLocalExec(opts, spec)
	}
	st := mustStore()
	id := mustIdentity()

	// Audit wiring FIRST so that every rejection below produces an
	// encrypted audit event (design.md §7.7: every attempt is
	// recorded, including rejected ones). The stored directory was
	// signature-verified on ingest; re-verify before extracting owner
	// recipients (defense in depth, design.md §9.1).
	cl := newClient(st, id)
	var auditRecips []audit.OwnerRecipient
	var dirDevices []audit.DeviceRecord
	var reporterRaw []byte
	var vaultID string
	var ownerPub []byte
	paired := false
	if vaultRaw, ok, _ := st.GetKV(session.KVVaultID); ok && len(vaultRaw) > 0 {
		if pub, err := syncing.OwnerSignPub(st); err == nil {
			vaultID = string(vaultRaw)
			ownerPub = pub
			reporterRaw, _, _ = st.GetKV(session.KVDeviceID)
			if dirSigned, ok, _ := st.GetKV(pair.KVDirectorySigned); ok && len(dirSigned) > 0 {
				if dirSig, ok2, _ := st.GetKV(pair.KVDirectorySig); ok2 && len(dirSig) > 0 {
					if syncing.VerifyStoredDirectory(st, dirSigned, dirSig) == nil {
						if recips, err := audit.OwnersFromDirectory(dirSigned); err == nil {
							auditRecips = recips
						}
						// The same directory is the only authority for the
						// deciding device's key (protocol v2 B).
						if devices, err := audit.ParseDirectory(dirSigned); err == nil {
							dirDevices = devices
						}
					}
				}
			}
			paired = true
		}
	}
	// refreshDevices re-syncs once and re-reads the owner-signed directory;
	// the approval flow calls it when a decision names a device it has not
	// seen yet (protocol v2 B).
	refreshDevices := func() ([]audit.DeviceRecord, error) {
		if len(vaultID) == 0 || len(ownerPub) == 0 || len(reporterRaw) == 0 {
			return nil, errNotPaired
		}
		if _, err := syncing.Run(st, cl, string(reporterRaw)); err != nil {
			return nil, err
		}
		dirSigned, ok, _ := st.GetKV(pair.KVDirectorySigned)
		if !ok || len(dirSigned) == 0 {
			return nil, errNoDirectory
		}
		dirSig, ok, _ := st.GetKV(pair.KVDirectorySig)
		if !ok || len(dirSig) == 0 {
			return nil, errNoDirectory
		}
		if err := syncing.VerifyStoredDirectory(st, dirSigned, dirSig); err != nil {
			return nil, err
		}
		return audit.ParseDirectory(dirSigned)
	}
	injection := injectionModes(opts)
	appr := &approvalAudit{}
	auditAttempt := func(code int, state string, refs []string) int {
		if paired && len(auditRecips) > 0 {
			o := &exec.Outcome{
				ChildExit:   -1,
				PolicyState: "deny:" + state,
				Refs:        refs,
				Injection:   injection,
				Argv:        opts.Argv,
				AllowArgv:   opts.AllowArgv,
			}
			if envelope := buildAuditEnvelope(o, vaultID, string(reporterRaw), auditRecips); envelope != nil {
				audit.UploadBestEffort(cl, envelope)
			}
		}
		return code
	}

	if !paired {
		return fatalf(1, "not paired; run keyref pair first")
	}
	if locked(st) {
		fmt.Fprintln(opts.Stderr, "keyref: session is locked; run keyref unlock")
		return auditAttempt(exitcode.SessionLocked, "locked", nil)
	}

	// Collect every referenced ref.
	var wanted []string
	see := map[string]bool{}
	addRef := func(ref string) {
		if ref != "" && !see[ref] {
			see[ref] = true
			wanted = append(wanted, ref)
		}
	}
	for _, spec := range opts.EnvRefs {
		_, ref, err := splitSpec(spec)
		if err != nil {
			return auditAttempt(fatalf(10, "--env expects NAME=REF"), "env-spec", nil)
		}
		addRef(ref)
	}
	for _, spec := range opts.FdRefs {
		_, ref, err := splitSpec(spec)
		if err != nil {
			return auditAttempt(fatalf(10, "--fd expects N=REF"), "fd-spec", nil)
		}
		addRef(ref)
	}
	addRef(opts.StdinRef)
	addRef(opts.LoginRef)
	for _, rp := range opts.Replies {
		addRef(rp.Ref)
	}
	for _, ref := range placeholdersInArgv(opts.Argv) {
		addRef(ref)
	}

	// Stage 1 — resolve metas only (view grants). Secrets are NOT
	// decrypted yet: exec.Run resolves values lazily after its policy
	// checks pass, so a rejected attempt never touches secret
	// plaintext (design.md §7.3 checks-before-spawn, §12.2).
	// sms:<message_id> refs carry no item meta: they are recorded as
	// message refs and resolved through their own approval round
	// (design v0.8 §14.5).
	refs := map[string]*exec.ResolvedRef{}
	itemIDs := map[string]string{}
	messageIDs := map[string]string{}
	for _, ref := range wanted {
		if strings.HasPrefix(ref, exec.MessageRefPrefix) {
			messageID, ok := exec.ParseMessageRef(ref)
			if !ok {
				return auditAttempt(fatalf(exitcode.PolicyRejection,
					"malformed sms ref %q (want sms:<32 hex message id>)", ref), "sms-ref", []string{ref})
			}
			refs[ref] = &exec.ResolvedRef{Ref: ref, Message: true}
			messageIDs[ref] = messageID
			continue
		}
		itemID, m, err := metaByRef(st, id, vaultID, ownerPub, ref)
		if err != nil {
			if errors.Is(err, meta.ErrUnknownRef) || errors.Is(err, meta.ErrNoViewGrant) {
				fmt.Fprintf(opts.Stderr, "keyref: unknown ref %q\n", ref)
				return auditAttempt(exitcode.UnknownRef, "unknown-ref", []string{ref})
			}
			return auditAttempt(unwrapOrGeneric(err), "unwrap-meta", []string{ref})
		}
		refs[ref] = &exec.ResolvedRef{Ref: ref, Meta: m, Paired: true}
		itemIDs[ref] = itemID
	}

	// Stage 2 — lazy value resolution used by exec.Run after policy.
	// The CLI needs the approval round when the item's meta says
	// sensitivity = approval OR this device holds no usable use grant
	// (protocol v2 §I): the meta can only tighten that rule, never
	// loosen it. What the approval delivers follows the row — an item
	// with no secret_ciphertext receives the secret value itself, any
	// other item a one-time item key.
	deviceID, _, _ := st.GetKV(session.KVDeviceID)
	resolveValue := func(ref string) (*secret.Plaintext, int, string) {
		if rr, ok := refs[ref]; ok && rr.Message {
			return resolveMessageViaApproval(vaultID, string(deviceID), id, cl, auditRecips, dirDevices, refreshDevices,
				opts, rr, messageIDs[ref], appr)
		}
		m := refs[ref].Meta
		granted, err := hasUsableUseGrant(st, itemIDs[ref])
		if err != nil {
			fmt.Fprintln(opts.Stderr, "keyref:", err)
			return nil, 1, "internal"
		}
		if m.Policy.Sensitivity == "approval" || !granted {
			return resolveViaApproval(st, vaultID, string(deviceID), id, cl, auditRecips, dirDevices, refreshDevices,
				opts, refs[ref], itemIDs[ref], appr)
		}
		return resolveValueFor(st, id, vaultID, ownerPub, refs[ref], itemIDs[ref], ref == opts.LoginRef)
	}

	req := &exec.Request{
		EnvRefs:      opts.EnvRefs,
		PassNames:    opts.PassNames,
		StdinRef:     opts.StdinRef,
		LoginRef:     opts.LoginRef,
		FdRefs:       opts.FdRefs,
		FdTemplate:   opts.FdTemplate,
		FdRaw:        opts.FdRaw,
		AllowArgv:    opts.AllowArgv,
		Pty:          opts.Pty,
		Stdin:        opts.Stdin,
		Replies:      opts.Replies,
		Argv:         opts.Argv,
		Refs:         refs,
		ResolveValue: resolveValue,
		ParentEnv:    os.Environ(),
		Stdout:       opts.Stdout,
		Stderr:       opts.Stderr,
		OnOutcome: func(o *exec.Outcome) {
			if !paired || len(auditRecips) == 0 {
				return
			}
			o.ApprovalResult = approvalResultOf(o.PolicyState, appr.used)
			o.DecisionDeviceID = appr.decisionDeviceID
			if envelope := buildAuditEnvelope(o, vaultID, string(reporterRaw), auditRecips); envelope != nil {
				audit.UploadBestEffort(cl, envelope)
			}
		},
	}
	return exec.Run(req)
}

// approvalAudit collects the two approval facts one exec's audit event
// needs (design §7.7, v0.8 §14.5): whether an approval round ran, and
// which device signed the decision — the owner or the delegated decider
// (protocol §6.22 decision_device_id). Both stay empty/true-independent
// for runs that never reached the approval flow.
type approvalAudit struct {
	used             bool
	decisionDeviceID string
}

// approvalResultOf maps the outcome into the audit event's approval
// field (design.md §7.7): "approved" for allowed runs that went through
// the flow, the deny reason otherwise.
func approvalResultOf(policyState string, approvalUsed bool) string {
	switch {
	case strings.HasPrefix(policyState, "deny:approval-"):
		return strings.TrimPrefix(policyState, "deny:approval-")
	case policyState == "allow" && approvalUsed:
		return "approved"
	default:
		return ""
	}
}

// resolveViaApproval runs the §8.3 approval round for one ref and
// produces the guarded secret value. It runs when the item's meta says
// sensitivity = approval, or when this device holds no usable use grant
// (protocol v2 §I). The decision payload follows the row, not the meta:
// an item with no cached secret_ciphertext (local-only) receives the
// secret VALUE itself, which goes straight to the injection path; any
// other item receives a one-time item key that decrypts its cached
// secret ciphertext (protocol §6.21). Key and value are destroyed after
// the single exec — neither reaches the keyring or the cache
// (design.md §15).
func resolveViaApproval(st *store.Store, vaultID, deviceID string, id *device.Identity, cl *client.Client,
	auditRecips []audit.OwnerRecipient, dirDevices []audit.DeviceRecord,
	refreshDevices func() ([]audit.DeviceRecord, error),
	opts execOptions, rr *exec.ResolvedRef, itemID string, appr *approvalAudit) (*secret.Plaintext, int, string) {
	appr.used = true
	it, ok, err := st.GetItem(itemID)
	if err != nil || !ok {
		fmt.Fprintln(opts.Stderr, "keyref: item missing from cache; run keyref sync")
		return nil, 1, "internal"
	}
	var replySpecs []string
	for _, rp := range opts.Replies {
		replySpecs = append(replySpecs, rp.Pattern+"="+rp.Ref)
	}
	// Local item: the unwrap result IS the secret value (guarded); it is
	// used once and wiped by exec.Run (design §6.6: 解开即用、即清).
	if len(it.SecretCiphertext) == 0 {
		if rr.Ref == opts.LoginRef {
			fmt.Fprintln(opts.Stderr, "keyref: --stdin-login requires a synchronized item")
			return nil, exitcode.InjectionInvalid, "login-not-synced"
		}
		value, code, state := approval.RequestSecret(&approval.Options{
			VaultID:        vaultID,
			DeviceID:       deviceID,
			Identity:       id,
			Owners:         auditRecips,
			ItemID:         itemID,
			Ref:            rr.Ref,
			Argv:           opts.Argv,
			Refs:           refsOf(opts),
			Injection:      injectionModes(opts),
			Hosts:          rr.Meta.Policy.AllowedHosts,
			Reply:          replySpecs,
			Timeout:        opts.Timeout,
			Client:         cl,
			Stderr:         opts.Stderr,
			Devices:        dirDevices,
			RefreshDevices: refreshDevices,
		}, &appr.decisionDeviceID)
		if value == nil {
			return nil, code, state
		}
		return value, 0, ""
	}
	displayRef := rr.Ref
	if rr.Ref == opts.LoginRef {
		displayRef = "the login item"
	}
	key, code, state := approval.RequestItemKey(&approval.Options{
		VaultID:        vaultID,
		DeviceID:       deviceID,
		Identity:       id,
		Owners:         auditRecips,
		ItemID:         itemID,
		Ref:            displayRef,
		Argv:           opts.Argv,
		Refs:           refsOf(opts),
		Injection:      injectionModes(opts),
		Hosts:          rr.Meta.Policy.AllowedHosts,
		Reply:          replySpecs,
		Timeout:        opts.Timeout,
		Client:         cl,
		Stderr:         opts.Stderr,
		Devices:        dirDevices,
		RefreshDevices: refreshDevices,
	}, &appr.decisionDeviceID)
	if key == nil {
		return nil, code, state
	}
	defer key.Destroy()
	return decryptExecValue(opts.Stderr, key, it.SecretCiphertext, vaultID, itemID, rr, rr.Ref == opts.LoginRef)
}

// resolveMessageViaApproval runs the §14.5 consumption round for one
// sms:<message_id> ref. The decision delivers the message PLAINTEXT JSON
// (the message key never leaves the owner/decider domain), so the only
// thing this function keeps is its `body`: the code the agent needs, and
// the only value that enters the injection and redaction set. The JSON
// buffer is destroyed immediately; nothing reaches the keyring or the
// cache (design §16).
func resolveMessageViaApproval(vaultID, deviceID string, id *device.Identity, cl *client.Client,
	auditRecips []audit.OwnerRecipient, dirDevices []audit.DeviceRecord,
	refreshDevices func() ([]audit.DeviceRecord, error),
	opts execOptions, rr *exec.ResolvedRef,
	messageID string, appr *approvalAudit) (*secret.Plaintext, int, string) {
	appr.used = true
	value, code, state := approval.RequestMessage(&approval.Options{
		VaultID:        vaultID,
		DeviceID:       deviceID,
		Identity:       id,
		Owners:         auditRecips,
		MessageID:      messageID,
		Ref:            rr.Ref,
		Argv:           opts.Argv,
		Refs:           refsOf(opts),
		Injection:      injectionModes(opts),
		Timeout:        opts.Timeout,
		Client:         cl,
		Stderr:         opts.Stderr,
		Devices:        dirDevices,
		RefreshDevices: refreshDevices,
	}, &appr.decisionDeviceID)
	if value == nil {
		return nil, code, state
	}
	defer value.Destroy()
	body, err := messageBody(value.Bytes())
	if err != nil {
		fmt.Fprintln(opts.Stderr, "keyref: message payload is malformed")
		return nil, exitcode.UnwrapFailed, "sms-payload"
	}
	return body, 0, ""
}

// messageBody pulls the `body` field out of the §3.9 message plaintext
// JSON ({"v","sender","body","sim","received_at"}).
func messageBody(raw []byte) (*secret.Plaintext, error) {
	var m struct {
		V    int    `json:"v"`
		Body string `json:"body"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	if m.V != 1 || m.Body == "" {
		return nil, errors.New("message payload has no usable body")
	}
	return secret.NewPlaintextFromBytes([]byte(m.Body))
}

// refsOf lists every ref of an exec for the approval request transcript.
func refsOf(opts execOptions) []string {
	var out []string
	see := map[string]bool{}
	add := func(ref string) {
		if ref != "" && !see[ref] {
			see[ref] = true
			out = append(out, ref)
		}
	}
	for _, spec := range opts.EnvRefs {
		if _, ref, err := splitSpec(spec); err == nil {
			add(ref)
		}
	}
	for _, spec := range opts.FdRefs {
		if _, ref, err := splitSpec(spec); err == nil {
			add(ref)
		}
	}
	add(opts.StdinRef)
	add(opts.LoginRef)
	for _, rp := range opts.Replies {
		add(rp.Ref)
	}
	for _, ref := range placeholdersInArgv(opts.Argv) {
		add(ref)
	}
	sort.Strings(out)
	return out
}

// injectionModes lists the injection modes requested by the options
// (audit plaintext field and approval transcript field, design.md §7.7).
func injectionModes(opts execOptions) []string {
	modes := map[string]bool{}
	if len(opts.EnvRefs) > 0 {
		modes["env"] = true
	}
	if len(opts.FdRefs) > 0 {
		modes["fd"] = true
	}
	if opts.StdinRef != "" {
		modes["stdin"] = true
	}
	if opts.LoginRef != "" {
		modes["stdin-login"] = true
	}
	if opts.Pty {
		modes["pty"] = true
	}
	if len(opts.Replies) > 0 {
		modes["reply"] = true
	}
	if exec.HasArgvPlaceholder(opts.Argv) {
		modes["argv"] = true
	}
	out := make([]string, 0, len(modes))
	for m := range modes {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// decryptExecValue projects the authorized item into its requested fields.
func decryptExecValue(stderr io.Writer, key *secret.Key, blob []byte, vaultID, itemID string, rr *exec.ResolvedRef, login bool) (*secret.Plaintext, int, string) {
	var value *secret.Plaintext
	var err error
	if login {
		rr.Username, value, err = itemcrypt.DecryptLoginFields(key, blob, vaultID, itemID)
		if errors.Is(err, secret.ErrFieldNotFound) || errors.Is(err, secret.ErrNotAString) {
			fmt.Fprintln(stderr, "keyref: --stdin-login requires string username and value fields")
			return nil, exitcode.InjectionInvalid, "login-fields"
		}
	} else {
		value, err = itemcrypt.DecryptSecretValue(key, blob, vaultID, itemID)
	}
	if err != nil {
		fmt.Fprintf(stderr, "keyref: cannot decrypt secret for %s\n", rr.Ref)
		return nil, exitcode.UnwrapFailed, "unwrap-failed"
	}
	return value, 0, ""
}

// hasUsableUseGrant reports whether a long-lived use grant can serve the
// item right now (protocol v2 §I): without one the CLI takes the
// approval round even for a sensitivity = standard item. Presence and
// expiry decide the route; a grant that fails to unwrap stays an unwrap
// error (exit 16), never a silent fallback.
func hasUsableUseGrant(st *store.Store, itemID string) (bool, error) {
	grants, err := st.Grants()
	if err != nil {
		return false, err
	}
	now := time.Now().UnixMilli()
	for _, g := range grants {
		if g.ItemID != itemID || g.Kind != "use" || len(g.WrappedKey) == 0 {
			continue
		}
		if g.ExpiresAt > 0 && now > g.ExpiresAt {
			continue
		}
		return true, nil
	}
	return false, nil
}

// resolveValueFor decrypts the guarded secret value of one ref using
// its live use grant. It runs only when the item is not an approval item
// and a usable grant exists (v2 I). Exit codes follow §7.6: 16 unwrap
// failure.
func resolveValueFor(st *store.Store, id *device.Identity, vaultID string, ownerPub []byte, rr *exec.ResolvedRef, itemID string, login bool) (*secret.Plaintext, int, string) {
	ref := rr.Ref
	grants, err := st.Grants()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyref:", err)
		return nil, 1, "internal"
	}
	for _, g := range grants {
		if g.ItemID != itemID || g.Kind != "use" || len(g.WrappedKey) == 0 {
			continue
		}
		if g.ExpiresAt > 0 && time.Now().UnixMilli() > g.ExpiresAt {
			continue // honest CLI stops using expired grants (design §8.4)
		}
		key, err := itemcrypt.UnwrapGrantKey(vaultID, &g, id.HPKEPrivate, ownerPub)
		if err != nil {
			if errors.Is(err, itemcrypt.ErrBadGrantSignature) {
				fmt.Fprintln(os.Stderr, "keyref:", err)
				return nil, exitcode.UnwrapFailed, "unwrap-failed"
			}
			fmt.Fprintf(os.Stderr, "keyref: cannot unwrap item key for %s (grant stale or ciphertext damaged)\n", ref)
			return nil, exitcode.UnwrapFailed, "unwrap-failed"
		}
		it, ok, err := st.GetItem(itemID)
		if err != nil || !ok {
			key.Destroy()
			fmt.Fprintln(os.Stderr, "keyref: item missing from cache; run keyref sync")
			return nil, 1, "internal"
		}
		defer key.Destroy()
		return decryptExecValue(os.Stderr, key, it.SecretCiphertext, vaultID, itemID, rr, login)
	}
	fmt.Fprintf(os.Stderr, "keyref: no usable item key for %s (the use grant expired or was revoked)\n", ref)
	return nil, exitcode.UnwrapFailed, "no-item-key"
}

// metaByRef finds the cached item whose decrypted meta carries ref.
func metaByRef(st *store.Store, id *device.Identity, vaultID string, ownerPub []byte, ref string) (string, *itemcrypt.Meta, error) {
	ids, err := st.ItemIDs()
	if err != nil {
		return "", nil, err
	}
	for _, itemID := range ids {
		m, err := decryptMetaFor(st, id, vaultID, ownerPub, itemID)
		if err != nil {
			if errors.Is(err, meta.ErrNoViewGrant) {
				continue
			}
			return "", nil, err
		}
		if m.Ref == ref {
			return itemID, m, nil
		}
	}
	return "", nil, meta.ErrUnknownRef
}

// decryptMetaFor decrypts one item's meta (guarded key, wiped after).
func decryptMetaFor(st *store.Store, id *device.Identity, vaultID string, ownerPub []byte, itemID string) (*itemcrypt.Meta, error) {
	grants, err := st.Grants()
	if err != nil {
		return nil, err
	}
	for _, g := range grants {
		if g.ItemID != itemID || g.Kind != "view" || len(g.WrappedKey) == 0 {
			continue
		}
		key, err := itemcrypt.UnwrapGrantKey(vaultID, &g, id.HPKEPrivate, ownerPub)
		if err != nil {
			return nil, err
		}
		it, ok, err := st.GetItem(itemID)
		if err != nil || !ok {
			key.Destroy()
			return nil, err
		}
		m, err := itemcrypt.DecryptMeta(key, it.MetaCiphertext, vaultID, itemID)
		key.Destroy()
		return m, err
	}
	return nil, meta.ErrNoViewGrant
}

func placeholdersInArgv(argv []string) []string {
	var out []string
	seen := map[string]bool{}
	_, _ = exec.ReplaceArgvPlaceholders(argv, func(ref string) ([]byte, error) {
		if !seen[ref] {
			seen[ref] = true
			out = append(out, ref)
		}
		return nil, nil
	})
	sort.Strings(out)
	return out
}

func buildAuditEnvelope(o *exec.Outcome, vaultID, reporterDeviceID string, recips []audit.OwnerRecipient) []byte {
	if len(recips) == 0 {
		return nil
	}
	evt := audit.Event{
		Time:             time.Now().UnixMilli(),
		DeviceID:         reporterDeviceID,
		Refs:             o.Refs,
		Injection:        o.Injection,
		Argv:             o.Argv,
		AllowArgv:        o.AllowArgv,
		PolicyResult:     o.PolicyState,
		ApprovalResult:   o.ApprovalResult,
		DecisionDeviceID: o.DecisionDeviceID,
		ChildExit:        o.ChildExit,
		Redactions:       o.Redactions,
	}
	evtJSON, err := json.Marshal(evt)
	if err != nil {
		return nil
	}
	envelope, err := audit.SealEnvelope(evtJSON, vaultID, reporterDeviceID, recips)
	if err != nil {
		return nil
	}
	return envelope
}

func splitSpec(spec string) (string, string, error) {
	i := strings.IndexByte(spec, '=')
	if i <= 0 {
		return "", "", errors.New("spec expects NAME=REF")
	}
	return spec[:i], spec[i+1:], nil
}

// multiFlag collects repeatable string flags.
type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}

// ---- decider (design v0.8 §14.8) ----

// cmdDecider runs the auto-approval delegate. It deliberately refuses to
// start without a review API: the design makes the review mandatory and
// forbids a "nothing could check, so approve" branch.
func cmdDecider(args []string) int {
	if len(args) == 0 || args[0] != "run" {
		fmt.Fprintln(os.Stderr, "usage: keyref decider run --review-api <url> [--once] [--interval 3s]")
		return 2
	}
	fs := flag.NewFlagSet("decider run", flag.ContinueOnError)
	reviewAPI := fs.String("review-api", "", "decision API URL (mandatory)")
	once := fs.Bool("once", false, "run one poll cycle and exit")
	interval := fs.Duration("interval", 3*time.Second, "poll interval (>= 2s, the server's polling floor)")
	if err := fs.Parse(args[1:]); err != nil {
		return 2
	}
	if *reviewAPI == "" {
		fmt.Fprintln(os.Stderr, "keyref: --review-api is required: the review gate cannot be disabled (design §14.8)")
		return 2
	}
	if *interval < 2*time.Second {
		*interval = 2 * time.Second
	}

	st := mustStore()
	id := mustIdentity()
	vaultRaw, ok, _ := st.GetKV(session.KVVaultID)
	if !ok || len(vaultRaw) == 0 {
		return fatalf(1, "not paired; run keyref pair --kind decider first")
	}
	ownerPub, err := syncing.OwnerSignPub(st)
	if err != nil {
		return fatalf(1, "owner signing key unavailable: %v", err)
	}
	cl := newClient(st, id)
	mgr := session.New(st, cl, id)
	deviceID, err := mgr.DeviceID()
	if err != nil {
		return fatalf(1, "not paired; run keyref pair --kind decider first")
	}

	d, err := decider.New(decider.Config{
		VaultID:            string(vaultRaw),
		DeviceID:           deviceID,
		Identity:           id,
		Client:             cl,
		OwnerSignPublicKey: ownerPub,
		Reviewer:           &decider.HTTPReviewer{URL: *reviewAPI},
		Logger:             log.New(os.Stderr, "", log.LstdFlags),
		// The signed directory authenticates the CLI behind each request
		// (protocol v2 A); re-read every cycle so a revocation lands.
		Devices: func() ([]audit.DeviceRecord, error) {
			dirSigned, ok, _ := st.GetKV(pair.KVDirectorySigned)
			if !ok || len(dirSigned) == 0 {
				return nil, errNoDirectory
			}
			dirSig, ok, _ := st.GetKV(pair.KVDirectorySig)
			if !ok || len(dirSig) == 0 {
				return nil, errNoDirectory
			}
			if err := syncing.VerifyStoredDirectory(st, dirSigned, dirSig); err != nil {
				return nil, err
			}
			return audit.ParseDirectory(dirSigned)
		},
	})
	if err != nil {
		return fatalf(1, "%v", err)
	}

	runOnce := func() {
		n, err := d.RunOnce(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "keyref: decider: %v\n", err)
			return
		}
		if n > 0 {
			fmt.Fprintf(os.Stderr, "keyref: decider: auto-approved %d\n", n)
		}
	}
	if *once {
		runOnce()
		return 0
	}

	fmt.Fprintf(os.Stderr, "keyref: decider running (review API %s, interval %s)\n", *reviewAPI, *interval)
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for range ticker.C {
		runOnce()
	}
	return 0
}

// Errors used by the approval directory refresh (protocol v2 B).
var (
	errNotPaired   = errorString("keyref: not paired")
	errNoDirectory = errorString("keyref: signed directory unavailable; run keyref sync")
)

type errorString string

func (e errorString) Error() string { return string(e) }
