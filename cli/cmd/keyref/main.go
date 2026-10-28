// Command keyref is the CLI entry point (design.md §12.2): pair,
// status, lock, unlock, sync, list, get, exec, server. Machine-readable
// output is English; stdout never carries secret plaintext.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lidessen/keyref/proto/wire"

	"github.com/lidessen/keyref/cli/internal/approval"
	"github.com/lidessen/keyref/cli/internal/audit"
	"github.com/lidessen/keyref/cli/internal/client"
	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/exec"
	"github.com/lidessen/keyref/cli/internal/exitcode"
	"github.com/lidessen/keyref/cli/internal/itemcrypt"
	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/meta"
	"github.com/lidessen/keyref/cli/internal/pair"
	"github.com/lidessen/keyref/cli/internal/secret"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/store"
	"github.com/lidessen/keyref/cli/internal/syncing"
)

func main() {
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
	case "pair":
		return cmdPair(args)
	case "session":
		return cmdSession(args)
	case "sync":
		return cmdSync(args)
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
	case "local":
		return cmdLocal(args)
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
  server [set <origin>]     show or set the sync-server origin
  pair [--name <label>]     pair with the iOS vault (QR code + fingerprint)
  session                   establish or refresh the server session
  sync                      pull authorized ciphertext changes
  list [--format json]      refs, names, masks (no plaintext)
  get <ref> [--format json] one item, same view
  status                    pairing, session and grant expiry status
  lock | unlock             block or restore key unwrapping
  exec [flags] -- <argv>    run a command with injected secrets
  local <init|set|delete>    manage an independent local vault
  mcp                       serve list/get/exec over stdio as MCP JSON-RPC

exec flags:
  --env NAME=REF            inject the secret as an environment variable
  --pass NAME               forward NAME from the caller environment
  --stdin REF               write the secret to the child's stdin
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
	var ks keyring.SecretStore = keyring.OSKeyring{}
	if dir := os.Getenv("KEYREF_KEYRING_DIR"); dir != "" {
		dirKS, err := keyring.NewDirStore(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "keyref:", err)
			panic(fatalExit{1})
		}
		ks = dirKS
	}
	id, err := device.LoadOrCreate(ks)
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
	if err := fs.Parse(args); err != nil {
		return 2
	}
	st := mustStore()
	id := mustIdentity()
	cl := client.New(config.Origin(mustPaths()), nil)
	err := pair.Run(st, cl, id, pair.Options{
		Name:         *name,
		PrintPayload: *printPayload,
		Stdout:       os.Stdout,
	})
	if err != nil {
		return fatalf(1, "%v", err)
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
	if err := fs.Parse(args); err != nil {
		return 2
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
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		return fatalf(2, "usage: keyref get <ref> [--format json]")
	}
	ref := fs.Arg(0)
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
	fds := multiFlag{}
	fs.Var(&fds, "fd", "N=REF write the (rendered) secret to fd N (repeatable)")
	fdTemplate := fs.String("fd-template", "", "template with one {{keyref}} token (RFC 7230 header-value charset)")
	fdRaw := fs.Bool("fd-raw", false, "write the fd payload raw, without a template")
	allowArgv := fs.Bool("allow-argv", false, "allow {{keyref:REF}} placeholders in argv (needs item policy; args visible to ps / Activity Monitor)")
	pty := fs.Bool("pty", false, "run the child on a pty owned by keyref (output still redacted)")
	replies := multiFlag{}
	fs.Var(&replies, "reply", "REGEX=REF type REF into the pty input when REGEX matches the pre-redaction output (needs --pty, approval item, allowCommands)")
	timeoutSecs := fs.Int64("timeout", 120, "approval wait timeout in seconds (approval items)")
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
	var parsedReplies []exec.Reply
	for _, spec := range replies {
		rp, err := exec.ParseReply(spec)
		if err != nil {
			return fatalf(exitcode.PolicyRejection, "%v", err)
		}
		parsedReplies = append(parsedReplies, rp)
	}
	return runExecCore(execOptions{
		EnvRefs: envs, PassNames: passes, StdinRef: *stdinRef,
		FdRefs: fds, FdTemplate: *fdTemplate, FdRaw: *fdRaw,
		AllowArgv: *allowArgv, Pty: *pty, Replies: parsedReplies,
		Timeout: time.Duration(*timeoutSecs) * time.Second,
		Argv:    argv,
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
	FdRefs     []string
	FdTemplate string
	FdRaw      bool
	AllowArgv  bool
	Pty        bool
	Replies    []exec.Reply
	Timeout    time.Duration
	Argv       []string
	Stdout     io.Writer
	Stderr     io.Writer
	Stdin      io.Reader
}

// runExecCore executes one exec end to end: audit wiring, meta
// resolution, policy checks (inside exec.Run), lazy secret resolution —
// standard grants or, for approval items, the per-exec approval flow —
// and the redacted run.
func runExecCore(opts execOptions) int {
	st := mustStore()
	id := mustIdentity()

	// Audit wiring FIRST so that every rejection below produces an
	// encrypted audit event (design.md §7.7: every attempt is
	// recorded, including rejected ones). The stored directory was
	// signature-verified on ingest; re-verify before extracting owner
	// recipients (defense in depth, design.md §9.1).
	cl := newClient(st, id)
	var auditRecips []audit.OwnerRecipient
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
					if wire.VerifyOwnerSignature(dirSigned, dirSig, ownerPub) == nil {
						if recips, err := audit.OwnersFromDirectory(dirSigned); err == nil {
							auditRecips = recips
						}
					}
				}
			}
			paired = true
		}
	}
	injection := injectionModes(opts)
	approvalUsed := false
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
	refs := map[string]*exec.ResolvedRef{}
	itemIDs := map[string]string{}
	for _, ref := range wanted {
		itemID, m, err := metaByRef(st, id, vaultID, ownerPub, ref)
		if err != nil {
			if errors.Is(err, meta.ErrUnknownRef) || errors.Is(err, meta.ErrNoViewGrant) {
				fmt.Fprintf(opts.Stderr, "keyref: unknown ref %q\n", ref)
				return auditAttempt(exitcode.UnknownRef, "unknown-ref", []string{ref})
			}
			return auditAttempt(unwrapOrGeneric(err), "unwrap-meta", []string{ref})
		}
		refs[ref] = &exec.ResolvedRef{Ref: ref, Meta: m}
		itemIDs[ref] = itemID
	}

	// Stage 2 — lazy value resolution used by exec.Run after policy.
	// Approval items (sensitivity = approval, CLI holds only the meta
	// key) resolve through the per-exec approval flow of design §8.3.
	deviceID, _, _ := st.GetKV(session.KVDeviceID)
	resolveValue := func(ref string) (*secret.Plaintext, int, string) {
		m := refs[ref].Meta
		if m.Policy.Sensitivity == "approval" {
			return resolveViaApproval(st, vaultID, string(deviceID), id, cl, auditRecips, opts, refs[ref], itemIDs[ref], &approvalUsed)
		}
		return resolveValueFor(st, id, vaultID, ownerPub, ref, itemIDs[ref])
	}

	req := &exec.Request{
		EnvRefs:      opts.EnvRefs,
		PassNames:    opts.PassNames,
		StdinRef:     opts.StdinRef,
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
			o.ApprovalResult = approvalResultOf(o.PolicyState, approvalUsed)
			if envelope := buildAuditEnvelope(o, vaultID, string(reporterRaw), auditRecips); envelope != nil {
				audit.UploadBestEffort(cl, envelope)
			}
		},
	}
	return exec.Run(req)
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
// produces the guarded secret value. The wrap payload follows the
// storage class (design §6.6, v0.7): a synced item's decision carries
// the one-time item key, which decrypts the cached secret ciphertext; a
// LOCAL item (cache row with an empty secret_ciphertext) receives the
// secret value itself, which goes straight to the injection path. Key
// and value are destroyed by exec.Run after the single exec — neither
// reaches the keyring or the cache (design.md §15).
func resolveViaApproval(st *store.Store, vaultID, deviceID string, id *device.Identity, cl *client.Client,
	auditRecips []audit.OwnerRecipient, opts execOptions, rr *exec.ResolvedRef, itemID string, approvalUsed *bool) (*secret.Plaintext, int, string) {
	*approvalUsed = true
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
		value, code, state := approval.RequestSecret(&approval.Options{
			VaultID:   vaultID,
			DeviceID:  deviceID,
			Identity:  id,
			Owners:    auditRecips,
			ItemID:    itemID,
			Ref:       rr.Ref,
			Argv:      opts.Argv,
			Refs:      refsOf(opts),
			Injection: injectionModes(opts),
			Hosts:     rr.Meta.Policy.AllowedHosts,
			Reply:     replySpecs,
			Timeout:   opts.Timeout,
			Client:    cl,
			Stderr:    opts.Stderr,
		})
		if value == nil {
			return nil, code, state
		}
		return value, 0, ""
	}
	key, code, state := approval.RequestItemKey(&approval.Options{
		VaultID:   vaultID,
		DeviceID:  deviceID,
		Identity:  id,
		Owners:    auditRecips,
		ItemID:    itemID,
		Ref:       rr.Ref,
		Argv:      opts.Argv,
		Refs:      refsOf(opts),
		Injection: injectionModes(opts),
		Hosts:     rr.Meta.Policy.AllowedHosts,
		Reply:     replySpecs,
		Timeout:   opts.Timeout,
		Client:    cl,
		Stderr:    opts.Stderr,
	})
	if key == nil {
		return nil, code, state
	}
	defer key.Destroy()
	value, err := itemcrypt.DecryptSecretValue(key, it.SecretCiphertext, vaultID, itemID)
	if err != nil {
		fmt.Fprintf(opts.Stderr, "keyref: cannot decrypt secret for %s\n", rr.Ref)
		return nil, exitcode.UnwrapFailed, "unwrap-failed"
	}
	return value, 0, ""
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

// resolveValueFor decrypts the guarded secret value of one ref using
// its live use grant. Exit codes follow §7.6: 16 unwrap failure.
func resolveValueFor(st *store.Store, id *device.Identity, vaultID string, ownerPub []byte, ref, itemID string) (*secret.Plaintext, int, string) {
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
		value, err := itemcrypt.DecryptSecretValue(key, it.SecretCiphertext, vaultID, itemID)
		key.Destroy()
		if err != nil {
			fmt.Fprintf(os.Stderr, "keyref: cannot decrypt secret for %s\n", ref)
			return nil, exitcode.UnwrapFailed, "unwrap-failed"
		}
		return value, 0, ""
	}
	fmt.Fprintf(os.Stderr, "keyref: no usable item key for %s (approval items need the approval flow)\n", ref)
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
		Time:           time.Now().UnixMilli(),
		DeviceID:       reporterDeviceID,
		Refs:           o.Refs,
		Injection:      o.Injection,
		Argv:           o.Argv,
		AllowArgv:      o.AllowArgv,
		PolicyResult:   o.PolicyState,
		ApprovalResult: o.ApprovalResult,
		ChildExit:      o.ChildExit,
		Redactions:     o.Redactions,
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
