package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/lidessen/keyref/cli/internal/cache"
	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/localvault"
	"github.com/lidessen/keyref/cli/internal/meta"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/source"
	"github.com/lidessen/keyref/lib/exec"
	"github.com/lidessen/keyref/lib/exitcode"
	"github.com/lidessen/keyref/lib/local"
	"github.com/lidessen/keyref/lib/secret"
	"golang.org/x/term"
)

const maxLocalSecretBytes = 1 << 20

// stringList collects a repeatable flag value.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	if v == "" {
		return errors.New("must not be empty")
	}
	*l = append(*l, v)
	return nil
}

// secretStore is the OS keyring, or the directory implementation the
// tests and e2e runs point at. The MCP layer uses secretStoreOrError:
// a tool call reports failures as results, never through a panic.
func secretStore() keyring.SecretStore {
	ks, err := secretStoreOrError()
	if err != nil {
		fmt.Fprintln(os.Stderr, "keyref:", err)
		panic(fatalExit{1})
	}
	return ks
}

func secretStoreOrError() (keyring.SecretStore, error) {
	if dir := os.Getenv("KEYREF_KEYRING_DIR"); dir != "" {
		return keyring.NewDirStore(dir)
	}
	return keyring.OSKeyring{}, nil
}

// resolveSource applies --source, KEYREF_SOURCE and the configured
// default. The one-time default is recorded on the first command in a
// data directory: a vault paired before sources existed keeps the
// paired vault, so upgrading never moves existing commands onto an
// empty local vault.
func resolveSource(p config.Paths, override string) (source.Spec, error) {
	if _, err := os.Stat(source.Path(p)); errors.Is(err, os.ErrNotExist) {
		paired := false
		// Only look for a paired vault when its cache exists: a
		// local-only installation never grows a cache.sqlite. An
		// existing cache that cannot be read fails the command instead
		// of counting as "not paired" — that would write `local` as the
		// permanent default on a transient error (review 2026-11).
		if _, statErr := os.Stat(p.CacheFile); statErr == nil {
			st, err := cache.Open(p.Dir)
			if err != nil {
				return source.Spec{}, fmt.Errorf("could not open the sync cache %s: %w", p.CacheFile, err)
			}
			v, ok, getErr := st.GetKV(session.KVVaultID)
			closeErr := st.Close()
			if getErr != nil {
				return source.Spec{}, fmt.Errorf("could not read the sync cache %s: %w", p.CacheFile, getErr)
			}
			if closeErr != nil {
				return source.Spec{}, fmt.Errorf("could not close the sync cache %s: %w", p.CacheFile, closeErr)
			}
			paired = ok && len(v) > 0
		} else if !errors.Is(statErr, os.ErrNotExist) {
			return source.Spec{}, fmt.Errorf("could not stat %s: %w", p.CacheFile, statErr)
		}
		if err := source.Ensure(p, paired); err != nil {
			return source.Spec{}, err
		}
	}
	return source.Resolve(p, override)
}

// checkPrivateDir reports the reason a vault's directory is unusable.
// The local backend refuses a vault whose parent directory is readable
// by others, and says so here rather than "invalid local vault".
func checkPrivateDir(path string) error {
	parent := filepath.Dir(path)
	info, err := os.Lstat(parent)
	if err != nil {
		return fmt.Errorf("the directory %s is not usable: %v", parent, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", parent)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("the directory %s must be private (mode 0700) to hold a local vault", parent)
	}
	return nil
}

// errLocalLocked is the local-source view of `keyref lock`. The master
// key stays in the keyring, but nothing is unwrapped while locked (review
// 2026-11: local sources used to ignore the flag).
var errLocalLocked = errors.New("the session is locked; run `keyref unlock`")

// localOpenCode is the exit code for an openLocal failure: a lock is
// exit 12, everything else is a generic failure (design §17.8).
func localOpenCode(err error) int {
	if errors.Is(err, errLocalLocked) {
		return exitcode.SessionLocked
	}
	return 1
}

// localOpenError reports an openLocal failure on the process stderr and
// returns its exit code. Command paths use it; the MCP tool layer calls
// localOpenCode instead, because an MCP client never sees stderr
// (design §17.5).
func localOpenError(err error) int {
	return fatalf(localOpenCode(err), "%v", err)
}

// openLocal opens a local source's vault. The master key is wiped as
// soon as the backend has derived its own keys from it.
func openLocal(p config.Paths, spec source.Spec) (*local.Store, error) {
	if _, err := os.Stat(spec.Path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("local source %q has no vault yet; run `keyref init --source %s`", spec.Name, spec.Name)
	}
	if err := checkPrivateDir(spec.Path); err != nil {
		return nil, err
	}
	if locked(p) {
		return nil, errLocalLocked
	}
	ks, err := secretStoreOrError()
	if err != nil {
		return nil, err
	}
	key, err := localvault.Key(ks, spec.Path, os.LookupEnv)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(key)
	vault, err := localvault.Open(spec, key)
	if err != nil {
		// The library's classification decides the wording (design
		// §17.7): an embedder and the CLI say the same thing about the
		// same failure.
		switch {
		case errors.Is(err, local.ErrInvalidKey):
			return nil, fmt.Errorf("the master key does not match local source %q", spec.Name)
		case errors.Is(err, local.ErrStoreNotFound):
			// The vault disappeared between the check above and the open.
			return nil, fmt.Errorf("local source %q has no vault yet; run `keyref init --source %s`", spec.Name, spec.Name)
		case errors.Is(err, local.ErrInsecurePermissions):
			// The directory was checked above; this is the vault file's
			// own mode.
			return nil, fmt.Errorf("the vault file of local source %q must be private (mode 0600)", spec.Name)
		default:
			return nil, fmt.Errorf("could not open local source %q: %w", spec.Name, err)
		}
	}
	return vault, nil
}

// ---- source ----

func cmdSource(args []string) int {
	if len(args) == 0 {
		return fatalf(2, "usage: keyref source <list|default|add|remove>")
	}
	p := mustPaths()
	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fatalf(2, "usage: keyref source list")
		}
		cfg, err := source.Load(p)
		if err != nil {
			return fatalf(1, "%v", err)
		}
		for _, spec := range cfg.Specs() {
			where := spec.Path
			if spec.Kind == source.KindSync {
				where = "paired vault"
			}
			mark := ""
			if spec.Name == cfg.Default {
				mark = "  (default)"
			}
			fmt.Printf("%-16s %-6s %s%s\n", spec.Name, spec.Kind, where, mark)
		}
		return 0
	case "default":
		if len(args) == 1 {
			spec, err := resolveSource(p, "")
			if err != nil {
				return fatalf(1, "%v", err)
			}
			fmt.Println(spec.Name)
			return 0
		}
		if len(args) != 2 {
			return fatalf(2, "usage: keyref source default [NAME]")
		}
		if err := source.SetDefault(p, args[1]); err != nil {
			return fatalf(1, "%v", err)
		}
		fmt.Println(args[1])
		return 0
	case "add":
		fs := flag.NewFlagSet("source add", flag.ContinueOnError)
		path := fs.String("path", "", "absolute path of the new local vault")
		prepareHelp(fs, args[1:])
		rest, err := parseArgs(fs, args[1:])
		if err != nil {
			return parseExit(err)
		}
		if len(rest) != 1 {
			return fatalf(2, "usage: keyref source add NAME [--path /absolute/vault.db]")
		}
		spec, err := source.Add(p, rest[0], *path)
		if err != nil {
			return fatalf(1, "%v", err)
		}
		fmt.Printf("%s\t%s\n", spec.Name, spec.Path)
		fmt.Fprintf(os.Stderr, "keyref: run `keyref init --source %s` to create the vault\n", spec.Name)
		return 0
	case "remove":
		if len(args) != 2 {
			return fatalf(2, "usage: keyref source remove NAME")
		}
		if err := source.Remove(p, args[1]); err != nil {
			return fatalf(1, "%v", err)
		}
		fmt.Fprintf(os.Stderr, "keyref: source %q removed; its vault file was left in place\n", args[1])
		return 0
	default:
		return fatalf(2, "usage: keyref source <list|default|add|remove>")
	}
}

// ---- init / set / delete (local sources) ----

func cmdInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	sourceName := fs.String("source", "", "source to operate on")
	prepareHelp(fs, args)
	if _, err := parseArgs(fs, args); err != nil {
		return parseExit(err)
	}
	p := mustPaths()
	spec, err := resolveSource(p, *sourceName)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if spec.Kind != source.KindLocal {
		return fatalf(2, "init creates a local vault; the paired vault is created on iOS")
	}
	if _, err := os.Stat(spec.Path); err == nil {
		return fatalf(1, "local source %q already has a vault at %s; refusing to overwrite it", spec.Name, spec.Path)
	}
	if err := checkPrivateDir(spec.Path); err != nil {
		return fatalf(1, "%v", err)
	}
	vault, err := localvault.Create(secretStore(), spec, os.LookupEnv)
	if err != nil {
		if errors.Is(err, localvault.ErrKey) || errors.Is(err, localvault.ErrKeyExists) {
			return fatalf(1, "%v", err)
		}
		return fatalf(1, "could not create the local vault: %v", err)
	}
	if err := vault.Close(); err != nil {
		return fatalf(1, "could not close the local vault: %v", err)
	}
	fmt.Printf("local source %q initialized at %s\n", spec.Name, spec.Path)
	return 0
}

func cmdSet(args []string) int {
	fs := flag.NewFlagSet("set", flag.ContinueOnError)
	sourceName := fs.String("source", "", "source to operate on")
	raw := fs.Bool("raw", false, "store piped stdin byte for byte (default: strip one trailing newline)")
	description := fs.String("description", "", "description stored in the entry meta")
	var allowCommands, allowHosts stringList
	fs.Var(&allowCommands, "allow-command", "allow this command name for this entry (repeatable)")
	fs.Var(&allowHosts, "allow-host", "allow URL hosts in argv (repeatable)")
	prepareHelp(fs, args)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseExit(err)
	}
	if len(rest) != 1 {
		return fatalf(2, "usage: keyref set <ref> [--raw] [--description TEXT] [--allow-command NAME] [--allow-host HOST] [--source NAME]  (the secret is read from stdin)")
	}
	ref := rest[0]
	if !local.ValidRef(ref) {
		return fatalf(2, "invalid ref %q: a ref is one lowercase letter, or 2-64 lowercase letters, digits and hyphens starting with a letter and ending with a letter or digit", ref)
	}
	p := mustPaths()
	opts := local.PutOptions{Description: *description, AllowCommands: allowCommands, AllowedHosts: allowHosts}
	spec, client, err := writableSource(p, *sourceName)
	if err != nil {
		return fatalf(2, "%v", err)
	}
	if client != nil {
		defer clear(client.session.VaultKey)
		if len(allowHosts) > 0 {
			return fatalf(2, "--allow-host is available for local sources")
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		return client.putFromStdin(ctx, ref, *raw, opts)
	}
	if spec.Kind != source.KindLocal {
		return fatalf(2, "the paired vault is read-only for the CLI; create or edit items on iOS")
	}
	vault, err := openLocal(p, spec)
	if err != nil {
		return localOpenError(err)
	}
	defer vault.Close()
	value, err := readLocalSecret(os.Stdin, *raw)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	defer secret.Wipe(value)
	created, err := vault.Put(context.Background(), ref, value, opts)
	if err != nil {
		return fatalf(1, "could not store %q: %v", ref, err)
	}
	if len(value) < 8 {
		fmt.Fprintf(os.Stderr, "keyref: warning: the secret is %d bytes long; values shorter than 8 bytes are redacted less reliably\n", len(value))
	}
	verb := "replaced"
	if created {
		verb = "created"
	}
	fmt.Printf("%s %q\n", verb, ref)
	return 0
}

func cmdDelete(args []string) int {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	sourceName := fs.String("source", "", "source to operate on")
	prepareHelp(fs, args)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseExit(err)
	}
	if len(rest) != 1 {
		return fatalf(2, "usage: keyref delete <ref> [--source NAME]")
	}
	p := mustPaths()
	spec, err := resolveSource(p, *sourceName)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if spec.Kind != source.KindLocal {
		return fatalf(2, "the paired vault is read-only for the CLI; delete items on iOS")
	}
	vault, err := openLocal(p, spec)
	if err != nil {
		return localOpenError(err)
	}
	defer vault.Close()
	if err := vault.Delete(context.Background(), rest[0]); err != nil {
		if errors.Is(err, local.ErrNotFound) {
			return fatalf(exitcode.UnknownRef, "unknown ref %q", rest[0])
		}
		return fatalf(1, "could not delete %q: %v", rest[0], err)
	}
	fmt.Printf("deleted %q from source %q\n", rest[0], spec.Name)
	return 0
}

// confirmReveal asks for confirmation on the controlling terminal
// before printing a secret (design §17.4). It never reads stdin and
// never writes stdout, so `keyref get ref --reveal | pbcopy` keeps
// working; without a controlling terminal it refuses. There is no flag
// or environment variable that skips it.
func confirmReveal(ref string) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("--reveal needs a controlling terminal to confirm: %v", err)
	}
	defer tty.Close()
	if _, err := fmt.Fprintf(tty, "print the raw value of %q? [y/N] ", ref); err != nil {
		return fmt.Errorf("could not write the confirmation prompt: %v", err)
	}
	answer, err := readConfirmLine(tty)
	if err != nil {
		return fmt.Errorf("could not read the confirmation: %v", err)
	}
	if !confirmed(answer) {
		return errors.New("reveal cancelled: no confirmation on the controlling terminal")
	}
	return nil
}

// confirmed accepts only an explicit yes; everything else refuses.
func confirmed(answer string) bool {
	return answer == "y" || answer == "yes"
}

// readConfirmLine accepts a line ending in LF or CRLF and treats every
// other answer as refusal.
func readConfirmLine(r io.Reader) (string, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	return strings.ToLower(strings.TrimSpace(line)), nil
}

// runLocalGet shows one local entry from its encrypted meta. Without
// --reveal it never decrypts the secret; --reveal writes the raw secret
// bytes to stdout and nothing else.
func runLocalGet(p config.Paths, spec source.Spec, ref, format string, reveal bool) int {
	if reveal && format == "json" {
		return fatalf(2, "--reveal writes raw bytes and cannot be combined with --format json")
	}
	vault, err := openLocal(p, spec)
	if err != nil {
		return localOpenError(err)
	}
	defer vault.Close()
	if reveal {
		// Deliberate, explicitly requested plaintext path. It exists
		// for local sources only: the paired vault has no reveal at
		// all (design.md §16). The confirmation runs on the controlling
		// terminal, never on stdin/stdout, so piping the value still
		// works and an agent without a terminal is refused (§17.4).
		if err := confirmReveal(ref); err != nil {
			return fatalf(exitcode.PolicyRejection, "%v", err)
		}
		err := vault.Use(context.Background(), ref, func(value []byte) error {
			_, err := os.Stdout.Write(value)
			return err
		})
		if errors.Is(err, local.ErrNotFound) {
			return fatalf(exitcode.UnknownRef, "unknown ref %q", ref)
		}
		if err != nil {
			return fatalf(1, "could not read %q: %v", ref, err)
		}
		return 0
	}
	m, err := vault.Stat(context.Background(), ref)
	if errors.Is(err, local.ErrNotFound) {
		return fatalf(exitcode.UnknownRef, "unknown ref %q", ref)
	}
	if err != nil {
		return fatalf(1, "could not read %q: %v", ref, err)
	}
	e := localEntry(*m)
	return printEntry(&e, format)
}

// localEntry renders a local row in the same shape as a synced entry,
// so an agent only has to understand one list/get format (design §17.4).
func localEntry(m local.Meta) meta.Entry {
	return meta.Entry{
		Ref:         m.Ref,
		Name:        m.Ref,
		Description: m.Description,
		Type:        "local",
		Masked:      m.Masked,
		Sensitivity: "standard",
		Injectable:  true,
	}
}

// localList reads every local entry's meta. The secret column is
// never read: list decrypts the meta blob only.
func localList(p config.Paths, spec source.Spec) ([]meta.Entry, int) {
	vault, err := openLocal(p, spec)
	if err != nil {
		return nil, localOpenError(err)
	}
	defer vault.Close()
	metas, err := vault.List(context.Background())
	if err != nil {
		return nil, fatalf(1, "could not list source %q: %v", spec.Name, err)
	}
	entries := make([]meta.Entry, len(metas))
	for i, m := range metas {
		entries[i] = localEntry(m)
	}
	return entries, 0
}

// readLocalSecret reads one secret from stdin. On a terminal it reads one
// line without echo instead of waiting for EOF and never includes the line
// terminator. Piped input is read byte for byte up to 1 MiB, and unless raw
// is set exactly one trailing newline (\n or \r\n) is stripped: `echo
// "$TOKEN" | keyref set` then stores the token itself, so a consumer that
// trims its input still matches the redactor (design.md §7.4, §17.4).
func readLocalSecret(input *os.File, raw bool) ([]byte, error) {
	fd := int(input.Fd())
	if term.IsTerminal(fd) {
		value, err := readTerminalSecret(fd)
		_, _ = fmt.Fprintln(os.Stderr) // end the hidden line before any output
		if err != nil && !errors.Is(err, io.EOF) {
			secret.Wipe(value)
			return nil, errors.New("could not read the secret")
		}
		return checkSecretSize(value)
	}
	return readPipedSecret(input, raw)
}

// readTerminalSecret reads one line without echo. term.ReadPassword
// restores the terminal with defer, which does not run when a signal
// kills the process, so a signal handler restores the saved state and
// re-raises the signal: Ctrl-C must not leave the user's terminal with
// echo disabled.
func readTerminalSecret(fd int) ([]byte, error) {
	state, err := term.GetState(fd)
	if err != nil {
		return nil, err
	}
	sigCh := make(chan os.Signal, 1)
	done := make(chan struct{})
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	go func() {
		select {
		case sig := <-sigCh:
			_ = term.Restore(fd, state)
			signal.Reset(sig)
			if s, ok := sig.(syscall.Signal); ok {
				_ = syscall.Kill(os.Getpid(), s)
			}
		case <-done:
		}
	}()
	value, err := term.ReadPassword(fd)
	signal.Stop(sigCh)
	close(done)
	return value, err
}

func readPipedSecret(input io.Reader, raw bool) ([]byte, error) {
	// Three extra bytes leave room for a trailing CRLF that will be
	// trimmed, plus one more to prove that nothing follows a legal 1 MiB
	// value ending in CRLF. Reading only two extra would silently cut a
	// larger stream at a CRLF boundary and store its first 1 MiB.
	value, err := io.ReadAll(io.LimitReader(input, maxLocalSecretBytes+3))
	if err != nil {
		secret.Wipe(value)
		return nil, errors.New("could not read the secret")
	}
	if !raw {
		value = trimOneLineEnding(value)
	}
	return checkSecretSize(value)
}

func trimOneLineEnding(value []byte) []byte {
	if len(value) >= 2 && value[len(value)-2] == '\r' && value[len(value)-1] == '\n' {
		return value[:len(value)-2]
	}
	if len(value) >= 1 && value[len(value)-1] == '\n' {
		return value[:len(value)-1]
	}
	return value
}

func checkSecretSize(value []byte) ([]byte, error) {
	if len(value) == 0 || len(value) > maxLocalSecretBytes {
		secret.Wipe(value)
		return nil, errors.New("the secret on stdin must be 1 to 1048576 bytes")
	}
	return value, nil
}

// ---- exec on a local source ----

// localExecRef maps a local row onto the exec engine's own policy. A
// row that names its own allowCommands gets exactly that whitelist;
// without one the built-in deny list applies. argv injection stays off:
// nothing in a local vault records consent to putting a secret in
// process arguments.
func localExecRef(m *local.Meta) *exec.ResolvedRef {
	return &exec.ResolvedRef{
		Ref:        m.Ref,
		Injectable: true,
		Policy: exec.Policy{
			Sensitivity:   "standard",
			CommandPolicy: "deny-shells",
			AllowCommands: m.Policy.AllowCommands,
			AllowedHosts:  m.Policy.AllowedHosts,
		},
	}
}

// runLocalExec drives the same exec.Run as the paired vault — same
// policy checks before spawn, same injection, same redactor — but with
// no server, no grants, no approval round and no remote audit. Values
// are decrypted only after the policy checks pass.
func runLocalExec(p config.Paths, opts execOptions, spec source.Spec) int {
	if opts.LoginRef != "" {
		return fatalf(exitcode.PolicyRejection, "--stdin-login reads a synced item's username and value; it is not available on a local source")
	}
	vault, err := openLocal(p, spec)
	if err != nil {
		// opts.Stderr is the caller's channel: the CLI passes the
		// process stderr, the MCP exec tool passes the buffer that
		// becomes the tool result (design §17.5, issue #3).
		return fatalfTo(opts.Stderr, localOpenCode(err), "%v", err)
	}
	defer vault.Close()

	req := &exec.Request{
		EnvRefs: opts.EnvRefs, PassNames: opts.PassNames, StdinRef: opts.StdinRef,
		FdRefs: opts.FdRefs, FdTemplate: opts.FdTemplate, FdRaw: opts.FdRaw,
		AllowArgv: opts.AllowArgv, Argv: opts.Argv,
		Pty: opts.Pty, Stdin: opts.Stdin, Replies: opts.Replies,
		Refs:      map[string]*exec.ResolvedRef{},
		ParentEnv: os.Environ(), Stdout: opts.Stdout, Stderr: opts.Stderr,
	}
	for _, ref := range exec.CollectRefs(req) {
		m, err := vault.Stat(context.Background(), ref)
		switch {
		case err == nil:
			req.Refs[ref] = localExecRef(m)
		case errors.Is(err, local.ErrNotFound):
			// An unknown ref still needs a policy for the pass; it
			// resolves to exit 11 before any value is read.
			req.Refs[ref] = localExecRef(&local.Meta{Ref: ref})
		default:
			fmt.Fprintf(opts.Stderr, "keyref: could not read %q: %v\n", ref, err)
			return 1
		}
	}
	req.ResolveValue = func(ref string) (*secret.Plaintext, int, string) {
		var out *secret.Plaintext
		err := vault.Use(context.Background(), ref, func(value []byte) error {
			pt, err := secret.NewPlaintextFromBytes(value)
			if err != nil {
				return err
			}
			out = pt
			return nil
		})
		switch {
		case errors.Is(err, local.ErrNotFound):
			fmt.Fprintf(opts.Stderr, "keyref: unknown ref %q in source %q\n", ref, spec.Name)
			return nil, exitcode.UnknownRef, "unknown-ref"
		case err != nil || out == nil:
			fmt.Fprintf(opts.Stderr, "keyref: could not decrypt %q: %v\n", ref, err)
			return nil, exitcode.UnwrapFailed, "unwrap"
		}
		return out, 0, ""
	}
	return exec.Run(req)
}
