package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/lidessen/keyref/cli/internal/cache"
	"github.com/lidessen/keyref/cli/internal/exec"
	"github.com/lidessen/keyref/cli/internal/exitcode"
	"github.com/lidessen/keyref/cli/internal/itemcrypt"
	"github.com/lidessen/keyref/cli/internal/keyring"
	"github.com/lidessen/keyref/cli/internal/localvault"
	"github.com/lidessen/keyref/cli/internal/secret"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/source"
	"github.com/lidessen/keyref/cli/local"
)

const maxLocalSecretBytes = 1 << 20

// secretStore is the OS keyring, or the directory implementation the
// tests and e2e runs point at.
func secretStore() keyring.SecretStore {
	if dir := os.Getenv("KEYREF_KEYRING_DIR"); dir != "" {
		ks, err := keyring.NewDirStore(dir)
		if err != nil {
			fmt.Fprintln(os.Stderr, "keyref:", err)
			panic(fatalExit{1})
		}
		return ks
	}
	return keyring.OSKeyring{}
}

// resolveSource applies --source, KEYREF_SOURCE and the configured
// default. The one-time default is recorded on the first command in a
// data directory: a vault paired before sources existed keeps the
// paired vault, so upgrading never moves existing commands onto an
// empty local vault.
func resolveSource(override string) (source.Spec, error) {
	p := mustPaths()
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

// localOpenError turns an openLocal failure into an exit code: a lock
// is exit 12, everything else is a generic failure.
func localOpenError(err error) int {
	if errors.Is(err, errLocalLocked) {
		return fatalf(exitcode.SessionLocked, "%v", err)
	}
	return fatalf(1, "%v", err)
}

// openLocal opens a local source's vault. The master key is wiped as
// soon as the backend has derived its own keys from it.
func openLocal(spec source.Spec) (*local.Store, error) {
	if _, err := os.Stat(spec.Path); errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("local source %q has no vault yet; run `keyref init --source %s`", spec.Name, spec.Name)
	}
	if err := checkPrivateDir(spec.Path); err != nil {
		return nil, err
	}
	if locked(mustStore()) {
		return nil, errLocalLocked
	}
	key, err := localvault.Key(secretStore(), spec.Name, os.LookupEnv)
	if err != nil {
		return nil, err
	}
	defer secret.Wipe(key)
	vault, err := localvault.Open(spec, key)
	if errors.Is(err, local.ErrInvalidKey) {
		return nil, fmt.Errorf("the master key does not match local source %q", spec.Name)
	}
	if err != nil {
		return nil, fmt.Errorf("could not open local source %q: %w", spec.Name, err)
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
			spec, err := resolveSource("")
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
		rest, err := parseArgs(fs, args[1:])
		if err != nil || len(rest) != 1 {
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
	if _, err := parseArgs(fs, args); err != nil {
		return fatalf(2, "usage: keyref init [--source NAME]")
	}
	spec, err := resolveSource(*sourceName)
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
	key, err := localvault.Provision(secretStore(), spec.Name, os.LookupEnv)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	defer secret.Wipe(key)
	vault, err := localvault.Create(spec, key)
	if err != nil {
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
	rest, err := parseArgs(fs, args)
	if err != nil || len(rest) != 1 {
		return fatalf(2, "usage: keyref set <ref> [--source NAME]  (the secret is read from stdin)")
	}
	spec, err := resolveSource(*sourceName)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if spec.Kind != source.KindLocal {
		return fatalf(2, "the paired vault is read-only for the CLI; create or edit items on iOS")
	}
	vault, err := openLocal(spec)
	if err != nil {
		return localOpenError(err)
	}
	defer vault.Close()
	value, err := readLocalSecret(os.Stdin)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	defer secret.Wipe(value)
	if err := vault.Put(context.Background(), rest[0], value); err != nil {
		return fatalf(1, "could not store %q: %v", rest[0], err)
	}
	fmt.Printf("stored %q in source %q\n", rest[0], spec.Name)
	return 0
}

func cmdDelete(args []string) int {
	fs := flag.NewFlagSet("delete", flag.ContinueOnError)
	sourceName := fs.String("source", "", "source to operate on")
	rest, err := parseArgs(fs, args)
	if err != nil || len(rest) != 1 {
		return fatalf(2, "usage: keyref delete <ref> [--source NAME]")
	}
	spec, err := resolveSource(*sourceName)
	if err != nil {
		return fatalf(1, "%v", err)
	}
	if spec.Kind != source.KindLocal {
		return fatalf(2, "the paired vault is read-only for the CLI; delete items on iOS")
	}
	vault, err := openLocal(spec)
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

// runLocalGet shows one local entry. Without --reveal it prints a mask
// computed locally, never the value; --reveal writes the raw secret
// bytes to stdout and nothing else.
func runLocalGet(spec source.Spec, ref, format string, reveal bool) int {
	if reveal && format == "json" {
		return fatalf(2, "--reveal writes raw bytes and cannot be combined with --format json")
	}
	vault, err := openLocal(spec)
	if err != nil {
		return localOpenError(err)
	}
	defer vault.Close()
	if reveal {
		// Deliberate, explicitly requested plaintext path. It exists
		// for local sources only: the paired vault has no reveal at
		// all (design.md §16).
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
	var masked string
	var size int
	err = vault.Use(context.Background(), ref, func(value []byte) error {
		size = len(value)
		masked = maskSecret(value)
		return nil
	})
	if errors.Is(err, local.ErrNotFound) {
		return fatalf(exitcode.UnknownRef, "unknown ref %q", ref)
	}
	if err != nil {
		return fatalf(1, "could not read %q: %v", ref, err)
	}
	if format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"ref": ref, "source": spec.Name, "masked": masked, "bytes": size,
		}); err != nil {
			return fatalf(1, "%v", err)
		}
		return 0
	}
	fmt.Printf("ref: %s\nsource: %s\nmasked: %s\nbytes: %d\n", ref, spec.Name, masked, size)
	return 0
}

// maskSecret keeps the shape of the synced mask — a hint of the head and
// the last four characters — and refuses to hint at binary, whitespace-
// containing or short values at all. It runs on plaintext the caller
// already holds; nothing here reaches the value itself.
func maskSecret(value []byte) string {
	for _, b := range value {
		if b < 0x21 || b > 0x7e {
			return "***"
		}
	}
	if len(value) < 16 {
		return "***"
	}
	return string(value[:3]) + "****" + string(value[len(value)-4:])
}

// readLocalSecret reads 1 byte to 1 MiB, byte-exact: a trailing newline
// is part of the secret, and the value never appears in argv or output.
func readLocalSecret(input io.Reader) ([]byte, error) {
	value, err := io.ReadAll(io.LimitReader(input, maxLocalSecretBytes+1))
	if err != nil {
		return nil, err
	}
	if len(value) == 0 || len(value) > maxLocalSecretBytes {
		return nil, errors.New("the secret on stdin must be 1 to 1048576 bytes")
	}
	return value, nil
}

// ---- exec on a local source ----

// localMeta is the policy a local entry gets. A local vault has no
// per-item policy record, so the deny-shells command policy applies and
// argv injection stays off: there is no item policy that could consent
// to putting a secret in process arguments.
func localMeta(ref string) *itemcrypt.Meta {
	return &itemcrypt.Meta{
		V: 1, Ref: ref, Name: ref, Type: "local", Injectable: true,
		Policy: itemcrypt.MetaPolicy{
			Sensitivity:   "standard",
			CommandPolicy: "deny-shells",
		},
	}
}

// runLocalExec drives the same exec.Run as the paired vault — same
// policy checks before spawn, same injection, same redactor — but with
// no server, no grants, no approval round and no remote audit. Values
// are decrypted only after the policy checks pass.
func runLocalExec(opts execOptions, spec source.Spec) int {
	if opts.LoginRef != "" {
		return fatalf(exitcode.PolicyRejection, "--stdin-login reads a synced item's username and value; it is not available on a local source")
	}
	vault, err := openLocal(spec)
	if err != nil {
		return localOpenError(err)
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
		req.Refs[ref] = &exec.ResolvedRef{Ref: ref, Meta: localMeta(ref)}
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
