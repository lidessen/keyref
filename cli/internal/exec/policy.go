// Package exec implements `keyref exec` (design.md §7): policy checks
// in front of a direct os/exec spawn, secret injection through env,
// stdin and extra fds, multi-encoding redaction of child output, and
// the exit-code table of §7.6. The child is never started through a
// shell (design.md §15).
package exec

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lidessen/keyref/cli/internal/itemcrypt"
)

// PolicyError is a policy rejection → exit code 10 (design.md §7.6).
type PolicyError struct{ Reason string }

func (e *PolicyError) Error() string { return "exec: policy rejected: " + e.Reason }

// StartError means the child cannot be started safely → exit 18.
type StartError struct{ Reason string }

func (e *StartError) Error() string { return "exec: cannot start: " + e.Reason }

// denyList is the deny-shells command set of design.md §7.3, matched
// case-insensitively against the basename of the RESOLVED executable
// and of every shebang interpreter along the chain.
var denyList = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "fish": true,
	"ksh": true, "csh": true, "tcsh": true, "busybox": true,
	"env": true, "printenv": true,
	"echo": true, "printf": true,
	"cat": true, "tee": true, "dd": true, "od": true, "xxd": true,
	"hexdump": true, "base64": true, "base32": true,
	"openssl": true,
	"python":  true, "python2": true, "python3": true, "node": true,
	"nodejs": true, "deno": true, "bun": true, "perl": true, "ruby": true,
	"php": true, "lua": true,
	"osascript": true, "socat": true,
}

// maxShebangHops bounds interpreter chasing (design.md §7.3 step 2).
const maxShebangHops = 4

// ResolvedCommand is the outcome of resolving argv0 through PATH,
// symlinks and shebang interpreters.
type ResolvedCommand struct {
	// Path is the real executable the kernel will run.
	Path string
	// Layers are the lowercased basenames of every program in the
	// chain: the resolved argv0 and each shebang interpreter
	// (including /usr/bin/env arguments).
	Layers []string
	// First is the absolute PATH-resolved candidate for argv0 (the
	// file named by PATH/argv0 before symlinks are followed), and
	// FirstReal is its symlink-resolved path as checked. Run spawns
	// First, not Path: for a shebang script Path is the interpreter,
	// and for a multi-call binary the symlink name is what selects the
	// applet, so executing FirstReal would change behaviour.
	First     string
	FirstReal string
}

// Base returns the basename of the program that will actually run.
func (rc *ResolvedCommand) Base() string {
	if len(rc.Layers) == 0 {
		return ""
	}
	return rc.Layers[len(rc.Layers)-1]
}

// CommandPolicyAllowAll is the meta value that turns the owner's shell
// refusal off (design.md §7.3, protocol v2 §H). The default and any
// unknown value keep shell refusal on.
const CommandPolicyAllowAll = "allow-all"

// ItemAllowsCommand evaluates ONE item's command policy against one
// layer name (design.md §7.3, protocol v2 §H):
//
//   - A non-empty allowCommands list is an exact-name whitelist. It
//     always wins, whatever commandPolicy says: listing commands can
//     only tighten a policy.
//   - On the paired vault an empty list allows nothing unless the owner
//     turned shell refusal off (commandPolicy = allow-all). The built-in
//     deny list only catches slips — timeout sh -c, awk, find -exec and
//     aliased interpreters pass it — so it is not offered as protection
//     for items that came from the phone.
//   - On a local source an empty list keeps the built-in deny list; a
//     local vault has no per-item policy record to consent with.
func ItemAllowsCommand(base string, policy itemcrypt.MetaPolicy, paired bool) bool {
	if len(policy.AllowCommands) > 0 {
		for _, w := range policy.AllowCommands {
			if strings.EqualFold(w, base) {
				return true
			}
		}
		return false
	}
	if paired {
		return policy.CommandPolicy == CommandPolicyAllowAll
	}
	name := strings.ToLower(base)
	return !denyList[name] && !denyList[stripVersionSuffix(name)]
}

// commandDenial explains why one layer may not run for one item. ref is
// empty when the caller names no item (CheckCommand).
func commandDenial(ref, layer string, policy itemcrypt.MetaPolicy, paired bool) error {
	item := "the item"
	if ref != "" {
		item = "item " + ref
	}
	switch {
	case len(policy.AllowCommands) > 0:
		return &PolicyError{Reason: fmt.Sprintf(
			"command %q is not in %s's allowCommands whitelist", layer, item)}
	case paired:
		return &PolicyError{Reason: fmt.Sprintf(
			"%s allows no commands: an empty allowCommands list allows nothing on the paired vault; set the commands it may run on iOS", item)}
	default:
		return &PolicyError{Reason: fmt.Sprintf(
			"command %q is denied by the built-in deny list; local sources have no per-item allowCommands", layer)}
	}
}

// stripVersionSuffix drops a trailing version from an interpreter's
// real file name, so python3.13, perl5.36.0, lua5.4 and node18 are
// judged as python, perl, lua and node. Distributions install
// interpreters under versioned names and symlink the plain name to
// them; the deny list is matched against the symlink-resolved name.
func stripVersionSuffix(name string) string {
	return strings.TrimRight(name, "0123456789.-")
}

// CheckCommand resolves argv0 and judges every layer against ONE
// item's command policy. Run applies it per referenced item — the
// effective policy across multiple simultaneously injected items is the
// intersection, never the union: a permissive item never unlocks
// another item's secret.
func CheckCommand(argv []string, searchPath string, policy itemcrypt.MetaPolicy, paired bool) (*ResolvedCommand, error) {
	rc, err := ResolveCommand(argv, searchPath)
	if err != nil {
		return nil, err
	}
	for _, layer := range rc.Layers {
		if !ItemAllowsCommand(layer, policy, paired) {
			return nil, commandDenial("", layer, policy, paired)
		}
	}
	return rc, nil
}

// ResolveCommand implements execvp-style lookup with symlink
// canonicalisation, safe-to-start enforcement (regular, readable,
// executable, not setuid/setgid — exit 18) and shebang chasing up to
// maxShebangHops (design.md §7.3). It performs no policy judgement.
func ResolveCommand(argv []string, searchPath string) (*ResolvedCommand, error) {
	if len(argv) == 0 {
		return nil, &StartError{Reason: "empty argv"}
	}
	rc := &ResolvedCommand{}
	exe := argv[0]
	for hop := 0; hop < maxShebangHops; hop++ {
		cand, path, err := resolveExecutableBoth(exe, searchPath)
		if err != nil {
			return nil, err
		}
		if hop == 0 {
			rc.First, rc.FirstReal = cand, path
		}
		rc.Path = path
		rc.Layers = append(rc.Layers, strings.ToLower(filepath.Base(path)))

		interpreter, arg, err := readShebang(path)
		if err != nil {
			return nil, err
		}
		if interpreter == "" {
			return rc, nil
		}
		// The kernel will exec the interpreter; keep resolving that
		// layer. `/usr/bin/env python3` also resolves its argument as
		// a program (design.md §7.3 step 2).
		exe = interpreter
		if strings.EqualFold(filepath.Base(interpreter), "env") && arg != "" {
			argPath, err := resolveExecutable(arg, searchPath)
			if err != nil {
				return nil, err
			}
			rc.Layers = append(rc.Layers, strings.ToLower(filepath.Base(argPath)))
			exe = arg
		}
	}
	return nil, &PolicyError{Reason: "shebang interpreter chain too deep"}
}

// resolveExecutable implements execvp-style lookup: absolute or
// slash-containing paths are used as-is, bare names are searched along
// searchPath. It then canonicalises symlinks and enforces the
// safe-to-start conditions of design.md §7.3 step 3.
func resolveExecutable(exe, searchPath string) (string, error) {
	_, real, err := resolveExecutableBoth(exe, searchPath)
	return real, err
}

// resolveExecutableBoth also returns the absolute PATH-resolved
// candidate (before symlink resolution).
func resolveExecutableBoth(exe, searchPath string) (cand, real string, err error) {
	var candidates []string
	if strings.ContainsRune(exe, '/') {
		candidates = []string{exe}
	} else {
		for _, dir := range filepath.SplitList(searchPath) {
			if dir == "" {
				dir = "."
			}
			candidates = append(candidates, filepath.Join(dir, exe))
		}
	}
	for _, c := range candidates {
		cand := c
		fi, err := os.Stat(cand)
		if err != nil || fi.IsDir() {
			continue
		}
		if !fi.Mode().IsRegular() {
			return "", "", &StartError{Reason: fmt.Sprintf("%s is not a regular file", cand)}
		}
		if fi.Mode().Perm()&0o111 == 0 {
			return "", "", &StartError{Reason: fmt.Sprintf("%s is not executable", cand)}
		}
		if fi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return "", "", &StartError{Reason: fmt.Sprintf("%s is setuid/setgid", cand)}
		}
		// Resolve symlinks before judging the basename so multi-call
		// binaries (busybox) and disguised names are caught
		// (design.md §7.3 step 3).
		if _, err := os.ReadFile(cand); err != nil {
			return "", "", &StartError{Reason: fmt.Sprintf("%s is not readable", cand)}
		}
		real, err := filepath.EvalSymlinks(cand)
		if err != nil {
			return "", "", &StartError{Reason: fmt.Sprintf("%s cannot be resolved", cand)}
		}
		rfi, err := os.Stat(real)
		if err != nil || !rfi.Mode().IsRegular() {
			return "", "", &StartError{Reason: fmt.Sprintf("%s does not resolve to a regular file", cand)}
		}
		if rfi.Mode()&(os.ModeSetuid|os.ModeSetgid) != 0 {
			return "", "", &StartError{Reason: fmt.Sprintf("%s is setuid/setgid", real)}
		}
		abs, aerr := filepath.Abs(cand)
		if aerr != nil {
			return "", "", &StartError{Reason: fmt.Sprintf("%s cannot be resolved", cand)}
		}
		return abs, real, nil
	}
	return "", "", &StartError{Reason: fmt.Sprintf(
		"argv0 %q not found in PATH (fail closed)", exe)}
}

// readShebang returns the interpreter (and optional single argument) if
// path starts with "#!", else ("", "", nil).
func readShebang(path string) (interpreter, arg string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", &StartError{Reason: fmt.Sprintf("%s is not readable", path)}
	}
	defer f.Close()
	head := make([]byte, 256)
	n, _ := f.Read(head)
	head = head[:n]
	if len(head) < 2 || head[0] != '#' || head[1] != '!' {
		return "", "", nil
	}
	line := head[2:]
	if idx := bytes.IndexByte(line, '\n'); idx >= 0 {
		line = line[:idx]
	}
	fields := strings.Fields(string(line))
	if len(fields) == 0 {
		return "", "", &StartError{Reason: fmt.Sprintf("%s has an empty shebang", path)}
	}
	if len(fields) > 2 {
		// Linux passes at most one optional argument; more is invalid.
		return "", "", &StartError{Reason: fmt.Sprintf("%s has a multi-argument shebang", path)}
	}
	interpreter = fields[0]
	if len(fields) == 2 {
		arg = fields[1]
	}
	return interpreter, arg, nil
}
