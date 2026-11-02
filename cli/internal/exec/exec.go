package exec

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	osexec "os/exec"

	"github.com/awnumar/memguard"

	"github.com/lidessen/keyref/cli/internal/itemcrypt"
	"github.com/lidessen/keyref/cli/internal/secret"
)

// ResolvedRef is one referenced secret: the decrypted meta (policy)
// plus, once values are resolved, the guarded plaintext. The command
// layer may supply metas only and let Run resolve values lazily AFTER
// the policy checks pass — a rejected exec then never decrypts the
// secret at all (design.md §7.3: all checks happen before spawn).
type ResolvedRef struct {
	Ref   string
	Meta  *itemcrypt.Meta
	Value *secret.Plaintext // guarded; destroyed by Run
	// Message marks an sms:<message_id> ref (design v0.8 §14.5). Such a
	// ref has no item meta and no item policy: its only gate is the
	// per-consumption approval round, so every item-level check below
	// skips it.
	Message bool
}

// MessageRefPrefix introduces an SMS consumption reference. Message
// refs exist only in exec injection values (--env / --stdin / --fd):
// `list` and `get` do not know them, and there is no argv placeholder
// form (design v0.8 §14.5).
const MessageRefPrefix = "sms:"

// ParseMessageRef reports whether ref is a well-formed
// sms:<message_id> (protocol §1.1: 16 random bytes as 32 lowercase
// hex).
func ParseMessageRef(ref string) (string, bool) {
	id, ok := strings.CutPrefix(ref, MessageRefPrefix)
	if !ok || len(id) != 32 {
		return "", false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", false
		}
	}
	return id, true
}

// Outcome reports what happened during one exec; the command layer
// turns it into the encrypted audit event. PolicyState is "allow" or
// "deny:<reason>" — every attempted exec, including rejections,
// produces exactly one outcome (design.md §7.7). ApprovalResult carries
// the §7.7 approval outcome ("approved" or the deny reason) when the
// run went through the approval flow, and DecisionDeviceID names the
// device that signed that decision (design v0.8 §14.5/§14.8) — empty
// when no approval decided the run.
type Outcome struct {
	ChildExit        int
	Redactions       int
	Injection        []string
	Refs             []string
	Argv             []string
	AllowArgv        bool
	PolicyState      string
	ApprovalResult   string
	DecisionDeviceID string
}

// childNotStarted marks outcomes whose child never ran.
const childNotStarted = -1

// ValueResolver lazily decrypts one ref's secret. It returns the exit
// code (non-zero) and deny-state on failure.
type ValueResolver func(ref string) (*secret.Plaintext, int, string)

// Request is one `keyref exec` invocation.
type Request struct {
	EnvRefs    []string // NAME=REF
	PassNames  []string // NAME from the caller environment
	StdinRef   string
	FdRefs     []string // N=REF
	FdTemplate string
	FdRaw      bool
	AllowArgv  bool
	Argv       []string

	// Pty runs the child on a pseudo-terminal owned by keyref (design.md
	// §7.1); Stdin, when set, is forwarded into the pty input. Replies
	// are the --reply REGEX=REF specs: their patterns match the child's
	// raw output and type the referenced secret into the pty input. Both
	// are gated by the double gate of §7.1 before anything runs.
	Pty     bool
	Stdin   io.Reader
	Replies []Reply

	// Refs carries the metas (and optionally the values). ResolveValue,
	// when set, is called after the policy checks pass to decrypt only
	// the refs actually in use.
	Refs         map[string]*ResolvedRef
	ResolveValue ValueResolver
	ParentEnv    []string

	Stdout, Stderr io.Writer

	// OnOutcome receives the audit summary of every attempt (allowed
	// or rejected) before the exit code is returned.
	OnOutcome func(o *Outcome)
}

// Run executes the policy checks, resolves and injects secrets, spawns
// the child directly (never a shell), redacts its output and returns
// the exit code per design.md §7.6. Guarded values are destroyed on
// every path (design.md §12.2).
func Run(req *Request) int {
	// Destroy every guarded value on every return path — including the
	// rejection paths below (design.md §12.2: explicit zeroing).
	defer func() {
		for _, rr := range req.Refs {
			rr.Value.Destroy()
		}
	}()

	code, outcome := run(req)
	if req.OnOutcome != nil {
		req.OnOutcome(outcome)
	}
	return code
}

func baseOutcome(req *Request) *Outcome {
	usedRefs := map[string]bool{}
	injection := map[string]bool{}
	for _, spec := range req.EnvRefs {
		if _, ref, err := splitEnvSpec(spec); err == nil {
			usedRefs[ref] = true
			injection["env"] = true
		}
	}
	for _, spec := range req.FdRefs {
		if _, ref, err := splitFdSpec(spec); err == nil {
			usedRefs[ref] = true
			injection["fd"] = true
		}
	}
	if req.StdinRef != "" {
		usedRefs[req.StdinRef] = true
		injection["stdin"] = true
	}
	if req.Pty {
		injection["pty"] = true
	}
	if len(req.Replies) > 0 {
		injection["reply"] = true
		for _, rp := range req.Replies {
			usedRefs[rp.Ref] = true
		}
	}
	if HasArgvPlaceholder(req.Argv) {
		injection["argv"] = true
		for _, ref := range ArgvPlaceholderRefs(req.Argv) {
			usedRefs[ref] = true
		}
	}
	refs := make([]string, 0, len(usedRefs))
	for r := range usedRefs {
		refs = append(refs, r)
	}
	sort.Strings(refs)
	modes := make([]string, 0, len(injection))
	for m := range injection {
		modes = append(modes, m)
	}
	sort.Strings(modes)
	return &Outcome{
		ChildExit:   childNotStarted,
		Injection:   modes,
		Refs:        refs,
		Argv:        req.Argv,
		AllowArgv:   req.AllowArgv,
		PolicyState: "deny:unknown",
	}
}

// deny completes an outcome as a rejection.
func (o *Outcome) deny(state string) *Outcome {
	o.PolicyState = "deny:" + state
	return o
}

func run(req *Request) (int, *Outcome) {
	outcome := baseOutcome(req)
	deny := func(code int, state string) (int, *Outcome) {
		return code, outcome.deny(state)
	}

	// design §14.5: there is no argv placeholder form for a message —
	// {{keyref:sms:…}} does not exist, and silently handing the literal
	// text to the child would look like an injection that never
	// happened. Reject it before anything else can accept it.
	if HasMessagePlaceholder(req.Argv) {
		fmt.Fprintln(req.Stderr, "keyref: sms: refs cannot be argv placeholders; use --env, --stdin or --fd")
		return deny(10, "sms-argv")
	}

	for r, rr := range req.Refs {
		if rr.Message {
			// No item meta, no item policy: an sms: ref is gated by its
			// own approval round and nothing else (design v0.8 §14.5).
			continue
		}
		if rr.Meta == nil {
			return deny(1, "internal")
		}
		if !rr.Meta.Injectable {
			fmt.Fprintf(req.Stderr, "keyref: item %s is not injectable (enable injection on iOS)\n", r)
			return deny(15, "not-injectable")
		}
	}

	// --allow-argv needs BOTH the flag and every referenced item's
	// policy.allowArgv (design.md §6.1, §7.1).
	argvHasPlaceholder := HasArgvPlaceholder(req.Argv)
	if argvHasPlaceholder || req.AllowArgv {
		if !req.AllowArgv {
			fmt.Fprintln(req.Stderr, "keyref: argv placeholders require --allow-argv")
			return deny(10, "allow-argv-flag")
		}
		for _, ref := range outcome.Refs {
			if req.Refs[ref].Message {
				// Message refs reach the child through injection values
				// only; they never take the argv path (design §14.5).
				continue
			}
			if !req.Refs[ref].Meta.Policy.AllowArgv {
				fmt.Fprintf(req.Stderr, "keyref: item %s does not allow argv injection (policy.allowArgv)\n", ref)
				return deny(10, "allow-argv-policy")
			}
		}
	}

	// --reply gates (design.md §7.1): BOTH that the item's allowCommands
	// explicitly contains this argv0 AND sensitivity = approval — the
	// approval screen shows the full pattern and a person is the
	// gatekeeper. Missing either gate is exit 10 before anything runs.
	if len(req.Replies) > 0 && !req.Pty {
		fmt.Fprintln(req.Stderr, "keyref: --reply requires --pty")
		return deny(10, "reply-needs-pty")
	}
	for _, rp := range req.Replies {
		if err := ValidateReplyPattern(rp.Pattern); err != nil {
			fmt.Fprintln(req.Stderr, "keyref:", err)
			return deny(10, "reply-pattern")
		}
		rr, ok := req.Refs[rp.Ref]
		if !ok {
			fmt.Fprintf(req.Stderr, "keyref: unknown ref %q\n", rp.Ref)
			return deny(11, "unknown-ref")
		}
		if rr.Message {
			fmt.Fprintln(req.Stderr, "keyref: --reply requires an item ref, not an sms: ref")
			return deny(10, "reply-message-ref")
		}
		if rr.Meta.Policy.Sensitivity != "approval" {
			fmt.Fprintf(req.Stderr, "keyref: --reply requires item %s to have sensitivity=approval\n", rp.Ref)
			return deny(10, "reply-sensitivity")
		}
		if len(req.Argv) > 0 && !allowCommandsContainArgv0(rr.Meta.Policy.AllowCommands, req.Argv[0]) {
			fmt.Fprintf(req.Stderr, "keyref: --reply requires item %s allowCommands to contain argv0 explicitly\n", rp.Ref)
			return deny(10, "reply-allowcommands")
		}
	}

	// Environment checks (design.md §7.2).
	envPairs := map[string]string{}
	for _, spec := range req.EnvRefs {
		name, ref, err := splitEnvSpec(spec)
		if err != nil {
			fmt.Fprintln(req.Stderr, "keyref:", err)
			return deny(10, "env-spec")
		}
		if err := ValidateEnvName(name); err != nil {
			fmt.Fprintln(req.Stderr, "keyref:", err)
			return deny(10, "env-name")
		}
		if _, dup := envPairs[name]; dup {
			fmt.Fprintf(req.Stderr, "keyref: duplicate --env variable %q\n", name)
			return deny(10, "env-duplicate")
		}
		envPairs[name] = ref
		outcome.addRef(ref)
	}
	for _, name := range req.PassNames {
		if err := ValidateEnvName(name); err != nil {
			fmt.Fprintln(req.Stderr, "keyref:", err)
			return deny(10, "pass-name")
		}
	}
	baseEnv, err := SanitizeParentEnv(req.ParentEnv, req.PassNames)
	if err != nil {
		fmt.Fprintln(req.Stderr, "keyref:", err)
		return deny(10, "env-missing")
	}

	for _, ref := range outcome.Refs {
		if _, ok := req.Refs[ref]; !ok {
			fmt.Fprintf(req.Stderr, "keyref: unknown ref %q\n", ref)
			return deny(11, "unknown-ref")
		}
	}

	// Command policy: PATH resolution, shebang chasing, deny list
	// (design.md §7.3). The child's PATH is the sanitized one. Every
	// simultaneously injected item's policy must be satisfied — an
	// intersection, not a union: a permissive item never unlocks
	// another item's secret.
	childPath := "PATH=/usr/bin:/bin"
	for _, kv := range baseEnv {
		if strings.HasPrefix(kv, "PATH=") {
			childPath = kv
			break
		}
	}
	searchPath := strings.TrimPrefix(childPath, "PATH=")
	resolved, err := ResolveCommand(req.Argv, searchPath)
	if err != nil {
		fmt.Fprintln(req.Stderr, "keyref:", err)
		if isPolicyErr(err) {
			return deny(10, "policy-command")
		}
		return deny(18, "cannot-start")
	}
	for _, ref := range outcome.Refs {
		if req.Refs[ref].Message {
			continue // no item policy to intersect (design §14.5)
		}
		for _, layer := range resolved.Layers {
			if !ItemAllowsCommand(layer, req.Refs[ref].Meta.Policy.AllowCommands) {
				fmt.Fprintf(req.Stderr, "keyref: command %q is not allowed by item %s (allowCommands)\n", layer, ref)
				return deny(10, "policy-command")
			}
		}
	}
	for _, ref := range outcome.Refs {
		if req.Refs[ref].Message {
			continue
		}
		if err := allowedHostsFromArgv(req.Argv, req.Refs[ref].Meta.Policy.AllowedHosts); err != nil {
			fmt.Fprintln(req.Stderr, "keyref:", err)
			return deny(10, "policy-hosts")
		}
	}

	if argvHasPlaceholder {
		// §7.1: the local-visibility warning must accompany the argv
		// injection decision; it never names the secret.
		fmt.Fprintln(req.Stderr, "keyref: warning: secrets injected into process arguments are visible to other local users (ps, Activity Monitor)")
	}

	// ---- policy passed: from here on, secret bytes are touched ----

	// Resolve values lazily (rejected attempts above never decrypt).
	for _, ref := range outcome.Refs {
		rr := req.Refs[ref]
		if rr.Value != nil {
			continue
		}
		if req.ResolveValue == nil {
			return deny(1, "internal")
		}
		pt, code, state := req.ResolveValue(ref)
		if pt == nil {
			return deny(code, state)
		}
		rr.Value = pt
	}

	// fd payloads (render + validate before spawn, design.md §15). The
	// rendered template is a guarded buffer (design.md §12.2).
	var fdPayloads map[int][]byte
	var guardedPayloads []*memguard.LockedBuffer
	defer func() {
		for _, b := range guardedPayloads {
			b.Destroy()
		}
	}()
	fdPayloads = map[int][]byte{}
	for _, spec := range req.FdRefs {
		n, ref, err := splitFdSpec(spec)
		if err != nil {
			fmt.Fprintln(req.Stderr, "keyref:", err)
			return deny(10, "fd-spec")
		}
		rr, ok := req.Refs[ref]
		if !ok {
			fmt.Fprintf(req.Stderr, "keyref: unknown ref %q\n", ref)
			return deny(11, "unknown-ref")
		}
		if req.FdRaw {
			if req.FdTemplate != "" {
				fmt.Fprintln(req.Stderr, "keyref: --fd-raw and --fd-template are mutually exclusive")
				return deny(10, "fd-mode")
			}
			fdPayloads[n] = rr.Value.Bytes() // guarded, no copy
		} else {
			if req.FdTemplate == "" {
				fmt.Fprintln(req.Stderr, "keyref: --fd requires --fd-template or --fd-raw")
				return deny(10, "fd-mode")
			}
			rendered, rerr := RenderTemplate(req.FdTemplate, rr.Value.Bytes())
			if rerr != nil {
				fmt.Fprintln(req.Stderr, "keyref:", rerr)
				return deny(15, "fd-template")
			}
			if verr := ValidateHeaderValue(rendered.Bytes()); verr != nil {
				rendered.Destroy()
				fmt.Fprintln(req.Stderr, "keyref:", verr)
				return deny(15, "fd-template")
			}
			guardedPayloads = append(guardedPayloads, rendered)
			fdPayloads[n] = rendered.Bytes()
		}
	}

	// argv placeholder substitution (the double gate passed above).
	// argv strings are an execve boundary: one conversion per argument,
	// documented residual per design.md §12.2.
	argv := req.Argv
	if argvHasPlaceholder {
		argv, err = ReplaceArgvPlaceholders(req.Argv, func(ref string) ([]byte, error) {
			if rr, ok := req.Refs[ref]; ok && rr.Value != nil {
				return rr.Value.Bytes(), nil
			}
			return nil, fmt.Errorf("unknown ref %q", ref)
		})
		if err != nil {
			fmt.Fprintln(req.Stderr, "keyref:", err)
			return deny(11, "unknown-ref")
		}
	}

	// Child environment with injected secrets. Each entry is assembled
	// in guarded memory and converted exactly once at the os/exec
	// boundary (cmd.Env is []string; design.md §12.2 residual).
	childEnv := append([]string(nil), baseEnv...)
	injectedNames := make([]string, 0, len(envPairs))
	for name := range envPairs {
		injectedNames = append(injectedNames, name)
	}
	sort.Strings(injectedNames)
	for _, name := range injectedNames {
		entry := guardedEnvEntry(name, req.Refs[envPairs[name]].Value.Bytes())
		childEnv = append(childEnv, entry)
		entry = ""
	}

	// Redaction matchers over every secret in use (design.md §7.4). The
	// pty path redacts the single merged pty stream (stdoutRed); the
	// plain path redacts stdout and stderr separately.
	secrets := map[string][]byte{}
	for _, ref := range outcome.Refs {
		if rr, ok := req.Refs[ref]; ok && rr.Value != nil {
			secrets[ref] = rr.Value.Bytes()
		}
	}
	stdoutRed := NewRedactor(secrets)
	defer stdoutRed.Destroy()
	stdoutRed.Attach(req.Stdout)

	// fd staging: guarded bytes written to an unlinked file or a
	// Linux memfd (design.md §7.1: unlink immediately after write,
	// pass the still-open fd).
	var fdFiles []*os.File
	fdTempDir := ""
	defer func() {
		for _, f := range fdFiles {
			f.Close()
		}
		if fdTempDir != "" {
			os.RemoveAll(fdTempDir)
		}
	}()
	maxFd := 0
	for n := range fdPayloads {
		if n > maxFd {
			maxFd = n
		}
	}
	if len(fdPayloads) > 0 {
		fdTempDir, err = os.MkdirTemp("", "keyref-fd-")
		if err != nil {
			fmt.Fprintf(req.Stderr, "keyref: fd staging failed\n")
			return deny(18, "fd-staging")
		}
		if err = os.Chmod(fdTempDir, 0o700); err != nil {
			fmt.Fprintf(req.Stderr, "keyref: fd staging failed\n")
			return deny(18, "fd-staging")
		}
	}
	var extra []*os.File
	for i := 3; i <= maxFd; i++ {
		if payload, ok := fdPayloads[i]; ok {
			f, staged := stageFdFile(fdTempDir, i, payload)
			if !staged {
				fmt.Fprintf(req.Stderr, "keyref: fd staging failed\n")
				return deny(18, "fd-staging")
			}
			fdFiles = append(fdFiles, f)
			extra = append(extra, f)
			continue
		}
		fill, ferr := os.Open(os.DevNull)
		if ferr != nil {
			fmt.Fprintf(req.Stderr, "keyref: fd staging failed\n")
			return deny(18, "fd-staging")
		}
		fdFiles = append(fdFiles, fill)
		extra = append(extra, fill)
	}

	cmd := osexec.Command(argv[0], argv[1:]...)
	cmd.Env = childEnv
	// Core dumps are disabled process-wide before the spawn and
	// inherited by the child (design.md §7.2, §7.5).
	DisableCoreDumps()

	if req.Pty {
		// The pty path owns its whole tail: the child gets the slave as
		// stdio inside a fresh session, raw output is matched by the
		// --reply patterns and redacted, and both directions are
		// brokered until the session ends (design.md §7.1).
		return runPtyChild(req, cmd, stdoutRed, secrets, extra, outcome, deny)
	}

	stderrRed := NewRedactor(secrets)
	defer stderrRed.Destroy()
	stderrRed.Attach(req.Stderr)
	cmd.ExtraFiles = extra
	cmd.Stdout = stdoutRed
	cmd.Stderr = stderrRed
	if req.StdinRef != "" {
		stdinPipe, perr := cmd.StdinPipe()
		if perr != nil {
			fmt.Fprintf(req.Stderr, "keyref: cannot set up stdin\n")
			return deny(18, "stdin-setup")
		}
		defer stdinPipe.Close()
		go func(ref string) {
			v := req.Refs[ref].Value.Bytes()
			_, _ = stdinPipe.Write(v)
			if len(v) == 0 || v[len(v)-1] != '\n' {
				_, _ = stdinPipe.Write([]byte("\n"))
			}
			_ = stdinPipe.Close()
		}(req.StdinRef)
	}
	// own process group so a redaction failure kills the whole tree
	// (design.md §7.4). Linux PR_SET_DUMPABLE=0 needs child-side
	// support and is not claimed here (design.md §7.2).
	cmd.SysProcAttr = childSysProcAttr()

	if serr := cmd.Start(); serr != nil {
		fmt.Fprintf(req.Stderr, "keyref: cannot start child: %v\n", serr)
		return deny(18, "cannot-start")
	}
	kill := func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			if cmd.SysProcAttr != nil && cmd.SysProcAttr.Setpgid {
				_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
			}
		}
	}
	stdoutRed.OnFail = kill
	stderrRed.OnFail = kill

	werr := cmd.Wait()

	if stdoutRed.Failed() || stderrRed.Failed() {
		fmt.Fprintln(req.Stderr, "keyref: redaction failed; output discarded")
		return deny(14, "redaction")
	}
	if ferr := stdoutRed.Flush(); ferr != nil {
		kill()
		fmt.Fprintln(req.Stderr, "keyref: redaction failed; output discarded")
		return deny(14, "redaction")
	}
	if ferr := stderrRed.Flush(); ferr != nil {
		kill()
		fmt.Fprintln(req.Stderr, "keyref: redaction failed; output discarded")
		return deny(14, "redaction")
	}

	childExit := 0
	if werr != nil {
		var ee *osexec.ExitError
		if errors.As(werr, &ee) {
			if status, ok := ee.Sys().(syscall.WaitStatus); ok && status.Signaled() {
				childExit = 128 + int(status.Signal())
			} else {
				childExit = ee.ExitCode()
			}
		} else {
			fmt.Fprintf(req.Stderr, "keyref: child wait failed: %v\n", werr)
			return deny(14, "wait")
		}
	}

	outcome.ChildExit = childExit
	outcome.Redactions = stdoutRed.Count() + stderrRed.Count()
	outcome.PolicyState = "allow"
	return childExit, outcome
}

func (o *Outcome) addRef(ref string) {
	for _, r := range o.Refs {
		if r == ref {
			return
		}
	}
	o.Refs = append(o.Refs, ref)
	sort.Strings(o.Refs)
}

// guardedEnvEntry assembles NAME=value inside guarded memory and
// returns the single string os/exec requires. The returned string is
// the one unavoidable heap copy at the execve boundary (cmd.Env is
// []string); the secret is never heap-concatenated (design.md §12.2).
func guardedEnvEntry(name string, value []byte) string {
	total := len(name) + 1 + len(value)
	buf := memguard.NewBuffer(total)
	if !buf.IsAlive() {
		// Guarded allocation failed: assemble once in a plain buffer
		// (a single conversion, still no heap string concat of the
		// secret) — a missing env entry would break the exec.
		b := make([]byte, 0, total)
		b = append(b, name...)
		b = append(b, '=')
		b = append(b, value...)
		return string(b)
	}
	b := buf.Bytes()
	copy(b, name)
	b[len(name)] = '='
	copy(b[len(name)+1:], value)
	s := string(b)
	buf.Destroy()
	return s
}

func isPolicyErr(err error) bool {
	var pe *PolicyError
	return errors.As(err, &pe)
}

// allowCommandsContainArgv0 implements the explicit argv0 half of the
// --reply double gate (design.md §7.1): the item's allowCommands must
// name the command — by the literal argv0 or its basename.
func allowCommandsContainArgv0(allowCommands []string, argv0 string) bool {
	base := filepath.Base(argv0)
	for _, w := range allowCommands {
		if strings.EqualFold(w, argv0) || strings.EqualFold(w, base) {
			return true
		}
	}
	return false
}

// isStartErr reports a safe-to-start failure (exit 18 class).
func isStartErr(err error) bool {
	var se *StartError
	return errors.As(err, &se)
}

func splitEnvSpec(spec string) (name, ref string, err error) {
	i := strings.IndexByte(spec, '=')
	if i <= 0 {
		return "", "", fmt.Errorf("--env expects NAME=REF")
	}
	return spec[:i], spec[i+1:], nil
}

func splitFdSpec(spec string) (fd int, ref string, err error) {
	i := strings.IndexByte(spec, '=')
	if i <= 0 {
		return 0, "", fmt.Errorf("--fd expects N=REF")
	}
	n, convErr := strconv.Atoi(spec[:i])
	if convErr != nil || n < 3 {
		return 0, "", fmt.Errorf("--fd expects a descriptor number >= 3")
	}
	return n, spec[i+1:], nil
}
