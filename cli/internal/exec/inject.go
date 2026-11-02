package exec

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/awnumar/memguard"
)

// envNameRe is the POSIX-ish environment variable name grammar
// (design.md §7.2).
var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// envShortlist is the fixed parent-env allowlist (design.md §7.2).
var envShortlist = []string{
	"PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TERM", "TMPDIR",
}

// ValidateEnvName enforces the name grammar and the LD_*/DYLD_* ban
// (design.md §7.2): the sanitized environment must not re-admit them.
func ValidateEnvName(name string) error {
	if !envNameRe.MatchString(name) {
		return &PolicyError{Reason: fmt.Sprintf("environment variable name %q is invalid", name)}
	}
	if strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") {
		return &PolicyError{Reason: fmt.Sprintf("environment variable name %q is forbidden", name)}
	}
	return nil
}

// SanitizeParentEnv builds the child's base environment from the
// parent: only the shortlist survives, then the explicitly forwarded
// --pass names (values taken from the parent). Missing --pass names are
// a usage rejection (design.md §7.2: explicit by name, no bulk
// inheritance).
func SanitizeParentEnv(parent []string, passNames []string) ([]string, error) {
	parentMap := map[string]string{}
	for _, kv := range parent {
		if i := strings.IndexByte(kv, '='); i > 0 {
			parentMap[kv[:i]] = kv[i+1:]
		}
	}
	for _, name := range passNames {
		if err := ValidateEnvName(name); err != nil {
			return nil, err
		}
		if _, ok := parentMap[name]; !ok {
			return nil, &PolicyError{Reason: fmt.Sprintf("--pass variable %q is not present in the caller environment", name)}
		}
	}
	var out []string
	for _, name := range envShortlist {
		if v, ok := parentMap[name]; ok {
			out = append(out, name+"="+v)
		}
	}
	for _, name := range passNames {
		out = append(out, name+"="+parentMap[name])
	}
	return out, nil
}

// templateToken is the only placeholder a fd template may contain
// (design.md §7.1).
const templateToken = "{{keyref}}"

// InjectionError is an injection-content validation failure → exit 15
// (design.md §7.6).
type InjectionError struct{ Reason string }

func (e *InjectionError) Error() string { return "exec: injection invalid: " + e.Reason }

// RenderTemplate renders a --fd-template into GUARDED memory
// (design.md §12.2 names the rendered fd template among the buffers
// that must live in guarded allocations): the template must contain
// exactly one {{keyref}} token and no other braces. The caller owns
// the returned buffer and must Destroy it; the rendered bytes are
// validated by ValidateHeaderValue before any spawn.
func RenderTemplate(tmpl string, secret []byte) (*memguard.LockedBuffer, error) {
	if strings.Count(tmpl, templateToken) != 1 {
		return nil, &InjectionError{Reason: "--fd-template must contain exactly one {{keyref}} token"}
	}
	before, after, _ := strings.Cut(tmpl, templateToken)
	if strings.ContainsAny(before, "{}") || strings.ContainsAny(after, "{}") {
		return nil, &InjectionError{Reason: "--fd-template must not contain braces besides the {{keyref}} token"}
	}
	total := len(before) + len(secret) + len(after)
	buf := memguard.NewBuffer(total)
	if !buf.IsAlive() {
		return nil, &InjectionError{Reason: "guarded allocation for the rendered template failed"}
	}
	b := buf.Bytes()
	copy(b, before)
	copy(b[len(before):], secret)
	copy(b[len(before)+len(secret):], after)
	return buf, nil
}

// ValidateHeaderValue checks that the rendered fd template lands in the
// RFC 7230 header-value charset: visible ASCII plus SP/HTAB, no CR/LF,
// no NUL (design.md §7.1). The error names the constraint, never the
// value.
func ValidateHeaderValue(b []byte) error {
	for _, c := range b {
		if c == 0x09 {
			continue
		}
		if c < 0x20 || c > 0x7e {
			return &InjectionError{Reason: "rendered fd template must be visible ASCII with spaces or tabs only (no CR/LF/NUL or 8-bit bytes)"}
		}
	}
	return nil
}

// argvPlaceholderRe matches the {{keyref:REF}} argv placeholder (design
// §7.1). The keyref:// URI form was removed in v0.6: one notation, one
// parser. The keyref://pair QR scheme (§8.1) is unrelated and unchanged.
var argvPlaceholderRe = regexp.MustCompile(`\{\{keyref:([a-z][a-z0-9-]{0,62}[a-z0-9]|[a-z])\}\}`)

// HasArgvPlaceholder reports whether any argv element carries a
// placeholder.
func HasArgvPlaceholder(argv []string) bool {
	for _, a := range argv {
		if argvPlaceholderRe.MatchString(a) {
			return true
		}
	}
	return false
}

// HasMessagePlaceholder reports whether argv carries an
// {{keyref:sms:…}} placeholder. The form does not exist (design v0.8
// §14.5) — the argv placeholder grammar only admits item refs — so the
// caller rejects it explicitly instead of passing the literal text to
// the child.
func HasMessagePlaceholder(argv []string) bool {
	for _, a := range argv {
		if strings.Contains(a, "{{keyref:"+MessageRefPrefix) {
			return true
		}
	}
	return false
}

// ArgvPlaceholderRefs lists the refs referenced by argv placeholders.
func ArgvPlaceholderRefs(argv []string) []string {
	var refs []string
	seen := map[string]bool{}
	for _, a := range argv {
		for _, m := range argvPlaceholderRe.FindAllStringSubmatch(a, -1) {
			ref := m[1]
			if ref != "" && !seen[ref] {
				seen[ref] = true
				refs = append(refs, ref)
			}
		}
	}
	return refs
}

// ReplaceArgvPlaceholders substitutes every placeholder with the
// secret bytes resolved by resolve(ref). This is the --allow-argv path:
// the substituted argument becomes a Go string at the execve boundary
// (one conversion, documented residual per design.md §12.2; argv
// visibility itself is the explicit --allow-argv decision, §7.1).
func ReplaceArgvPlaceholders(argv []string, resolve func(ref string) ([]byte, error)) ([]string, error) {
	out := make([]string, len(argv))
	for i, a := range argv {
		var replaceErr error
		res := argvPlaceholderRe.ReplaceAllStringFunc(a, func(m string) string {
			ref := strings.TrimSuffix(strings.TrimPrefix(m, "{{keyref:"), "}}")
			secret, err := resolve(ref)
			if err != nil {
				replaceErr = err
				return m
			}
			return string(secret)
		})
		if replaceErr != nil {
			return nil, replaceErr
		}
		out[i] = res
	}
	return out, nil
}

// urlHostRe matches http(s) URL hosts in argv for the parameter check.
// The scheme is case-insensitive (RFC 3986 §3.1): children like curl
// normalize `HTTPS://host/` before connecting, so a uppercase scheme
// must not slip the host check (design.md §7.3).
var urlHostRe = regexp.MustCompile(`(?i)https?://([^/\s:<>"']+)`)

// allowedHostsFromArgv enforces one item's allowedHosts parameter
// check (design.md §7.3): when non-empty, every http:// and https://
// URL host in argv must match exactly (no suffix matching). An empty
// list means no host checking for THIS item; Run applies the check per
// referenced item, so the effective restriction is the intersection.
// This is best-effort parameter checking, not network isolation.
func allowedHostsFromArgv(argv []string, allowedHosts []string) error {
	if len(allowedHosts) == 0 {
		return nil // empty means no host checking (design.md §7.3)
	}
	allowed := map[string]bool{}
	for _, h := range allowedHosts {
		allowed[strings.ToLower(h)] = true
	}
	for _, a := range argv {
		for _, m := range urlHostRe.FindAllStringSubmatch(a, -1) {
			host := strings.ToLower(m[1])
			// Strip credentials if present.
			if i := strings.LastIndexByte(host, '@'); i >= 0 {
				host = host[i+1:]
			}
			if !allowed[host] {
				return &PolicyError{Reason: fmt.Sprintf(
					"argv URL host %q is not in the item's allowedHosts (exact match required)", m[1])}
			}
		}
	}
	return nil
}
