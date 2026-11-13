package exec

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"io"
	"sort"

	"github.com/awnumar/memguard"
)

// needle is one detectable encoding of one secret. The pattern bytes
// are DERIVED from the secret, so they live in guarded memory
// (design.md §12.2); the replacement text contains only the ref and
// stays on the ordinary heap.
type needle struct {
	pattern []byte // view into guarded memory (or heap fallback)
	replace []byte // ASCII replacement text
	guarded *memguard.LockedBuffer
}

// Redactor rewrites child output streams, replacing every appearance
// of any injected secret — raw, Base64 (std/url, with/without
// padding), lower/upper hex, and RFC 3986 percent-encoding (upper and
// lower hex digits) — with the fixed ASCII text <redacted:REF>
// (design.md §7.4).
//
// Streams are chunked. A secret split across read boundaries is caught by
// holding back only the trailing bytes that are still a prefix of some
// needle; every other byte is forwarded immediately (design.md §7.4). The
// window computed here is the upper bound this holding can reach.
type Redactor struct {
	needles  []needle
	window   int
	buf      []byte
	replaced int
	failed   bool
	dst      io.Writer

	// OnFail, when set, fires once on the first write failure so the
	// runner can kill the child instead of deadlocking on a full pipe.
	OnFail      func()
	onFailFired bool
}

// NewRedactor builds matchers for the given ref→secret values. Every
// encoded variant is generated directly into guarded memory; if a
// guarded allocation fails, the variant falls back to the ordinary
// heap rather than being skipped — a missing needle would silently
// weaken redaction, which is worse than a §12.2 residual.
func NewRedactor(secrets map[string][]byte) *Redactor {
	return newRedactor(secrets, nil)
}

// A fixed replacement avoids copying any reference into the stream.
func newRedactor(secrets map[string][]byte, fixedReplacement []byte) *Redactor {
	r := &Redactor{window: 16}
	refs := make([]string, 0, len(secrets))
	for ref := range secrets {
		refs = append(refs, ref)
	}
	sort.Strings(refs) // deterministic needle order
	for _, ref := range refs {
		secret := secrets[ref]
		if len(secret) == 0 {
			// An empty value is legal (jsonscan.go: empty string value) but
			// produces only zero-length patterns: every variant would match
			// at every position and a zero-length needle would leave emit
			// spinning in place forever. Nothing to redact — skip it.
			continue
		}
		replacement := fixedReplacement
		if replacement == nil {
			replacement = []byte("<redacted:" + ref + ">")
		}
		addVariants := func(value []byte) {
			for _, variant := range guardedVariants(value) {
				dup := false
				for _, n := range r.needles {
					if bytes.Equal(n.pattern, variant.pattern) {
						dup = true
						break
					}
				}
				if dup {
					if variant.guarded != nil {
						variant.guarded.Destroy()
					}
					continue
				}
				variant.replace = replacement
				r.needles = append(r.needles, variant)
			}
		}
		addVariants(secret)
		// A value with leading or trailing ASCII whitespace (typically the
		// newline `echo $TOKEN | keyref set` used to leave behind) is also
		// matched after trimming: consumers trim before echoing, and raw
		// matching alone would let the trimmed plaintext through
		// (design.md §7.4).
		if trimmed := trimASCIISpace(secret); len(trimmed) > 0 && !bytes.Equal(trimmed, secret) {
			addVariants(trimmed)
		}
		// Window basis: percent-encoding expands 3× at most (design.md §7.4).
		if w := 3*len(secret) + 16; w > r.window {
			r.window = w
		}
	}
	// Longest-first so the most specific encoding wins deterministically.
	sort.Slice(r.needles, func(i, j int) bool {
		if len(r.needles[i].pattern) != len(r.needles[j].pattern) {
			return len(r.needles[i].pattern) > len(r.needles[j].pattern)
		}
		return bytes.Compare(r.needles[i].pattern, r.needles[j].pattern) < 0
	})
	return r
}

// guardedVariants builds every representation of secret the redactor
// matches (design.md §7.4), filling guarded buffers in place so no
// encoded copy of the secret lands on the ordinary heap.
func guardedVariants(secret []byte) []needle {
	var out []needle
	build := func(capHint int, fill func(dst []byte) []byte) {
		buf := memguard.NewBuffer(capHint)
		if !buf.IsAlive() {
			// Guarded allocation failed: heap fallback beats a missing
			// needle (documented §12.2 residual on mlock exhaustion).
			out = append(out, needle{pattern: fill(make([]byte, 0, capHint))})
			return
		}
		out = append(out, needle{pattern: fill(buf.Bytes()[:0]), guarded: buf})
	}
	trimPad := func(b []byte) []byte {
		for len(b) > 0 && b[len(b)-1] == '=' {
			b = b[:len(b)-1]
		}
		return b
	}

	// raw
	build(len(secret), func(dst []byte) []byte { return append(dst, secret...) })
	// base64 std/url, padded and unpadded
	b64cap := base64.StdEncoding.EncodedLen(len(secret)) + 4
	build(b64cap, func(dst []byte) []byte { return base64.StdEncoding.AppendEncode(dst, secret) })
	build(b64cap, func(dst []byte) []byte { return trimPad(base64.StdEncoding.AppendEncode(dst, secret)) })
	build(b64cap, func(dst []byte) []byte { return base64.URLEncoding.AppendEncode(dst, secret) })
	build(b64cap, func(dst []byte) []byte { return trimPad(base64.URLEncoding.AppendEncode(dst, secret)) })
	// hex, lower and upper
	build(2*len(secret), func(dst []byte) []byte { return hex.AppendEncode(dst, secret) })
	build(2*len(secret), func(dst []byte) []byte {
		dst = hex.AppendEncode(dst, secret)
		for i := range dst {
			if dst[i] >= 'a' && dst[i] <= 'f' {
				dst[i] -= 'a' - 'A'
			}
		}
		return dst
	})
	// percent-encoding, uppercase and lowercase hex digits: RFC 3986
	// §2.1 lets decoders accept both, so both are matched.
	build(3*len(secret), func(dst []byte) []byte { return percentEncodeInto(dst, secret, true) })
	build(3*len(secret), func(dst []byte) []byte { return percentEncodeInto(dst, secret, false) })
	return out
}

// trimASCIISpace strips only ASCII whitespace, not the Unicode set
// bytes.TrimSpace would also remove (design.md §7.4 says ASCII).
func trimASCIISpace(b []byte) []byte {
	return bytes.Trim(b, " \t\n\v\f\r")
}

// percentEncodeInto percent-encodes every byte that is not RFC 3986
// unreserved (ALPHA / DIGIT / "-" / "." / "_" / "~") into dst, with
// uppercase or lowercase hex digits.
func percentEncodeInto(dst, b []byte, upper bool) []byte {
	const upperDigits = "0123456789ABCDEF"
	const lowerDigits = "0123456789abcdef"
	digits := lowerDigits
	if upper {
		digits = upperDigits
	}
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9',
			c == '-', c == '.', c == '_', c == '~':
			dst = append(dst, c)
		default:
			dst = append(dst, '%', digits[c>>4], digits[c&0xf])
		}
	}
	return dst
}

// percentEncode is the uppercase-hex form (test helper).
func percentEncode(b []byte) []byte {
	return percentEncodeInto(make([]byte, 0, 3*len(b)), b, true)
}

// Attach sets the destination writer of this redactor.
func (r *Redactor) Attach(w io.Writer) { r.dst = w }

// Count returns how many replacements were made (audit input).
func (r *Redactor) Count() int { return r.replaced }

// Failed reports whether a write failed after partial redaction; the
// runner then kills the child and discards buffered output with exit
// code 14 (design.md §7.4: never "output as much as possible").
func (r *Redactor) Failed() bool { return r.failed }

// Destroy wipes every guarded needle (design.md §12.2).
func (r *Redactor) Destroy() {
	for i := range r.needles {
		if r.needles[i].guarded != nil {
			r.needles[i].guarded.Destroy()
			r.needles[i].guarded = nil
			r.needles[i].pattern = nil
		}
	}
	r.needles = nil
}

// Write consumes a child-output chunk. Only decided bytes are emitted.
func (r *Redactor) Write(p []byte) (int, error) {
	r.buf = append(r.buf, p...)
	if err := r.emit(false); err != nil {
		r.failed = true
		r.fireOnFail()
		return 0, err
	}
	return len(p), nil
}

// Flush emits everything remaining (end of stream).
func (r *Redactor) Flush() error {
	if err := r.emit(true); err != nil {
		r.failed = true
		r.fireOnFail()
		return err
	}
	if len(r.buf) > 0 {
		if _, err := r.dst.Write(r.buf); err != nil {
			r.failed = true
			r.fireOnFail()
			return err
		}
		r.buf = r.buf[:0]
	}
	return nil
}

func (r *Redactor) fireOnFail() {
	if r.OnFail != nil && !r.onFailFired {
		r.onFailFired = true
		r.OnFail()
	}
}

// emit scans the buffer, translating decided positions. With final it
// also decides positions near the end of the buffer.
func (r *Redactor) emit(final bool) error {
	if len(r.needles) == 0 {
		return nil
	}
	i := 0
	var out []byte
	for i < len(r.buf) {
		remaining := r.buf[i:]
		matched := false
		held := false
		// Longest-first: a longer needle that could still complete in a
		// later chunk keeps this position undecided even when a shorter
		// needle matches here, so the longest match always wins.
		for _, n := range r.needles {
			p := n.pattern
			if len(p) == 0 {
				// Defensive; NewRedactor skips empty secrets and empty
				// trimmed variants.
				continue
			}
			if len(p) <= len(remaining) {
				if bytes.Equal(remaining[:len(p)], p) {
					out = append(out, n.replace...)
					r.replaced++
					i += len(p)
					matched = true
					break
				}
				continue
			}
			// The tail is shorter than this needle. Hold it only when it
			// is a prefix of the needle; otherwise no match can start
			// here and the byte is forwarded immediately (design.md §7.4:
			// the window is an upper bound, not a fixed hold).
			if !final && bytes.HasPrefix(p, remaining) {
				held = true
				break
			}
		}
		if matched {
			continue
		}
		if held {
			break
		}
		out = append(out, remaining[0])
		i++
	}
	r.buf = append(r.buf[:0], r.buf[i:]...)
	if len(out) > 0 {
		if _, err := r.dst.Write(out); err != nil {
			return err
		}
	}
	return nil
}
