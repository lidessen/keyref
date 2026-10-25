package exec

import (
	"fmt"
	"regexp"
	"strings"
)

// Reply is one --reply REGEX=REF spec (design.md §7.1): when the regex
// matches the child's output BEFORE redaction, the referenced secret is
// written into the pty input, as if a person had typed it.
type Reply struct {
	Pattern string
	Ref     string
}

// ParseReply splits a --reply spec at the LAST '=' so patterns may
// contain '=' themselves (refs cannot: they are ^[a-z][a-z0-9-]*$).
func ParseReply(spec string) (Reply, error) {
	i := strings.LastIndexByte(spec, '=')
	if i <= 0 || i == len(spec)-1 {
		return Reply{}, &PolicyError{Reason: "--reply expects REGEX=REF"}
	}
	return Reply{Pattern: spec[:i], Ref: spec[i+1:]}, nil
}

// replyCanaries probe for "matches anything" patterns (design.md §7.1:
// an agent-supplied regex that fires on arbitrary output would type the
// secret into whatever is listening, so it is rejected outright).
var replyCanaries = []string{
	"x", "0", " ", "\t", "abcdefghij", "0123456789", "!@#%^&*()",
	"The quick brown fox jumps over the lazy dog",
}

// ValidateReplyPattern rejects patterns that must never be allowed to
// type a secret: empty strings, patterns that do not compile, patterns
// that match the empty string (".*", "a*", "(|x)") and patterns that
// match every canary (".+", "[\\s\\S]+"). A prompt pattern like
// "Password:" passes all four.
func ValidateReplyPattern(pattern string) error {
	if pattern == "" {
		return &PolicyError{Reason: "--reply pattern must not be empty"}
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return &PolicyError{Reason: fmt.Sprintf("--reply pattern does not compile: %v", err)}
	}
	if re.MatchString("") {
		return &PolicyError{Reason: "--reply pattern matches the empty string and could fire on any output"}
	}
	all := true
	for _, c := range replyCanaries {
		if !re.MatchString(c) {
			all = false
			break
		}
	}
	if all {
		return &PolicyError{Reason: "--reply pattern matches arbitrary output and must be anchored to the prompt"}
	}
	return nil
}

// compiledReply pairs a validated pattern with one-shot state.
type compiledReply struct {
	re    *regexp.Regexp
	ref   string
	fired bool
}

// replyMatcher matches patterns against the child's raw (pre-redaction)
// pty stream. It retains the last maxPatternLen−1 bytes across Feed
// calls so a prompt split across read boundaries is still caught.
type replyMatcher struct {
	replies []compiledReply
	keep    int
	buf     []byte
}

func newReplyMatcher(replies []Reply) (*replyMatcher, error) {
	m := &replyMatcher{}
	for _, r := range replies {
		if err := ValidateReplyPattern(r.Pattern); err != nil {
			return nil, err
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, err
		}
		m.replies = append(m.replies, compiledReply{re: re, ref: r.Ref})
		if n := len(r.Pattern); n > m.keep {
			m.keep = n - 1
		}
	}
	if m.keep < 64 {
		m.keep = 64
	}
	return m, nil
}

// Feed scans one raw output chunk and returns the refs whose patterns
// matched (each ref at most once per process lifetime).
func (m *replyMatcher) Feed(chunk []byte) []string {
	m.buf = append(m.buf, chunk...)
	var fired []string
	for i := range m.replies {
		if m.replies[i].fired {
			continue
		}
		if m.replies[i].re.Match(m.buf) {
			m.replies[i].fired = true
			fired = append(fired, m.replies[i].ref)
		}
	}
	// Retain only the tail a straddling match could still need.
	if len(m.buf) > m.keep {
		copy(m.buf, m.buf[len(m.buf)-m.keep:])
		m.buf = m.buf[:m.keep]
	}
	return fired
}
