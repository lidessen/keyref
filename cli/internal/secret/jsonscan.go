package secret

import (
	"errors"
	"fmt"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/awnumar/memguard"
)

// Errors of the scanner. They describe positions, never content: the
// scanned bytes are secret plaintext and must not leak into error
// strings.
var (
	ErrSyntax        = errors.New("secret: malformed json plaintext")
	ErrFieldNotFound = errors.New("secret: field not found")
	ErrNotAString    = errors.New("secret: field value is not a json string")
)

// Plaintext is a guarded secret value extracted from decrypted JSON.
// The empty value is represented by a nil buffer with Bytes() == nil,
// because memguard cannot allocate zero-length buffers.
type Plaintext struct {
	buf *memguard.LockedBuffer
}

// Bytes returns the guarded plaintext, nil for the empty value.
func (p *Plaintext) Bytes() []byte {
	if p == nil || p.buf == nil {
		return nil
	}
	return p.buf.Bytes()
}

// EqualTo compares in constant time.
func (p *Plaintext) EqualTo(want []byte) bool {
	if p == nil || p.buf == nil {
		return len(want) == 0
	}
	return p.buf.EqualTo(want)
}

// Destroy wipes the guarded buffer. It is idempotent.
func (p *Plaintext) Destroy() {
	if p != nil && p.buf != nil {
		p.buf.Destroy()
		p.buf = nil
	}
}

// ExtractStringField scans a decrypted JSON object held in guarded
// memory and returns the string value of its top-level `field` in a
// fresh guarded buffer (design.md §12.2: no heap strings for secret
// values; the secret plaintext JSON of an item is
// {"v":1,"value":"...","username":"...","notes":"","fields":{}}).
//
// Decoding handles the full JSON string escape set, including surrogate
// pairs. Object keys containing escapes are skipped (never matched):
// keyref's own producers emit plain ASCII keys. The input buffer is left
// untouched; destroy it after use as usual.
func ExtractStringField(data []byte, field string) (*Plaintext, error) {
	if field == "" {
		return nil, errors.New("secret: empty field name")
	}
	i, err := skipWS(data, 0)
	if err != nil {
		return nil, err
	}
	if i >= len(data) || data[i] != '{' {
		return nil, ErrSyntax
	}
	i++
	for first := true; ; first = false {
		i, err = skipWS(data, i)
		if err != nil {
			return nil, err
		}
		if i < len(data) && data[i] == '}' {
			break
		}
		if !first {
			if i >= len(data) || data[i] != ',' {
				return nil, ErrSyntax
			}
			i++
			i, err = skipWS(data, i)
			if err != nil {
				return nil, err
			}
		}
		if i >= len(data) || data[i] != '"' {
			return nil, ErrSyntax
		}
		keyStart := i + 1
		keyEndAfterQuote, err := scanString(data, keyStart)
		if err != nil {
			return nil, err
		}
		keyInner := keyEndAfterQuote - 1 // index of the closing quote
		i = keyEndAfterQuote
		i, err = skipWS(data, i)
		if err != nil {
			return nil, err
		}
		if i >= len(data) || data[i] != ':' {
			return nil, ErrSyntax
		}
		i++
		i, err = skipWS(data, i)
		if err != nil {
			return nil, err
		}
		if keyInner-keyStart == len(field) && equalASCII(data[keyStart:keyInner], field) {
			if i >= len(data) {
				return nil, ErrSyntax
			}
			if data[i] != '"' {
				return nil, ErrNotAString
			}
			valStart := i + 1
			valEndAfterQuote, err := scanString(data, valStart)
			if err != nil {
				return nil, err
			}
			valInner := valEndAfterQuote - 1
			n, err := stringDecodedLen(data, valStart, valInner)
			if err != nil {
				return nil, err
			}
			if n == 0 {
				return &Plaintext{}, nil // empty string value
			}
			buf := memguard.NewBuffer(n)
			if !buf.IsAlive() {
				return nil, fmt.Errorf("secret: guarded allocation failed")
			}
			if _, err := decodeStringInto(data, valStart, valInner, buf.Bytes()[:0]); err != nil {
				buf.Destroy()
				return nil, err
			}
			return &Plaintext{buf: buf}, nil
		}
		i, err = skipValue(data, i)
		if err != nil {
			return nil, err
		}
	}
	return nil, ErrFieldNotFound
}

// equalASCII compares a byte span against an ASCII field name without
// allocating.
func equalASCII(span []byte, field string) bool {
	for k := 0; k < len(field); k++ {
		if span[k] != field[k] {
			return false
		}
	}
	return true
}

func skipWS(data []byte, i int) (int, error) {
	for i < len(data) {
		switch data[i] {
		case ' ', '\t', '\n', '\r':
			i++
		default:
			return i, nil
		}
	}
	return i, nil
}

// scanString validates the string token whose inner span starts at
// start and returns the index just past the closing quote. Escape
// sequences are validated so positioning never desynchronises.
func scanString(data []byte, start int) (int, error) {
	j := start
	for j < len(data) {
		c := data[j]
		if c == '"' {
			return j + 1, nil
		}
		if c == '\\' {
			j++
			if j >= len(data) {
				return 0, ErrSyntax
			}
			switch data[j] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				j++
			case 'u':
				if _, _, err := hex4(data, j+1); err != nil {
					return 0, err
				}
				j += 5
			default:
				return 0, ErrSyntax
			}
			continue
		}
		if c < 0x20 {
			return 0, ErrSyntax // unescaped control character
		}
		j++
	}
	return 0, ErrSyntax // unterminated string
}

// hex4 decodes four hex digits at data[i:i+4].
func hex4(data []byte, i int) (rune, int, error) {
	if i+4 > len(data) {
		return 0, 0, ErrSyntax
	}
	var v rune
	for k := 0; k < 4; k++ {
		c := data[i+k]
		var d rune
		switch {
		case c >= '0' && c <= '9':
			d = rune(c - '0')
		case c >= 'a' && c <= 'f':
			d = rune(c-'a') + 10
		case c >= 'A' && c <= 'F':
			d = rune(c-'A') + 10
		default:
			return 0, 0, ErrSyntax
		}
		v = v<<4 | d
	}
	return v, i + 4, nil
}

// decodeEscape decodes the escape sequence at data[j] == '\\', returning
// the decoded rune and the index just past the sequence. Surrogate pairs
// are combined.
func decodeEscape(data []byte, j int) (rune, int, error) {
	if j+1 >= len(data) {
		return 0, 0, ErrSyntax
	}
	switch e := data[j+1]; e {
	case '"', '\\', '/':
		return rune(e), j + 2, nil
	case 'b':
		return '\b', j + 2, nil
	case 'f':
		return '\f', j + 2, nil
	case 'n':
		return '\n', j + 2, nil
	case 'r':
		return '\r', j + 2, nil
	case 't':
		return '\t', j + 2, nil
	case 'u':
		r1, next, err := hex4(data, j+2)
		if err != nil {
			return 0, 0, err
		}
		if utf16.IsSurrogate(r1) {
			if next+1 < len(data) && data[next] == '\\' && data[next+1] == 'u' {
				r2, after, err := hex4(data, next+2)
				if err != nil {
					return 0, 0, err
				}
				r := utf16.DecodeRune(r1, r2)
				if r == utf8.RuneError {
					return 0, 0, ErrSyntax
				}
				return r, after, nil
			}
			return 0, 0, ErrSyntax // lone surrogate
		}
		return r1, next, nil
	default:
		return 0, 0, ErrSyntax
	}
}

// stringDecodedLen returns the decoded byte length of the string inner
// span data[start:end].
func stringDecodedLen(data []byte, start, end int) (int, error) {
	n := 0
	j := start
	for j < end {
		switch c := data[j]; {
		case c == '\\':
			r, next, err := decodeEscape(data, j)
			if err != nil {
				return 0, err
			}
			n += utf8.RuneLen(r)
			j = next
		case c < 0x20:
			return 0, ErrSyntax
		default:
			n++
			j++
		}
	}
	return n, nil
}

// decodeStringInto appends the decoded bytes of the string inner span
// data[start:end] to dst.
func decodeStringInto(data []byte, start, end int, dst []byte) ([]byte, error) {
	j := start
	for j < end {
		switch c := data[j]; {
		case c == '\\':
			r, next, err := decodeEscape(data, j)
			if err != nil {
				return nil, err
			}
			dst = utf8.AppendRune(dst, r)
			j = next
		case c < 0x20:
			return nil, ErrSyntax
		default:
			dst = append(dst, c)
			j++
		}
	}
	return dst, nil
}

// skipValue advances past one JSON value at data[i].
func skipValue(data []byte, i int) (int, error) {
	if i >= len(data) {
		return 0, ErrSyntax
	}
	switch c := data[i]; c {
	case '"':
		return scanString(data, i+1)
	case '{':
		i++
		i, err := skipWS(data, i)
		if err != nil {
			return 0, err
		}
		if i < len(data) && data[i] == '}' {
			return i + 1, nil
		}
		for {
			if i >= len(data) || data[i] != '"' {
				return 0, ErrSyntax
			}
			i, err = scanString(data, i+1)
			if err != nil {
				return 0, err
			}
			i, err = skipWS(data, i)
			if err != nil {
				return 0, err
			}
			if i >= len(data) || data[i] != ':' {
				return 0, ErrSyntax
			}
			i, err = skipValue(data, i+1)
			if err != nil {
				return 0, err
			}
			i, err = skipWS(data, i)
			if err != nil {
				return 0, err
			}
			if i < len(data) && data[i] == ',' {
				i++
				i, err = skipWS(data, i)
				if err != nil {
					return 0, err
				}
				continue
			}
			if i < len(data) && data[i] == '}' {
				return i + 1, nil
			}
			return 0, ErrSyntax
		}
	case '[':
		i++
		i, err := skipWS(data, i)
		if err != nil {
			return 0, err
		}
		if i < len(data) && data[i] == ']' {
			return i + 1, nil
		}
		for {
			i, err = skipValue(data, i)
			if err != nil {
				return 0, err
			}
			i, err = skipWS(data, i)
			if err != nil {
				return 0, err
			}
			if i < len(data) && data[i] == ',' {
				i++
				i, err = skipWS(data, i)
				if err != nil {
					return 0, err
				}
				continue
			}
			if i < len(data) && data[i] == ']' {
				return i + 1, nil
			}
			return 0, ErrSyntax
		}
	case 't':
		return skipLiteral(data, i, "true")
	case 'f':
		return skipLiteral(data, i, "false")
	case 'n':
		return skipLiteral(data, i, "null")
	default:
		// number: consume the JSON number grammar loosely but strictly
		// enough to stay inside the token.
		j := i
		for j < len(data) {
			ch := data[j]
			if ch == '-' || ch == '+' || ch == '.' || ch == 'e' || ch == 'E' ||
				(ch >= '0' && ch <= '9') {
				j++
				continue
			}
			break
		}
		if j == i {
			return 0, ErrSyntax
		}
		return j, nil
	}
}

func skipLiteral(data []byte, i int, lit string) (int, error) {
	if i+len(lit) > len(data) || !equalASCII(data[i:i+len(lit)], lit) {
		return 0, ErrSyntax
	}
	return i + len(lit), nil
}
