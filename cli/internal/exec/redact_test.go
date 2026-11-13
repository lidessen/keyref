package exec

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

// oneShot runs the whole stream through a single Write+Flush.
func oneShot(t *testing.T, secrets map[string][]byte, stream []byte) (string, int) {
	t.Helper()
	var buf bytes.Buffer
	r := NewRedactor(secrets)
	r.Attach(&buf)
	if _, err := r.Write(stream); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := r.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	return buf.String(), r.Count()
}

func TestRedactEveryEncoding(t *testing.T) {
	secret := []byte("sk-PLAINTEXT-fixture-0123456789")
	secrets := map[string][]byte{"openai-prod": secret}
	want := "<redacted:openai-prod>"
	encodings := map[string][]byte{
		"raw":        secret,
		"b64std":     []byte(base64.StdEncoding.EncodeToString(secret)),
		"b64std-nop": []byte(strings.TrimRight(base64.StdEncoding.EncodeToString(secret), "=")),
		"b64url":     []byte(base64.URLEncoding.EncodeToString(secret)),
		"b64url-nop": []byte(strings.TrimRight(base64.URLEncoding.EncodeToString(secret), "=")),
		"hex-lower":  []byte(hex.EncodeToString(secret)),
		"hex-upper":  []byte(strings.ToUpper(hex.EncodeToString(secret))),
		"percent":    percentEncode(secret),
	}
	for name, enc := range encodings {
		stream := []byte("prefix " + string(enc) + " suffix")
		got, n := oneShot(t, secrets, stream)
		if got != "prefix "+want+" suffix" {
			t.Errorf("%s not redacted: %q", name, got)
		}
		if n != 1 {
			t.Errorf("%s: replacement count %d, want 1", name, n)
		}
	}
}

func TestRedactSplitAcrossChunksAtEveryPosition(t *testing.T) {
	secret := []byte("sk-cross-chunk-fixture-9876")
	secrets := map[string][]byte{"x": secret}
	// Try every possible raw-split point, and splits of the hex form.
	hexForm := hex.EncodeToString(secret)
	forms := [][]byte{secret, []byte(hexForm), percentEncode(secret)}
	for _, form := range forms {
		for split := 1; split < len(form)-1; split++ {
			var buf bytes.Buffer
			r := NewRedactor(secrets)
			r.Attach(&buf)
			if _, err := r.Write(form[:split]); err != nil {
				t.Fatal(err)
			}
			if _, err := r.Write(form[split:]); err != nil {
				t.Fatal(err)
			}
			if err := r.Flush(); err != nil {
				t.Fatal(err)
			}
			if got := buf.String(); got != "<redacted:x>" {
				t.Fatalf("form %q split at %d leaked: %q", form[:min(6, len(form))], split, got)
			}
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestRedactMultipleRefsAndLongestFirst(t *testing.T) {
	secrets := map[string][]byte{
		"a": []byte("secret-alpha-0001"),
		"b": []byte("secret-alpha-0001-with-suffix"),
	}
	stream := []byte("x secret-alpha-0001-with-suffix y secret-alpha-0001 z")
	got, n := oneShot(t, secrets, stream)
	if got != "x <redacted:b> y <redacted:a> z" {
		t.Fatalf("multi-ref redaction wrong: %q", got)
	}
	if n != 2 {
		t.Fatalf("count %d", n)
	}
}

func TestRedactManyChunks(t *testing.T) {
	secret := []byte("sk-multi-chunk-abcdef")
	secrets := map[string][]byte{"r": secret}
	var buf bytes.Buffer
	r := NewRedactor(secrets)
	r.Attach(&buf)
	chunk := []byte("noise-" + string(secret) + "-")
	for i := 0; i < 100; i++ {
		if _, err := r.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	got := buf.String()
	if strings.Contains(got, string(secret)) {
		t.Fatal("secret leaked in chunked stream")
	}
	if !strings.Contains(got, "<redacted:r>") {
		t.Fatal("replacement missing")
	}
	if r.Count() != 100 {
		t.Fatalf("replacement count %d, want 100", r.Count())
	}
}

type failingWriter struct{ after int }

func (f *failingWriter) Write(p []byte) (int, error) {
	if f.after <= 0 {
		return 0, fmt.Errorf("sink closed")
	}
	f.after--
	return len(p), nil
}

func TestRedactorFailureFiresOnFail(t *testing.T) {
	secrets := map[string][]byte{"r": []byte("sk-failcase-123456")}
	fired := false
	var buf bytes.Buffer
	r := NewRedactor(secrets)
	sink := &failingWriter{after: 0}
	_ = sink
	r.Attach(&buf)
	r.OnFail = func() { fired = true }
	// Redirect to a failing sink mid-test. Write only a prefix of the
	// secret so the bytes stay held until Flush.
	_, err := r.Write([]byte("sk-failcase-"))
	if err != nil {
		t.Fatal(err)
	}
	// Now swap the sink — simulate failure on flush.
	r.dst = &failingWriter{}
	_ = r.Flush()
	if !r.Failed() {
		t.Fatal("redactor did not record failure")
	}
	if !fired {
		t.Fatal("OnFail callback not fired")
	}
}

func TestWindowBasis(t *testing.T) {
	secret := bytes.Repeat([]byte{0xc3}, 40) // percent encoding expands 3x
	secrets := map[string][]byte{"w": secret}
	r := NewRedactor(secrets)
	if want := 3*len(secret) + 16; r.window < want {
		t.Fatalf("window %d < %d (design.md §7.4)", r.window, want)
	}
}

func TestRedactorEmptySecretDoesNotHang(t *testing.T) {
	// An empty value is a legal plaintext (jsonscan.go: empty string
	// value). Before the skip in NewRedactor it produced a zero-length
	// needle and emit spun on it forever, growing the buffer without
	// bound (OOM). This test must simply terminate.
	secrets := map[string][]byte{"empty": {}, "real": []byte("sk-empty-case-42")}
	var buf bytes.Buffer
	r := NewRedactor(secrets)
	defer r.Destroy()
	r.Attach(&buf)
	if _, err := r.Write([]byte("out: sk-empty-case-42 end")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := r.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if got := buf.String(); got != "out: <redacted:real> end" {
		t.Fatalf("stream rendered as %q, want real secret redacted and empty one inert", got)
	}
	if r.Count() != 1 {
		t.Fatalf("replacement count %d, want 1", r.Count())
	}

	// Only-empty map: nothing to match, stream passes through untouched.
	only := NewRedactor(map[string][]byte{"blank": {}})
	defer only.Destroy()
	var pass bytes.Buffer
	only.Attach(&pass)
	if _, err := only.Write([]byte("plain text")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := only.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if pass.String() != "plain text" {
		t.Fatalf("pass-through broken: %q", pass.String())
	}
}

func TestRedactTrimmedWhitespaceVariants(t *testing.T) {
	secret := []byte("sk-trim-fixture-0001\n")
	trimmed := []byte("sk-trim-fixture-0001")
	secrets := map[string][]byte{"trim": secret}
	want := "<redacted:trim>"

	// The raw value, newline included, still matches.
	if got, _ := oneShot(t, secrets, secret); got != want {
		t.Fatalf("raw value with newline: %q", got)
	}
	// Consumers trim before echoing, so every encoding of the trimmed
	// value must match too (design.md §7.4).
	encodings := map[string][]byte{
		"raw-trimmed": trimmed,
		"b64":         []byte(base64.StdEncoding.EncodeToString(trimmed)),
		"b64-nopad":   []byte(strings.TrimRight(base64.StdEncoding.EncodeToString(trimmed), "=")),
		"b64url":      []byte(base64.URLEncoding.EncodeToString(trimmed)),
		"hex-lower":   []byte(hex.EncodeToString(trimmed)),
		"hex-upper":   []byte(strings.ToUpper(hex.EncodeToString(trimmed))),
		"percent":     percentEncode(trimmed),
	}
	for name, enc := range encodings {
		got, _ := oneShot(t, secrets, []byte("x"+string(enc)+"y"))
		if got != "x"+want+"y" {
			t.Errorf("%s not redacted: %q", name, got)
		}
	}

	// Leading whitespace is trimmed as well.
	spaced := map[string][]byte{"spaced": []byte("  sk-spaced-fixture  ")}
	got, _ := oneShot(t, spaced, []byte("x sk-spaced-fixture y"))
	if got != "x <redacted:spaced> y" {
		t.Fatalf("leading whitespace variant not redacted: %q", got)
	}
}

func TestRedactorEmitsBytesThatCannotStartAMatch(t *testing.T) {
	var buf bytes.Buffer
	r := NewRedactor(map[string][]byte{"r": []byte("sk-prefix-fixture")})
	defer r.Destroy()
	r.Attach(&buf)
	if _, err := r.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "hello" {
		t.Fatalf("a tail that cannot start a match was withheld: %q", got)
	}
	if _, err := r.Write([]byte("sk-pre")); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "hello" {
		t.Fatalf("a potential match prefix must be held: %q", got)
	}
	if _, err := r.Write([]byte("fix-fixture")); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "hello<redacted:r>" {
		t.Fatalf("stream rendered as %q", got)
	}
}

func TestRedactorWaitsForALongerMatchAcrossChunks(t *testing.T) {
	secrets := map[string][]byte{
		"short": []byte("sk-abc"),
		"long":  []byte("sk-abcdefgh"),
	}
	var buf bytes.Buffer
	r := NewRedactor(secrets)
	defer r.Destroy()
	r.Attach(&buf)
	if _, err := r.Write([]byte("sk-abc")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 0 {
		t.Fatalf("a shorter match was emitted before the longer one could complete: %q", buf.String())
	}
	if _, err := r.Write([]byte("defgh")); err != nil {
		t.Fatal(err)
	}
	if err := r.Flush(); err != nil {
		t.Fatal(err)
	}
	if got := buf.String(); got != "<redacted:long>" {
		t.Fatalf("longest match lost across chunks: %q", got)
	}
}
