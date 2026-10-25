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
	// Redirect to a failing sink mid-test.
	_, err := r.Write([]byte("sk-failcase-123456"))
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
