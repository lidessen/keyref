package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/exec"
	"github.com/lidessen/keyref/cli/internal/source"
)

func TestMaskSecret(t *testing.T) {
	cases := []struct {
		name  string
		value []byte
		want  string
	}{
		{"long printable value", []byte("sk-abc1234567890wxyz"), "sk-****wxyz"},
		{"short value", []byte("short"), "***"},
		{"empty value", []byte{}, "***"},
		{"binary value", []byte{0x00, 0x01, 0x02, 0x03, 0xff, 0x10, 0x20, 0x30}, "***"},
		{"value with a trailing newline", []byte("sk-abc1234567890wxyz\n"), "***"},
		{"value with a space", []byte("two words here ok"), "***"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := maskSecret(tc.value); got != tc.want {
				t.Fatalf("maskSecret(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// A local entry has no per-item policy record: deny-shells applies and
// argv injection is never consented to.
func TestLocalMetaPolicy(t *testing.T) {
	meta := localMeta("my-ref")
	if !meta.Injectable {
		t.Fatal("local entries must be injectable")
	}
	if meta.Policy.AllowArgv {
		t.Fatal("a local entry must not allow argv injection")
	}
	if meta.Policy.Sensitivity != "standard" {
		t.Fatalf("sensitivity = %q", meta.Policy.Sensitivity)
	}
	if !exec.ItemAllowsCommand("curl", meta.Policy, false) {
		t.Fatal("an ordinary command should be allowed under deny-shells")
	}
	if exec.ItemAllowsCommand("sh", meta.Policy, false) {
		t.Fatal("sh must stay denied for local entries")
	}
}

func TestReadPipedSecretStripsOneTrailingNewline(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		raw     bool
		want    string
		wantErr bool
	}{
		{"lf", "tok\n", false, "tok", false},
		{"crlf", "tok\r\n", false, "tok", false},
		{"only one ending is stripped", "tok\r\n\r\n", false, "tok\r\n", false},
		{"no trailing newline", "tok", false, "tok", false},
		{"raw keeps lf", "tok\n", true, "tok\n", false},
		{"raw keeps crlf", "tok\r\n", true, "tok\r\n", false},
		{"a lone lf becomes empty", "\n", false, "", true},
		{"a lone crlf becomes empty", "\r\n", false, "", true},
		{"empty input", "", false, "", true},
		{"raw lone lf is a value", "\n", true, "\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := readPipedSecret(strings.NewReader(tc.in), tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("got %q, want an error", got)
				}
				return
			}
			if err != nil || string(got) != tc.want {
				t.Fatalf("got %q, %v; want %q", got, err, tc.want)
			}
		})
	}
}

func TestReadPipedSecretSizeLimits(t *testing.T) {
	max := bytes.Repeat([]byte{'x'}, maxLocalSecretBytes)
	withCRLF := append(append([]byte{}, max...), '\r', '\n')
	got, err := readPipedSecret(bytes.NewReader(withCRLF), false)
	if err != nil || len(got) != maxLocalSecretBytes {
		t.Fatalf("a 1 MiB value plus CRLF was rejected: len=%d err=%v", len(got), err)
	}
	oversize := append(append([]byte{}, max...), 'x')
	if _, err := readPipedSecret(bytes.NewReader(oversize), false); err == nil {
		t.Fatal("accepted a value over 1 MiB")
	}
	// A legal 1 MiB value plus CRLF followed by more data must be
	// rejected, not silently truncated at the CRLF boundary.
	withExtra := append(append(append([]byte{}, max...), '\r', '\n'), 'x')
	if _, err := readPipedSecret(bytes.NewReader(withExtra), false); err == nil {
		t.Fatal("accepted data after a 1 MiB value and CRLF")
	}
	if _, err := readPipedSecret(bytes.NewReader(max), true); err != nil {
		t.Fatalf("raw 1 MiB value: %v", err)
	}
}

// An existing sync cache that cannot be read must fail the command, not
// silently count as "not paired" and write `local` as the permanent
// default (review 2026-11).
func TestResolveSourceFailsClosedOnUnreadableCache(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(config.EnvHome, dir)
	// A directory where cache.sqlite belongs makes the sqlite open fail.
	if err := os.Mkdir(filepath.Join(dir, "cache.sqlite"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveSource(mustPaths(), ""); err == nil {
		t.Fatal("resolveSource accepted an unreadable sync cache")
	}
	if _, err := os.Stat(source.Path(mustPaths())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the default source was written despite the error: %v", err)
	}
}
