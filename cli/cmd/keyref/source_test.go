package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/source"
	"github.com/lidessen/keyref/lib/exec"
	"github.com/lidessen/keyref/lib/local"
)

func TestLocalExecPolicy(t *testing.T) {
	ref := localExecRef(&local.Meta{Ref: "my-ref"})
	if !ref.Injectable {
		t.Fatal("local entries must be injectable")
	}
	if ref.Policy.AllowArgv {
		t.Fatal("a local entry must not allow argv injection")
	}
	if ref.Policy.Sensitivity != "standard" {
		t.Fatalf("sensitivity = %q", ref.Policy.Sensitivity)
	}
	if !exec.ItemAllowsCommand("curl", ref.Policy) {
		t.Fatal("an ordinary command should be allowed under deny-shells")
	}
	if exec.ItemAllowsCommand("sh", ref.Policy) {
		t.Fatal("sh must stay denied for a local entry")
	}
	named := localExecRef(&local.Meta{
		Ref: "my-ref",
		Policy: local.Policy{
			AllowedHosts: []string{"api.openai.com"},
		},
	})
	if len(named.Policy.AllowedHosts) != 1 || named.Policy.AllowedHosts[0] != "api.openai.com" {
		t.Fatalf("allowedHosts = %v", named.Policy.AllowedHosts)
	}
}

func TestLocalExecUnsupportedInjectionHints(t *testing.T) {
	cases := []struct {
		name string
		opts execOptions
		want []string
	}{
		{"reply", execOptions{Replies: []exec.Reply{{Ref: "ref"}}}, []string{"--reply", "local sources", "--stdin", "approval item"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var stderr bytes.Buffer
			tc.opts.Stderr = &stderr
			if code := runLocalExec(config.Paths{}, tc.opts, source.Spec{}); code != 10 {
				t.Fatalf("exit %d, want 10", code)
			}
			for _, want := range tc.want {
				if !strings.Contains(stderr.String(), want) {
					t.Fatalf("diagnostic %q missing %q", stderr.String(), want)
				}
			}
		})
	}
}

func TestStatusLocalReportsEnvironmentKeyValidity(t *testing.T) {
	dir := t.TempDir()
	vault := filepath.Join(dir, "vault")
	if err := os.WriteFile(vault, nil, 0600); err != nil {
		t.Fatal(err)
	}
	valid := base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name, value, path, want string
	}{
		{"empty", "", vault, "key: invalid"},
		{"invalid base64", strings.Repeat("!", 44), vault, "key: invalid"},
		{"wrong length", base64.StdEncoding.EncodeToString(make([]byte, 31)), vault, "key: invalid"},
		{"missing vault", "", filepath.Join(dir, "missing"), "key: invalid"},
		{"valid", valid, vault, "key: KEYREF_LOCAL_MASTER"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("KEYREF_LOCAL_MASTER", tc.value)
			old := os.Stdout
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			os.Stdout = w
			code := statusLocal(config.Paths{LockFile: filepath.Join(dir, "locked")}, source.Spec{Name: "local", Path: tc.path})
			w.Close()
			os.Stdout = old
			out, err := io.ReadAll(r)
			r.Close()
			if err != nil || code != 0 || !strings.Contains(string(out), tc.want) {
				t.Fatalf("status code %d output %q read error %v; want %q", code, out, err, tc.want)
			}
			if tc.want == "key: invalid" && !strings.Contains(string(out), "KEYREF_LOCAL_MASTER is empty or invalid") {
				t.Fatalf("invalid override lacks diagnostic: %q", out)
			}
		})
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

func TestCheckSecretSizeWipesRejectedInput(t *testing.T) {
	value := bytes.Repeat([]byte{'x'}, maxLocalSecretBytes+1)
	if out, err := checkSecretSize(value); err == nil || out != nil {
		t.Fatal("oversized secret was accepted")
	}
	if !bytes.Equal(value, make([]byte, len(value))) {
		t.Fatal("rejected secret was not wiped")
	}
}

type failingSecretReader struct{ retained []byte }

func (r *failingSecretReader) Read(p []byte) (int, error) {
	n := copy(p, "synthetic-input")
	r.retained = p[:n]
	return n, errors.New("synthetic-input must not appear in the error")
}

func TestReadPipedSecretWipesPartialRead(t *testing.T) {
	reader := &failingSecretReader{}
	out, err := readPipedSecret(reader, false)
	if err == nil || out != nil || strings.Contains(err.Error(), "synthetic-input") {
		t.Fatal("read error returned plaintext or echoed the reader error")
	}
	if len(reader.retained) == 0 || !bytes.Equal(reader.retained, make([]byte, len(reader.retained))) {
		t.Fatal("partial secret was not wiped")
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

func TestLocalExecOptInAndLoginEntry(t *testing.T) {
	m := local.Meta{Ref: "login", Type: "login", Username: "person", URL: "https://example.test", Policy: local.Policy{AllowCommands: []string{"python3"}, AllowArgv: true}}
	r := localExecRef(&m)
	if !r.Policy.AllowArgv || !exec.ItemAllowsCommand("python3", r.Policy) || exec.ItemAllowsCommand("sh", r.Policy) {
		t.Fatalf("policy: %+v", r.Policy)
	}
	e := localEntry(m)
	if e.Type != "login" || e.Username != m.Username || e.URL != m.URL {
		t.Fatalf("entry: %+v", e)
	}
}
