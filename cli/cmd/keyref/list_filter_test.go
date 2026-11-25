package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/meta"
	"github.com/lidessen/keyref/lib/local"
)

func TestListHost(t *testing.T) {
	for _, tc := range []struct {
		input, host, port string
		ok                bool
	}{
		{"https://GitHub.com:443/login?q=1", "GitHub.com", "443", true},
		{"github.com", "github.com", "", true},
		{"https://user@example.com/path", "example.com", "", true},
		{"github.com:8080", "github.com", "8080", true},
		{"[::1]:8080", "::1", "8080", true},
		{"https://[::1]/login", "::1", "", true},
		{"", "", "", false},
		{"github.com/path", "", "", false},
		{"https://github.com:bad/", "", "", false},
		{"https://", "", "", false},
	} {
		t.Run(tc.input, func(t *testing.T) {
			host, port, ok := listHost(tc.input)
			if host != tc.host || port != tc.port || ok != tc.ok {
				t.Fatalf("listHost(%q) = %q, %q, %v; want %q, %q, %v", tc.input, host, port, ok, tc.host, tc.port, tc.ok)
			}
		})
	}
}

func TestFilterEntries(t *testing.T) {
	entries := []meta.Entry{
		{Ref: "one", Type: "login", URL: "https://github.com/login"},
		{Ref: "two", Type: "LOGIN", URL: "https://GITHUB.com:443/"},
		{Ref: "other-port", Type: "login", URL: "https://github.com:8443/"},
		{Ref: "subdomain", Type: "login", URL: "https://api.github.com/"},
		{Ref: "no-url", Type: "login"},
		{Ref: "secret", Type: "secret", URL: "github.com"},
	}
	for _, tc := range []struct {
		name   string
		filter listFilter
		want   []string
	}{
		{"type", listFilter{Type: "LoGiN"}, []string{"one", "two", "other-port", "subdomain", "no-url"}},
		{"host", listFilter{URL: "GITHUB.COM"}, []string{"one", "two", "other-port", "secret"}},
		{"url and type", listFilter{URL: "https://github.com/login", Type: "login"}, []string{"one", "two", "other-port"}},
		{"port", listFilter{URL: "github.com:443"}, []string{"two"}},
		{"url port", listFilter{URL: "https://github.com:8443/"}, []string{"other-port"}},
		{"invalid", listFilter{URL: "https://"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, e := range filterEntries(entries, tc.filter) {
				got = append(got, e.Ref)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("refs = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestListFiltersCLIAndMCP(t *testing.T) {
	mcpTestEnv(t)
	spec := mcpInitLocal(t)
	p, err := config.Resolve()
	if err != nil {
		t.Fatal(err)
	}
	vault, err := openLocal(p, spec)
	if err != nil {
		t.Fatal(err)
	}
	username := "user"
	for _, row := range []struct{ ref, url string }{
		{"account-one", "https://github.com/login"},
		{"account-two", "https://GITHUB.com:443/"},
		{"other-site", "https://api.github.com/"},
		{"no-url", ""},
	} {
		if _, err := vault.Put(context.Background(), row.ref, []byte("synthetic-password"), local.PutOptions{Username: &username, URL: row.url}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := vault.Put(context.Background(), "plain-secret", []byte("synthetic-secret"), local.PutOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := vault.Close(); err != nil {
		t.Fatal(err)
	}

	for _, format := range []string{"text", "json"} {
		t.Run(format, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			old := os.Stdout
			os.Stdout = w
			code := cmdList([]string{"--vault", spec.Name, "--type", "LOGIN", "--url", "https://github.com/login", "--format", format})
			os.Stdout = old
			w.Close()
			out, err := io.ReadAll(r)
			r.Close()
			if err != nil || code != 0 {
				t.Fatalf("list exit %d, read: %v", code, err)
			}
			assertFilteredList(t, string(out))
			if format == "json" && !json.Valid(out) {
				t.Fatalf("invalid JSON: %s", out)
			}
		})
	}
	srv := mcpSession(t, spec.Name)
	resp, raw := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list","arguments":{"type":"LOGIN","url":"github.com"}}}`)
	if resp.Error != nil {
		t.Fatalf("MCP error: %+v", resp.Error)
	}
	assertFilteredList(t, raw)
	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list","arguments":{"url":42}}}`)
	if text := mcpText(t, resp); !strings.Contains(text, "exit_code: 2") {
		t.Fatalf("invalid arguments: %s", text)
	}
	for _, tool := range mcpTools() {
		if tool.Name == "list" && (!strings.Contains(string(tool.InputSchema), `"type":{"type":"string"`) || !strings.Contains(string(tool.InputSchema), `"url":{"type":"string"`)) {
			t.Fatalf("list schema: %s", tool.InputSchema)
		}
	}
}

func assertFilteredList(t *testing.T, out string) {
	t.Helper()
	for _, ref := range []string{"account-one", "account-two"} {
		if !strings.Contains(out, ref) {
			t.Errorf("missing %s in %s", ref, out)
		}
	}
	for _, ref := range []string{"other-site", "no-url", "plain-secret", "synthetic-password", "synthetic-secret"} {
		if strings.Contains(out, ref) {
			t.Errorf("unexpected %s in %s", ref, out)
		}
	}
}
