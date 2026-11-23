package main

import (
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/lidessen/keyref/cli/internal/meta"
)

func captureListOutput(t *testing.T, entries []meta.Entry, format string) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = w
	defer func() { os.Stdout = old }()
	code := printEntries(entries, format)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("printEntries returned %d", code)
	}
	return string(out)
}

func TestListTextOmitsRedundantNames(t *testing.T) {
	entries := []meta.Entry{
		{Ref: "first", Name: "first", Type: "secret", Source: "local", Masked: "****"},
		{Ref: "second", Name: "", Type: "secret", Source: "local", Masked: "****"},
	}
	want := fmt.Sprintf("%-24s %-10s %-16s %s\n", "REF", "TYPE", "SOURCE", "MASKED") +
		fmt.Sprintf("%-24s %-10s %-16s %s\n", "first", "secret", "local", "****") +
		fmt.Sprintf("%-24s %-10s %-16s %s\n", "second", "secret", "local", "****")
	if got := captureListOutput(t, entries, "text"); got != want {
		t.Fatalf("text output:\n%q\nwant:\n%q", got, want)
	}
}

func TestListTextShowsDistinctNames(t *testing.T) {
	entries := []meta.Entry{
		{Ref: "sync-ref", Name: "Sync name", Type: "secret", Source: "sync", Masked: "****"},
		{Ref: "local-ref", Name: "local-ref", Type: "secret", Source: "local", Masked: "****"},
		{Ref: "empty-ref", Type: "secret", Source: "local", Masked: "****"},
	}
	want := fmt.Sprintf("%-24s %-28s %-10s %-16s %s\n", "REF", "NAME", "TYPE", "SOURCE", "MASKED") +
		fmt.Sprintf("%-24s %-28s %-10s %-16s %s\n", "sync-ref", "Sync name", "secret", "sync", "****") +
		fmt.Sprintf("%-24s %-28s %-10s %-16s %s\n", "local-ref", "—", "secret", "local", "****") +
		fmt.Sprintf("%-24s %-28s %-10s %-16s %s\n", "empty-ref", "—", "secret", "local", "****")
	if got := captureListOutput(t, entries, "text"); got != want {
		t.Fatalf("text output:\n%q\nwant:\n%q", got, want)
	}
}

func TestListJSONPreservesNames(t *testing.T) {
	entries := []meta.Entry{{Ref: "local-ref", Name: "local-ref", Type: "secret", Source: "local", Masked: "****", Injectable: true}}
	want := `[
  {
    "source": "local",
    "ref": "local-ref",
    "name": "local-ref",
    "description": "",
    "type": "secret",
    "masked": "****",
    "sensitivity": "",
    "injectable": true
  }
]
`
	if got := captureListOutput(t, entries, "json"); got != want {
		t.Fatalf("JSON output:\n%s\nwant:\n%s", got, want)
	}
}
