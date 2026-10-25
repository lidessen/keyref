package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOriginPrecedence(t *testing.T) {
	base := t.TempDir()
	p := Paths{Dir: base, ServerFile: filepath.Join(base, "server.conf")}

	if got := Origin(p); got != DefaultOrigin {
		t.Fatalf("default origin %q, want %q", got, DefaultOrigin)
	}
	if err := SetOrigin(p, "https://keys.example.com"); err != nil {
		t.Fatal(err)
	}
	if got := Origin(p); got != "https://keys.example.com" {
		t.Fatalf("file origin %q", got)
	}
	t.Setenv(EnvServer, "https://override.example")
	if got := Origin(p); got != "https://override.example" {
		t.Fatalf("env override ignored: %q", got)
	}
}

func TestSetOriginRejectsBadOrigins(t *testing.T) {
	base := t.TempDir()
	p := Paths{ServerFile: filepath.Join(base, "server.conf")}
	for _, bad := range []string{"ftp://x", "http://evil.example", "", "https://"} {
		if err := SetOrigin(p, bad); err == nil {
			t.Errorf("accepted origin %q", bad)
		}
	}
	// Loopback http is the development exception (design.md §10.4).
	for _, good := range []string{"http://127.0.0.1:8080", "http://localhost:9000", "https://keys.example.com"} {
		if err := SetOrigin(p, good); err != nil {
			t.Errorf("rejected origin %q: %v", good, err)
		}
	}
}

func TestResolveCreatesDirWith0700(t *testing.T) {
	base := t.TempDir()
	home := filepath.Join(base, "keyref-home")
	t.Setenv(EnvHome, home)
	p, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if p.Dir != home {
		t.Fatalf("dir %q, want %q", p.Dir, home)
	}
	fi, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o, want 0700", fi.Mode().Perm())
	}
}
