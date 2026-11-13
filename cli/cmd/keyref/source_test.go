package main

import (
	"testing"

	"github.com/lidessen/keyref/cli/internal/exec"
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
	if !exec.ItemAllowsCommand("curl", meta.Policy.AllowCommands) {
		t.Fatal("an ordinary command should be allowed under deny-shells")
	}
	if exec.ItemAllowsCommand("sh", meta.Policy.AllowCommands) {
		t.Fatal("sh must stay denied for local entries")
	}
}
