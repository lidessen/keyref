package exec

import (
	"bytes"
	"os"
	"testing"
)

func TestValidateEnvName(t *testing.T) {
	for _, good := range []string{"PATH", "OPENAI_API_KEY", "_x", "a1", "HTTPS_PROXY", "SSH_AUTH_SOCK"} {
		if err := ValidateEnvName(good); err != nil {
			t.Errorf("rejected valid name %q: %v", good, err)
		}
	}
	bad := []string{
		"", "1x", "a-b", "a b",
		"LD_PRELOAD", "LD_", "DYLD_INSERT_LIBRARIES", "DYLD_X",
		// Shell startup and trace hooks.
		"BASH_ENV", "ENV", "ZDOTDIR", "SHELLOPTS", "BASHOPTS", "PS4", "PROMPT_COMMAND",
		// Interpreter and class-loader injection.
		"NODE_OPTIONS", "NODE_PATH", "PERL5OPT", "PERL5LIB", "PERLLIB", "PERL5DB", "PERL5SHELL",
		"PYTHONSTARTUP", "PYTHONHOME", "PYTHONPATH", "RUBYOPT", "RUBYLIB",
		"JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH",
		// Helper executables chosen by the environment.
		"SSH_ASKPASS", "GIT_SSH_COMMAND", "GIT_SSH", "GIT_EXTERNAL_DIFF", "GIT_ASKPASS",
		"GIT_PAGER", "GIT_EXEC_PATH", "PAGER", "LESSOPEN", "LESSCLOSE", "MANPAGER", "MANOPT",
	}
	for _, name := range bad {
		if err := ValidateEnvName(name); err == nil {
			t.Errorf("accepted invalid name %q", name)
		} else if !isPolicyErr(err) {
			t.Errorf("name %q error is not a policy error: %T", name, err)
		}
	}
}

func TestSanitizeParentEnv(t *testing.T) {
	parent := []string{
		"PATH=/usr/bin", "HOME=/home/u", "USER=u", "LOGNAME=u",
		"LANG=C", "LC_ALL=C", "TERM=xterm", "TMPDIR=/tmp",
		"SECRET_LEAK=zzz", "LD_PRELOAD=/evil.so", "DYLD_INSERT_LIBRARIES=/evil",
		"HTTPS_PROXY=http://127.0.0.1:3128",
	}
	env, err := SanitizeParentEnv(parent, []string{"HTTPS_PROXY"})
	if err != nil {
		t.Fatal(err)
	}
	joined := "\x00" + joinNul(env) + "\x00"
	for _, must := range []string{"PATH=/usr/bin", "HOME=/home/u", "HTTPS_PROXY=http://127.0.0.1:3128"} {
		if !bytes.Contains([]byte(joined), []byte("\x00"+must+"\x00")) {
			t.Errorf("missing %s", must)
		}
	}
	for _, banned := range []string{"SECRET_LEAK", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"} {
		if bytes.Contains([]byte(joined), []byte(banned)) {
			t.Errorf("%s survived sanitization", banned)
		}
	}
	// Missing --pass variable is a rejection.
	if _, err := SanitizeParentEnv(parent, []string{"NOT_THERE"}); !isPolicyErr(err) {
		t.Fatalf("missing --pass accepted: %v", err)
	}
	// A forbidden name cannot be re-admitted through --pass either.
	parent = append(parent, "GIT_SSH_COMMAND=sh -c evil", "PAGER=sh")
	for _, name := range []string{"GIT_SSH_COMMAND", "PAGER"} {
		if _, err := SanitizeParentEnv(parent, []string{name}); !isPolicyErr(err) {
			t.Fatalf("forbidden --pass name %q accepted: %v", name, err)
		}
	}
}

func joinNul(env []string) string {
	out := ""
	for i, e := range env {
		if i > 0 {
			out += "\x00"
		}
		out += e
	}
	return out
}

func TestRenderTemplateSingleToken(t *testing.T) {
	out, err := RenderTemplate(`header "Authorization: Bearer {{keyref}}"`, []byte("sk-abc"))
	if err != nil {
		t.Fatal(err)
	}
	defer out.Destroy()
	if !bytes.Equal(out.Bytes(), []byte(`header "Authorization: Bearer sk-abc"`)) {
		t.Fatalf("rendered %q", out.Bytes())
	}
	for _, bad := range []string{"no token", "{{keyref}} and {{keyref}}", "{{keyref}} {{other}}"} {
		if _, err := RenderTemplate(bad, []byte("x")); err == nil {
			t.Errorf("template %q accepted", bad)
		}
	}
}

func TestValidateHeaderValue(t *testing.T) {
	good := []byte(`Authorization: Bearer sk-abc \t ok`)
	if err := ValidateHeaderValue(good); err != nil {
		t.Fatalf("valid header value rejected: %v", err)
	}
	for _, bad := range [][]byte{
		[]byte("a\r\nb"), []byte("a\nb"), []byte("a\x00b"), []byte("aéb"), []byte("\x7f"),
	} {
		if err := ValidateHeaderValue(bad); err == nil {
			t.Errorf("invalid header value accepted: %q", bad)
		} else if _, ok := err.(*InjectionError); !ok {
			t.Errorf("wrong error type for %q: %T", bad, err)
		}
	}
}

func TestArgvPlaceholders(t *testing.T) {
	argv := []string{"tool", "--token", "{{keyref:openai-prod}}", "{{keyref:wifi-home}}", "literal", "https://api.example.com/x", "keyref://pair?u=x"}
	if !HasArgvPlaceholder(argv) {
		t.Fatal("placeholder not detected")
	}
	if HasArgvPlaceholder([]string{"tool", "{{keyref:"}) {
		t.Fatal("malformed placeholder detected")
	}
	// The keyref:// URI form was removed (design v0.6): a bare keyref://…
	// string must no longer be treated as a placeholder.
	if HasArgvPlaceholder([]string{"tool", "keyref://openai-prod"}) {
		t.Fatal("URI placeholder form must not match")
	}
	refs := ArgvPlaceholderRefs(argv)
	if len(refs) != 2 || refs[0] != "openai-prod" || refs[1] != "wifi-home" {
		t.Fatalf("refs = %v, want [openai-prod wifi-home]", refs)
	}
	out, err := ReplaceArgvPlaceholders(argv, func(ref string) ([]byte, error) {
		if ref == "openai-prod" {
			return []byte("SK1"), nil
		}
		if ref == "wifi-home" {
			return []byte("SK2"), nil
		}
		return nil, os.ErrNotExist
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tool", "--token", "SK1", "SK2", "literal", "https://api.example.com/x", "keyref://pair?u=x"}
	for i := range want {
		if out[i] != want[i] {
			t.Fatalf("argv[%d]=%q want %q", i, out[i], want[i])
		}
	}
}
