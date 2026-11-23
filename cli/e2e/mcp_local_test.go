//go:build e2e

package e2e

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The MCP server on a local source (design §17.5): one command surface,
// one tool surface. The session picks its source once at startup and
// keeps serving that vault, with every tool message inside the tool
// result and nothing on the process stderr the MCP client cannot read.

// localMCP drives a real `keyref mcp` process over stdio.
type localMCP struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	reader *bufio.Reader
	errBuf bytes.Buffer
}

func startLocalMCP(t *testing.T, env []string, args ...string) *localMCP {
	t.Helper()
	m := &localMCP{}
	cmd := exec.Command(cliBin, append([]string{"mcp"}, args...)...)
	cmd.Env = env
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stderr = &m.errBuf
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	m.cmd = cmd
	m.stdin = stdin
	m.reader = bufio.NewReader(stdout)
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	return m
}

// send writes one JSON-RPC request and reads the single response line.
func (m *localMCP) send(t *testing.T, req map[string]any) map[string]any {
	t.Helper()
	b, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	if _, err := m.stdin.Write(append(b, '\n')); err != nil {
		t.Fatalf("mcp write: %v (stderr: %s)", err, m.errBuf.String())
	}
	line, err := m.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("mcp read: %v (stderr: %s)", err, m.errBuf.String())
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		t.Fatalf("mcp response: %v (%q)", err, line)
	}
	if resp["jsonrpc"] != "2.0" {
		t.Fatalf("response missing \"jsonrpc\":\"2.0\": %q", line)
	}
	return resp
}

func (m *localMCP) call(t *testing.T, method string, params map[string]any) map[string]any {
	t.Helper()
	return m.send(t, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
}

func (m *localMCP) tool(t *testing.T, name string, args map[string]any) map[string]any {
	t.Helper()
	if args == nil {
		args = map[string]any{}
	}
	return m.call(t, "tools/call", map[string]any{"name": name, "arguments": args})
}

// TestMCPservesTheLocalSource drives the MCP server against the default
// local vault: list, get and exec over stdio, the value never in a
// result, the child's output redacted, the source pinned for the whole
// session and no cache.sqlite anywhere.
func TestMCPservesTheLocalSource(t *testing.T) {
	home, _, env := localHome(t)
	if run := localRun(t, env, "", "init"); run.code != 0 {
		t.Fatalf("init exit %d: %s", run.code, run.stderr)
	}
	if run := localRun(t, env, localSecret, "set", "tok"); run.code != 0 {
		t.Fatalf("set exit %d: %s", run.code, run.stderr)
	}

	// No --vault: a fresh installation serves its default, which is
	// the local vault (design §17.3).
	m := startLocalMCP(t, env)
	if init := m.call(t, "initialize", map[string]any{"protocolVersion": "2024-11-05"}); init["result"] == nil {
		t.Fatalf("mcp initialize: %+v", init)
	}
	if tools := m.call(t, "tools/list", nil); tools["result"] == nil {
		t.Fatalf("mcp tools/list: %+v", tools)
	}

	// list: meta only.
	text := mcpText(t, m.tool(t, "list", nil))
	if !strings.Contains(text, `"ref": "tok"`) || !strings.Contains(text, `"type": "local"`) {
		t.Fatalf("mcp local list: %q", text)
	}
	if strings.Contains(text, `"value"`) {
		t.Fatalf("mcp local list carries a value field: %q", text)
	}
	assertNoLocalLeak(t, "mcp local list", text)

	// get: the sealed mask, never the secret.
	text = mcpText(t, m.tool(t, "get", map[string]any{"ref": "tok"}))
	if !strings.Contains(text, `"masked":`) {
		t.Fatalf("mcp local get: %q", text)
	}
	assertNoLocalLeak(t, "mcp local get", text)

	// Unknown ref: exit 11 inside the result, no enumeration.
	text = mcpText(t, m.tool(t, "get", map[string]any{"ref": "nope"}))
	if !strings.Contains(text, "exit_code: 11") {
		t.Fatalf("mcp local get on an unknown ref: %q", text)
	}

	// exec: the same engine as the CLI — the child sees the value, the
	// result sees only the redaction marker.
	text = mcpText(t, m.tool(t, "exec", map[string]any{
		"argv": []any{helperBin, "print-env"},
		"env":  map[string]any{"K": "tok"},
	}))
	if !strings.Contains(text, "K=<redacted:tok>") || !strings.Contains(text, "exit_code: 0") {
		t.Fatalf("mcp local exec: %q", text)
	}
	assertNoLocalLeak(t, "mcp local exec", text)

	// The session is pinned: moving the configured default elsewhere
	// while it runs cannot move it to another vault (§17.5).
	alt := filepath.Join(home, "alt.db")
	if run := localRun(t, env, "", "source", "add", "alt", "--path", alt); run.code != 0 {
		t.Fatalf("source add exit %d: %s", run.code, run.stderr)
	}
	if run := localRun(t, env, "", "source", "default", "alt"); run.code != 0 {
		t.Fatalf("source default exit %d: %s", run.code, run.stderr)
	}
	text = mcpText(t, m.tool(t, "list", nil))
	if !strings.Contains(text, `"ref": "tok"`) {
		t.Fatalf("the running session left its pinned vault: %q", text)
	}
	// CLI listing includes every initialized vault. Get still follows
	// the configured default, which has no vault yet.
	if run := localRun(t, env, "", "list"); run.code != 0 || !strings.Contains(run.stdout, "tok") {
		t.Fatalf("CLI list lost an initialized vault: exit %d %q", run.code, run.stderr)
	}
	if run := localRun(t, env, "", "get", "tok"); run.code == 0 || !strings.Contains(run.stderr, "has no vault yet") {
		t.Fatalf("CLI get must follow the new default: exit %d %q", run.code, run.stderr)
	}

	// --vault selects explicitly, whatever the default says.
	explicit := startLocalMCP(t, env, "--vault", "local")
	if init := explicit.call(t, "initialize", map[string]any{"protocolVersion": "2024-11-05"}); init["result"] == nil {
		t.Fatalf("mcp --vault initialize: %+v", init)
	}
	text = mcpText(t, explicit.tool(t, "list", nil))
	if !strings.Contains(text, `"ref": "tok"`) {
		t.Fatalf("mcp --vault local: %q", text)
	}

	// Nothing reached the process stderr: an MCP client only ever sees
	// the tool results (design §17.5).
	if out := m.errBuf.String(); strings.Contains(out, "keyref:") {
		t.Fatalf("the MCP server wrote to its process stderr: %q", out)
	}

	// A local-only installation never grows a cache.sqlite (issue #7).
	if _, err := os.Stat(filepath.Join(home, "cache.sqlite")); !os.IsNotExist(err) {
		t.Fatalf("the local MCP server created cache.sqlite")
	}
}
