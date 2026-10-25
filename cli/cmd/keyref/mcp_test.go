package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// mcpRoundTrip drives serveMCP with one JSON request line and decodes
// the single response line.
func mcpRoundTrip(t *testing.T, srv *mcpServer, line string) (mcpResponse, string) {
	t.Helper()
	var in, out bytes.Buffer
	in.WriteString(line + "\n")
	serveMCP(&in, &out)
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("no response for %s", line)
	}
	var resp mcpResponse
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("decode response %q: %v", lines[0], err)
	}
	return resp, out.String()
}

func TestMCPInitializeAndToolsList(t *testing.T) {
	srv := &mcpServer{}
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`)
	if resp.Error != nil || resp.Result == nil {
		t.Fatalf("initialize: %+v", resp)
	}
	result, _ := resp.Result.(map[string]any)
	if result["protocolVersion"] != "2024-11-05" {
		t.Fatalf("protocolVersion: %+v", result)
	}
	info, _ := result["serverInfo"].(map[string]any)
	if info["name"] != "keyref" {
		t.Fatalf("serverInfo: %+v", info)
	}

	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	result, _ = resp.Result.(map[string]any)
	tools, _ := result["tools"].([]any)
	if len(tools) != 3 {
		t.Fatalf("tools = %d, want list/get/exec only", len(tools))
	}
	names := map[string]bool{}
	for _, tl := range tools {
		m := tl.(map[string]any)
		names[m["name"].(string)] = true
		desc, _ := m["description"].(string)
		// Every tool description tells the caller to pass refs, never
		// secrets (design §7.8).
		if !strings.Contains(desc, "ref") || !strings.Contains(strings.ToUpper(desc), "NEVER") {
			t.Fatalf("tool %q description missing the ref-not-secret warning: %q", m["name"], desc)
		}
	}
	for _, want := range []string{"list", "get", "exec"} {
		if !names[want] {
			t.Fatalf("tool %q missing", want)
		}
	}
}

func TestMCPProtocolErrors(t *testing.T) {
	srv := &mcpServer{}
	// Parse error.
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0",`)
	if resp.Error == nil || resp.Error.Code != errParse {
		t.Fatalf("parse error: %+v", resp)
	}
	// Unknown method.
	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":3,"method":"resources/list"}`)
	if resp.Error == nil || resp.Error.Code != errNotFound {
		t.Fatalf("unknown method: %+v", resp)
	}
	// Non-2.0 envelope.
	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"1.0","id":4,"method":"tools/list"}`)
	if resp.Error == nil || resp.Error.Code != errInvalidReq {
		t.Fatalf("bad envelope: %+v", resp)
	}
	// Notifications produce no response at all.
	var in, out bytes.Buffer
	in.WriteString("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n")
	in.WriteString("{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"ping\"}\n")
	serveMCP(&in, &out)
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Fatalf("notification produced a response: %d lines: %q", n, out.String())
	}
}

// mcpTestEnv wires a temp KEYREF_HOME (unpaired store) so the tool
// layer can run without the e2e harness.
func mcpTestEnv(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYREF_HOME", dir)
	t.Setenv("KEYREF_KEYRING_DIR", filepath.Join(dir, "keyring"))
	t.Setenv("KEYREF_SERVER", "http://127.0.0.1:1") // nothing listens; tools must not hang
}

func TestMCPToolListUnpaired(t *testing.T) {
	mcpTestEnv(t)
	srv := &mcpServer{}
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list","arguments":{}}}`)
	if resp.Error != nil {
		t.Fatalf("tools/call must map failures to results, not JSON-RPC errors: %+v", resp)
	}
	result := resp.Result.(map[string]any)
	if result["isError"] == true {
		// An empty-but-unpaired vault still lists (no items visible).
		t.Fatalf("list on an unpaired store should succeed with an empty set: %+v", result)
	}
	content, _ := result["content"].([]any)
	text, _ := content[0].(map[string]any)["text"].(string)
	var entries []map[string]any
	if err := json.Unmarshal([]byte(text), &entries); err != nil || entries == nil {
		t.Fatalf("list result is not a JSON array: %q", text)
	}
	if len(entries) != 0 {
		t.Fatalf("expected an empty list: %q", text)
	}
}

func TestMCPToolGetUnknownRef(t *testing.T) {
	mcpTestEnv(t)
	srv := &mcpServer{}
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get","arguments":{"ref":"nope"}}}`)
	result := resp.Result.(map[string]any)
	if result["isError"] != true {
		t.Fatalf("unknown ref must be an error result: %+v", result)
	}
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "exit_code: 11") {
		t.Fatalf("unknown ref must map to exit code 11: %q", text)
	}
	// The error must not enumerate other refs (design §12.2).
	if strings.Count(text, "ref") > 3 {
		t.Fatalf("error text enumerates refs: %q", text)
	}
}

func TestMCPToolExecUnpairedMapsExitCode(t *testing.T) {
	mcpTestEnv(t)
	srv := &mcpServer{}
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["/bin/true"],"env":{"K":"some-ref"}}}}`)
	result := resp.Result.(map[string]any)
	if result["isError"] != true {
		t.Fatalf("unpaired exec must be an error result: %+v", result)
	}
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "exit_code: 1") {
		t.Fatalf("exec failure must carry an exit code: %q", text)
	}
}

func TestMCPToolExecBadArguments(t *testing.T) {
	mcpTestEnv(t)
	srv := &mcpServer{}
	// Empty argv.
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"exec","arguments":{"argv":[]}}}`)
	text := resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "exit_code: 2") {
		t.Fatalf("empty argv must map to exit code 2: %q", text)
	}
	// Unknown argument field.
	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["x"],"bogus":1}}}`)
	text = resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "exit_code: 2") {
		t.Fatalf("unknown field must map to exit code 2: %q", text)
	}
	// Unknown tool.
	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"write","arguments":{}}}`)
	text = resp.Result.(map[string]any)["content"].([]any)[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, "exit_code: 2") || !strings.Contains(text, "unknown tool") {
		t.Fatalf("unknown tool must be an error result: %q", text)
	}
}

// TestMCPExecTimeoutClamped pins the 120 s server window clamp on the
// exec tool's timeout argument.
func TestMCPExecTimeoutClamped(t *testing.T) {
	if d := approvalTimeoutFromSeconds(500); d != 120*1e9 {
		t.Fatalf("timeout clamp: %s", d)
	}
	if d := approvalTimeoutFromSeconds(0); d != 2*60*1e9 {
		t.Fatalf("timeout default: %s", d)
	}
	if d := approvalTimeoutFromSeconds(5); d != 5*1e9 {
		t.Fatalf("timeout passthrough: %s", d)
	}
}
