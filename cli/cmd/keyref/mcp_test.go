package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lidessen/keyref/cli/internal/cache"
	"github.com/lidessen/keyref/cli/internal/config"
	"github.com/lidessen/keyref/cli/internal/pair"
	"github.com/lidessen/keyref/cli/internal/session"
	"github.com/lidessen/keyref/cli/internal/source"
	"github.com/lidessen/keyref/lib/local"
)

// mcpRoundTrip drives one session with a single JSON request line and
// decodes the single response line. Passing the session matters: state
// such as the pinned source or the opened cache must survive across the
// calls of one session (design §17.5).
func mcpRoundTrip(t *testing.T, srv *mcpServer, line string) (mcpResponse, string) {
	t.Helper()
	var in, out bytes.Buffer
	in.WriteString(line + "\n")
	srv.serve(&in, &out)
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")
	if len(lines) == 0 || lines[0] == "" {
		t.Fatalf("no response for %s", line)
	}
	var resp mcpResponse
	if err := json.Unmarshal([]byte(lines[0]), &resp); err != nil {
		t.Fatalf("decode response %q: %v", lines[0], err)
	}
	if resp.JSONRPC != "2.0" {
		t.Fatalf("response %q missing \"jsonrpc\":\"2.0\" (JSON-RPC 2.0 §6.1)", lines[0])
	}
	return resp, out.String()
}

// mcpText extracts the text payload of a tools/call result.
func mcpText(t *testing.T, resp mcpResponse) string {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("tool failures must be results, not JSON-RPC errors: %+v", resp)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %+v", resp.Result)
	}
	if result["isError"] != true {
		t.Fatalf("expected an error result: %+v", result)
	}
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("empty result content: %+v", result)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	return text
}

// mcpSession builds the session state cmdMCP pins at startup for the
// given source: an empty name means the configured default (§17.3).
func mcpSession(t *testing.T, name string) *mcpServer {
	t.Helper()
	p, err := config.Resolve()
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	spec, err := resolveSource(p, name)
	if err != nil {
		t.Fatalf("resolve source %q: %v", name, err)
	}
	return &mcpServer{p: p, spec: spec}
}

// mcpInitLocal creates the default local vault the way `keyref init`
// does and returns the resolved spec.
func mcpInitLocal(t *testing.T) source.Spec {
	t.Helper()
	if code := cmdInit(nil); code != 0 {
		t.Fatalf("keyref init exit %d", code)
	}
	p, err := config.Resolve()
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	spec, err := resolveSource(p, "")
	if err != nil {
		t.Fatalf("resolve source: %v", err)
	}
	return spec
}

// mcpPut writes one entry into a local vault.
func mcpPut(t *testing.T, spec source.Spec, ref, value string) {
	t.Helper()
	p, err := config.Resolve()
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	vault, err := openLocal(p, spec)
	if err != nil {
		t.Fatalf("open %q: %v", spec.Name, err)
	}
	defer vault.Close()
	if _, err := vault.Put(context.Background(), ref, []byte(value), local.PutOptions{
		Description: "mcp test entry",
	}); err != nil {
		t.Fatalf("put %q: %v", ref, err)
	}
}

func TestMCPInitializeAndToolsList(t *testing.T) {
	mcpTestEnv(t)
	srv := mcpSession(t, source.SyncName)
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
	// design v0.10 §17.8: the MCP version is the same value as
	// `keyref --version`.
	if info["version"] != version {
		t.Fatalf("serverInfo version = %v, want %q", info["version"], version)
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
	mcpTestEnv(t)
	srv := mcpSession(t, source.SyncName)
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
	srv.serve(&in, &out)
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Fatalf("notification produced a response: %d lines: %q", n, out.String())
	}
}

// mcpTestEnv wires a temp KEYREF_HOME with no paired vault so the tool
// layer can run without the e2e harness.
func mcpTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("KEYREF_HOME", dir)
	t.Setenv("KEYREF_KEYRING_DIR", filepath.Join(dir, "keyring"))
	t.Setenv("KEYREF_SERVER", "http://127.0.0.1:1") // nothing listens; tools must not hang
	return dir
}

// mcpPairedEnv creates the cache.sqlite that `keyref pair` would leave
// behind, so tool-call paths past the pairing check can be exercised.
func mcpPairedEnv(t *testing.T) string {
	t.Helper()
	dir := mcpTestEnv(t)
	st, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("close cache: %v", err)
	}
	return dir
}

// TestMCPToolListUnpaired pins issue #7: a tool call on a data
// directory with no paired vault is a result, and it does not create a
// cache.sqlite.
func TestMCPToolListUnpaired(t *testing.T) {
	dir := mcpTestEnv(t)
	srv := mcpSession(t, source.SyncName)
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"list","arguments":{}}}`)
	text := mcpText(t, resp)
	if !strings.Contains(text, "not paired") || !strings.Contains(text, "exit_code: 1") {
		t.Fatalf("unpaired list result: %q", text)
	}
	if _, err := os.Stat(filepath.Join(dir, "cache.sqlite")); !os.IsNotExist(err) {
		t.Fatalf("an MCP tool call created cache.sqlite on a local-only installation")
	}
}

func TestMCPToolGetUnknownRef(t *testing.T) {
	mcpPairedEnv(t)
	srv := mcpSession(t, source.SyncName)
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"get","arguments":{"ref":"nope"}}}`)
	text := mcpText(t, resp)
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
	srv := mcpSession(t, source.SyncName)
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["/bin/true"],"env":{"K":"some-ref"}}}}`)
	text := mcpText(t, resp)
	if !strings.Contains(text, "exit_code: 1") || !strings.Contains(text, "not paired") {
		t.Fatalf("unpaired exec must carry the reason and an exit code: %q", text)
	}
}

func TestMCPToolExecBadArguments(t *testing.T) {
	mcpPairedEnv(t)
	srv := mcpSession(t, source.SyncName)
	// Empty argv.
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"exec","arguments":{"argv":[]}}}`)
	text := mcpText(t, resp)
	if !strings.Contains(text, "exit_code: 2") {
		t.Fatalf("empty argv must map to exit code 2: %q", text)
	}
	// Unknown argument field.
	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":9,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["x"],"bogus":1}}}`)
	text = mcpText(t, resp)
	if !strings.Contains(text, "exit_code: 2") {
		t.Fatalf("unknown field must map to exit code 2: %q", text)
	}
	// Unknown tool.
	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":10,"method":"tools/call","params":{"name":"write","arguments":{}}}`)
	text = mcpText(t, resp)
	if !strings.Contains(text, "exit_code: 2") || !strings.Contains(text, "unknown tool") {
		t.Fatalf("unknown tool must be an error result: %q", text)
	}
}

// TestMCPExecValidationErrorReachesTheResult pins issue #3: a message
// produced by the shared exec core while serving a tool call is part of
// the tool result, not the process stderr the MCP client never sees.
func TestMCPExecValidationErrorReachesTheResult(t *testing.T) {
	dir := mcpTestEnv(t)
	st, err := cache.Open(dir)
	if err != nil {
		t.Fatalf("open cache: %v", err)
	}
	// Enough pairing state for the exec core to reach its argument
	// validation: a vault id and a pinned owner key.
	if err := st.SetKV(session.KVVaultID, []byte("vault-test")); err != nil {
		t.Fatal(err)
	}
	if err := st.SetKV(pair.KVOwnerSignPub, []byte("owner-test")); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	srv := mcpSession(t, source.SyncName)
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["/usr/bin/true"],"env":{"":"some-ref"}}}}`)
	text := mcpText(t, resp)
	if !strings.Contains(text, "--env expects NAME=REF") {
		t.Fatalf("the reason is missing from the tool result: %q", text)
	}
	if !strings.Contains(text, "exit_code: 10") {
		t.Fatalf("the policy exit code is missing from the tool result: %q", text)
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

// localSecret is the plaintext every local MCP test must never see in a
// result. It is deliberately a made-up value, not a credential.
const localSecret = "sk-local-TESTONLY-0123456789abcdef"

// mcpResultText extracts the text payload of a successful tools/call
// result.
func mcpResultText(t *testing.T, resp mcpResponse) string {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("tool failures must be results, not JSON-RPC errors: %+v", resp)
	}
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is not an object: %+v", resp.Result)
	}
	if result["isError"] == true {
		t.Fatalf("unexpected error result: %+v", result)
	}
	content, _ := result["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("empty result content: %+v", result)
	}
	text, _ := content[0].(map[string]any)["text"].(string)
	return text
}

// mcpList runs the list tool on a session and returns its text.
func mcpList(t *testing.T, srv *mcpServer, id int) string {
	t.Helper()
	line := fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":"list","arguments":{}}}`, id)
	resp, _ := mcpRoundTrip(t, srv, line)
	return mcpResultText(t, resp)
}

// TestMCPToolsOnLocalSource pins design §17.5: the three tools serve a
// local source with the same shapes as the paired one, list and get read
// only the encrypted meta, exec goes through the same core, and no
// cache.sqlite ever appears.
func TestMCPToolsOnLocalSource(t *testing.T) {
	dir := mcpTestEnv(t)
	spec := mcpInitLocal(t)
	if spec.Kind != source.KindLocal {
		t.Fatalf("fresh install default = %s, want local", spec.Kind)
	}
	mcpPut(t, spec, "tok", localSecret)

	srv := mcpSession(t, "")
	if srv.spec.Kind != source.KindLocal {
		t.Fatalf("session source = %s, want local", srv.spec.Kind)
	}

	// list: meta only, never the value.
	text := mcpList(t, srv, 20)
	if !strings.Contains(text, `"ref": "tok"`) {
		t.Fatalf("local list missing the entry: %q", text)
	}
	if !strings.Contains(text, `"type": "local"`) {
		t.Fatalf("local list must share the synced entry shape: %q", text)
	}
	if strings.Contains(text, localSecret) {
		t.Fatalf("local list leaked the value: %q", text)
	}

	// get: masked meta, never the value.
	resp, _ := mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":21,"method":"tools/call","params":{"name":"get","arguments":{"ref":"tok"}}}`)
	text = mcpResultText(t, resp)
	if !strings.Contains(text, `"masked":`) || !strings.Contains(text, `"description": "mcp test entry"`) {
		t.Fatalf("local get result: %q", text)
	}
	if strings.Contains(text, localSecret) {
		t.Fatalf("local get leaked the value: %q", text)
	}

	// Unknown ref: exit 11, no enumeration (design §12.2).
	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":22,"method":"tools/call","params":{"name":"get","arguments":{"ref":"nope"}}}`)
	text = mcpText(t, resp)
	if !strings.Contains(text, "exit_code: 11") {
		t.Fatalf("unknown local ref must map to exit code 11: %q", text)
	}

	// exec: the same core as the CLI, with the value injected into the
	// child and never into the result.
	resp, _ = mcpRoundTrip(t, srv, `{"jsonrpc":"2.0","id":23,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["/usr/bin/true"],"env":{"K":"tok"}}}}`)
	text = mcpResultText(t, resp)
	if !strings.Contains(text, "exit_code: 0") {
		t.Fatalf("local exec result: %q", text)
	}
	if strings.Contains(text, localSecret) {
		t.Fatalf("local exec leaked the value: %q", text)
	}

	// A local-only installation never grows a cache.sqlite (issue #7).
	if _, err := os.Stat(filepath.Join(dir, "cache.sqlite")); !os.IsNotExist(err) {
		t.Fatalf("the local MCP tools created cache.sqlite")
	}
}

// TestMCPSourcePinnedForTheSession pins §17.5: the source — including
// its path — is selected once at startup, so changing the default or
// removing the registration mid-session cannot move a running session to
// another vault.
func TestMCPSourcePinnedForTheSession(t *testing.T) {
	dir := mcpTestEnv(t)
	localSpec := mcpInitLocal(t)
	mcpPut(t, localSpec, "tok", localSecret)

	p, err := config.Resolve()
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	altPath := filepath.Join(dir, "alt.db")
	altSpec, err := source.Add(p, "alt", altPath)
	if err != nil {
		t.Fatalf("add source: %v", err)
	}
	if code := cmdInit([]string{"--vault", "alt"}); code != 0 {
		t.Fatalf("init alt exit %d", code)
	}
	mcpPut(t, altSpec, "altref", localSecret)
	if err := source.SetDefault(p, "alt"); err != nil {
		t.Fatalf("set default: %v", err)
	}

	// The session starts on the configured default: alt.
	srv := mcpSession(t, "")
	if srv.spec.Name != "alt" || srv.spec.Path != altPath {
		t.Fatalf("session source = %+v, want alt at %s", srv.spec, altPath)
	}
	text := mcpList(t, srv, 30)
	if !strings.Contains(text, `"ref": "altref"`) {
		t.Fatalf("session must serve alt: %q", text)
	}

	// Mid-session: point the default somewhere else and drop the
	// registration entirely. The running session keeps serving alt.
	if err := source.SetDefault(p, source.LocalName); err != nil {
		t.Fatalf("set default: %v", err)
	}
	if err := source.Remove(p, "alt"); err != nil {
		t.Fatalf("remove source: %v", err)
	}
	text = mcpList(t, srv, 31)
	if !strings.Contains(text, `"ref": "altref"`) {
		t.Fatalf("the session moved away from its pinned vault: %q", text)
	}
	if strings.Contains(text, `"ref": "tok"`) {
		t.Fatalf("the session switched to the new default: %q", text)
	}

	// A new session follows the new default.
	next := mcpSession(t, "")
	if next.spec.Name != source.LocalName {
		t.Fatalf("new session source = %s, want local", next.spec.Name)
	}
	text = mcpList(t, next, 32)
	if !strings.Contains(text, `"ref": "tok"`) {
		t.Fatalf("new session must serve the new default: %q", text)
	}
	if strings.Contains(text, `"ref": "altref"`) {
		t.Fatalf("new session still serves the removed source: %q", text)
	}
}

// TestMCPLocalSourceHonoursLock pins §17.8 for the MCP layer: `keyref
// lock` closes every local unwrap path, reported as exit 12 in the tool
// result — never as a message on the process stderr.
func TestMCPLocalSourceHonoursLock(t *testing.T) {
	mcpTestEnv(t)
	spec := mcpInitLocal(t)
	mcpPut(t, spec, "tok", localSecret)
	p, err := config.Resolve()
	if err != nil {
		t.Fatalf("resolve config: %v", err)
	}
	if err := os.WriteFile(p.LockFile, []byte("1\n"), 0o600); err != nil {
		t.Fatalf("lock: %v", err)
	}
	srv := mcpSession(t, "")
	for _, line := range []string{
		`{"jsonrpc":"2.0","id":40,"method":"tools/call","params":{"name":"list","arguments":{}}}`,
		`{"jsonrpc":"2.0","id":41,"method":"tools/call","params":{"name":"get","arguments":{"ref":"tok"}}}`,
		`{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"exec","arguments":{"argv":["/usr/bin/true"],"env":{"K":"tok"}}}}`,
	} {
		resp, _ := mcpRoundTrip(t, srv, line)
		text := mcpText(t, resp)
		if !strings.Contains(text, "exit_code: 12") {
			t.Fatalf("a locked session must report exit code 12: %q", text)
		}
	}
}
