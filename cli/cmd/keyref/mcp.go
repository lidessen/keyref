package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/lidessen/keyref/cli/internal/approval"
	"github.com/lidessen/keyref/cli/internal/cache"
	"github.com/lidessen/keyref/cli/internal/device"
	"github.com/lidessen/keyref/cli/internal/exec"
	"github.com/lidessen/keyref/cli/internal/meta"
	"github.com/lidessen/keyref/cli/internal/source"
)

// `keyref mcp` serves the vault over stdio as an MCP-compatible JSON-RPC
// 2.0 server (design.md §7.8, §13 Phase 2). The tool surface is exactly
// list / get / exec and the exec tool is semantically identical to
// `keyref exec`: the same runExecCore performs the policy checks, the
// spawn, the injection and the redaction. Tool arguments carry refs —
// never secret values — and every result returns redacted output plus an
// exit code; tool-level failures are results with isError, never panics.

// mcpProtocolVersion is the MCP protocol version this server speaks.
const mcpProtocolVersion = "2024-11-05"

// mcpRequest is one newline-delimited JSON-RPC message from the client.
type mcpRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// mcpResponse is one message back to the client. Exactly one of result
// and error is set. JSONRPC is filled by reply() — every response MUST
// carry "jsonrpc":"2.0" (JSON-RPC 2.0 §6.1; strict MCP clients reject
// messages without it).
type mcpResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *mcpError       `json:"error,omitempty"`
}

// reply builds a successful response for the given request id.
func reply(id json.RawMessage, result any) *mcpResponse {
	return &mcpResponse{JSONRPC: "2.0", ID: id, Result: result}
}

// replyError builds an error response for the given request id.
func replyError(id json.RawMessage, rpcErr *mcpError) *mcpResponse {
	return &mcpResponse{JSONRPC: "2.0", ID: id, Error: rpcErr}
}

// mcpError is a JSON-RPC error object.
type mcpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// JSON-RPC error codes used here.
const (
	errParse      = -32700
	errInvalidReq = -32600
	errNotFound   = -32601
)

type mcpTool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

const refNotSecret = "Pass keyref refs (e.g. \"openai-prod\"); NEVER pass secret values, keys or tokens — keyref resolves refs against the vault itself."

func mcpTools() []mcpTool {
	return []mcpTool{
		{
			Name: "list",
			Description: "List the vault items this device is authorized to see: ref, name, description, type, masked value, sensitivity. " +
				refNotSecret + " Use a returned ref with get or exec.",
			InputSchema: json.RawMessage(`{"type":"object","properties":{},"additionalProperties":false}`),
		},
		{
			Name: "get",
			Description: "Show one item's metadata by ref: name, description, type, masked value, sensitivity. Never returns the secret value. " +
				refNotSecret,
			InputSchema: json.RawMessage(`{"type":"object","properties":{"ref":{"type":"string","description":"the item ref, e.g. openai-prod"}},"required":["ref"],"additionalProperties":false}`),
		},
		{
			Name: "exec",
			Description: "Run a command with secrets injected. Equivalent to `keyref exec`: put {{keyref:REF}} placeholders where secrets belong in argv " +
				"(requires allow_argv and the item policy), bind environment variables to refs with env (NAME → REF), or pass one ref via stdin_ref. " +
				"Child stdout/stderr are returned REDACTED together with the exit code. " +
				refNotSecret,
			InputSchema: json.RawMessage(`{"type":"object","properties":{` +
				`"argv":{"type":"array","items":{"type":"string"},"description":"command and arguments; may contain {{keyref:REF}} placeholders"},` +
				`"env":{"type":"object","additionalProperties":{"type":"string"},"description":"environment variable name → item ref"},` +
				`"stdin_ref":{"type":"string","description":"item ref written to the child's stdin"},` +
				`"allow_argv":{"type":"boolean","description":"allow {{keyref:REF}} placeholders in argv (also needs the item's allowArgv policy)"},` +
				`"timeout":{"type":"number","description":"approval wait timeout in seconds (approval items, default 120)"}` +
				`},"required":["argv"],"additionalProperties":false}`),
		},
	}
}

// mcpServer holds the lazily initialized store and identity shared by
// every tool call of one MCP session.
type mcpServer struct {
	st   *cache.Store
	id   *device.Identity
	init bool
}

// serveMCP reads newline-delimited JSON-RPC from in and writes responses
// to out. It returns when the input ends. Every tool call is recovered:
// a panic becomes an error result, never a crash.
func serveMCP(in io.Reader, out io.Writer) {
	srv := &mcpServer{}
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	w := bufio.NewWriter(out)
	defer w.Flush()
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		resp := srv.handle(line)
		if resp == nil {
			continue // notification: no response
		}
		b, err := json.Marshal(resp)
		if err != nil {
			b = []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"internal encode failure"}}`)
		}
		w.Write(b)
		w.WriteByte('\n')
		w.Flush()
	}
}

// handle decodes and dispatches one request line.
func (s *mcpServer) handle(line []byte) *mcpResponse {
	var req mcpRequest
	if err := json.Unmarshal(line, &req); err != nil {
		return replyError(json.RawMessage("null"), &mcpError{Code: errParse, Message: "parse error"})
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		return replyError(req.ID, &mcpError{Code: errInvalidReq, Message: "invalid request"})
	}
	if len(req.ID) == 0 {
		// Notification (e.g. notifications/initialized): acknowledge by
		// silence.
		return nil
	}
	result, rpcErr := s.dispatch(req.Method, req.Params)
	if rpcErr != nil {
		return replyError(req.ID, rpcErr)
	}
	return reply(req.ID, result)
}

// dispatch routes one method. Tool-level failures never reach here as
// errors: they become results with isError and an exit code.
func (s *mcpServer) dispatch(method string, params json.RawMessage) (any, *mcpError) {
	switch method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		_ = json.Unmarshal(params, &p)
		protoVersion := p.ProtocolVersion
		if protoVersion == "" {
			protoVersion = mcpProtocolVersion
		}
		return map[string]any{
			"protocolVersion": protoVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": "keyref", "version": version},
			"instructions":    refNotSecret,
		}, nil
	case "notifications/initialized", "initialized":
		return nil, &mcpError{Code: errInvalidReq, Message: "notifications must not carry an id"}
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": mcpTools()}, nil
	case "tools/call":
		return s.toolsCall(params)
	default:
		return nil, &mcpError{Code: errNotFound, Message: "method not found: " + method}
	}
}

// mcpCallResult is the tools/call result shape.
type mcpCallResult struct {
	Content []mcpContent `json:"content"`
	IsError bool         `json:"isError,omitempty"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// textResult wraps one text payload as a successful result.
func textResult(text string, isError bool) mcpCallResult {
	return mcpCallResult{
		Content: []mcpContent{{Type: "text", Text: text}},
		IsError: isError,
	}
}

// mcpExecArgs is the exec tool's argument object, mirroring the CLI
// flags of `keyref exec` (design.md §7.8 semantic isomorphism).
type mcpExecArgs struct {
	Argv      []string          `json:"argv"`
	Env       map[string]string `json:"env"`
	StdinRef  string            `json:"stdin_ref"`
	AllowArgv bool              `json:"allow_argv"`
	Timeout   float64           `json:"timeout"`
}

// toolsCall executes one tools/call. Every failure path returns a
// result carrying the mapped CLI exit code; a panic in the shared core
// is recovered into the same shape.
func (s *mcpServer) toolsCall(params json.RawMessage) (result any, rpcErr *mcpError) {
	defer func() {
		if rec := recover(); rec != nil {
			result = textResult(fmt.Sprintf("keyref: internal error: %v\nexit_code: 1", rec), true)
			rpcErr = nil
		}
	}()
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	dec := json.NewDecoder(bytes.NewReader(params))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return textResult("keyref: invalid tools/call arguments: "+err.Error()+"\nexit_code: 2", true), nil
	}
	switch p.Name {
	case "list":
		return s.toolList()
	case "get":
		return s.toolGet(p.Arguments)
	case "exec":
		return s.toolExec(p.Arguments)
	default:
		return textResult(fmt.Sprintf("keyref: unknown tool %q (available: list, get, exec)", p.Name)+"\nexit_code: 2", true), nil
	}
}

// errMCPNotPaired is what a tool call reports for a data directory with
// no paired vault. MCP serves the paired vault only (§17.5's local mode
// is not implemented), and it must not grow a cache.sqlite for a
// local-only installation (issue #7).
var errMCPNotPaired = errors.New("not paired; run keyref pair first")

// ensureInit lazily opens the store and loads the device identity once
// per MCP session. It never creates the cache file: a tool call on an
// unpaired installation is a result, not a new file on disk.
func (s *mcpServer) ensureInit() error {
	if s.init {
		return nil
	}
	p := mustPaths()
	if _, err := os.Stat(p.CacheFile); errors.Is(err, os.ErrNotExist) {
		return errMCPNotPaired
	} else if err != nil {
		return err
	}
	st := mustStore()
	id := mustIdentity()
	s.st = st
	s.id = id
	s.init = true
	return nil
}

// toolList mirrors `keyref list --format json` (same meta layer, no
// secret decryption).
func (s *mcpServer) toolList() (any, *mcpError) {
	if err := s.ensureInit(); err != nil {
		return textResult("keyref: "+err.Error()+"\nexit_code: 1", true), nil
	}
	if locked(mustPaths()) {
		return textResult("keyref: session is locked; run keyref unlock\nexit_code: 12", true), nil
	}
	entries, err := meta.Items(s.st, s.id)
	if err != nil {
		return textResult("keyref: "+err.Error()+"\nexit_code: 1", true), nil
	}
	if entries == nil {
		entries = []meta.Entry{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(entries); err != nil {
		return textResult("keyref: "+err.Error()+"\nexit_code: 1", true), nil
	}
	return textResult(buf.String(), false), nil
}

// toolGet mirrors `keyref get <ref> --format json`.
func (s *mcpServer) toolGet(args json.RawMessage) (any, *mcpError) {
	if err := s.ensureInit(); err != nil {
		return textResult("keyref: "+err.Error()+"\nexit_code: 1", true), nil
	}
	var p struct {
		Ref string `json:"ref"`
	}
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil || p.Ref == "" {
		return textResult("keyref: get requires {\"ref\": \"...\"}\nexit_code: 2", true), nil
	}
	if locked(mustPaths()) {
		return textResult("keyref: session is locked; run keyref unlock\nexit_code: 12", true), nil
	}
	e, err := meta.Lookup(s.st, s.id, p.Ref)
	if err != nil {
		// Unknown ref and no-view share one code, never enumerating
		// other refs (design.md §12.2).
		return textResult(fmt.Sprintf("keyref: unknown ref %q\nexit_code: 11", p.Ref), true), nil
	}
	b, _ := json.MarshalIndent(e, "", "  ")
	return textResult(string(b)+"\n", false), nil
}

// toolExec mirrors `keyref exec`: the shared runExecCore performs the
// policy checks, the approval flow, the spawn and the redaction; the
// MCP result carries the redacted output and the exit code.
func (s *mcpServer) toolExec(args json.RawMessage) (any, *mcpError) {
	if err := s.ensureInit(); err != nil {
		return textResult("keyref: "+err.Error()+"\nexit_code: 1", true), nil
	}
	var a mcpExecArgs
	dec := json.NewDecoder(bytes.NewReader(args))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&a); err != nil {
		return textResult("keyref: invalid exec arguments: "+err.Error()+"\nexit_code: 2", true), nil
	}
	if len(a.Argv) == 0 {
		return textResult("keyref: exec requires a non-empty argv\nexit_code: 2", true), nil
	}
	envs := make([]string, 0, len(a.Env))
	for name, ref := range a.Env {
		envs = append(envs, name+"="+ref)
	}
	timeout := approvalTimeoutFromSeconds(a.Timeout)
	var out, errBuf bytes.Buffer
	code := runExecCore(execOptions{
		EnvRefs:   envs,
		StdinRef:  a.StdinRef,
		AllowArgv: a.AllowArgv,
		Argv:      a.Argv,
		Timeout:   timeout,
		// The MCP server is a paired CLI device: all three tools speak
		// the paired vault, whatever the CLI's default source is
		// (design.md §7.8).
		Source: source.SyncName,
		Stdout: &out,
		Stderr: &errBuf,
	})
	var text strings.Builder
	text.WriteString(out.String())
	if errBuf.Len() > 0 {
		text.WriteString(errBuf.String())
	}
	fmt.Fprintf(&text, "exit_code: %d\n", code)
	return textResult(text.String(), code != 0), nil
}

// approvalTimeoutFromSeconds maps the exec tool's timeout (seconds) to
// a duration, clamped to the server's 120-second window (protocol
// §6.19: expires_at − now ≤ 120000); 0 means the default.
func approvalTimeoutFromSeconds(secs float64) time.Duration {
	if secs <= 0 {
		return approval.DefaultTimeout
	}
	if secs > 120 {
		secs = 120
	}
	return time.Duration(secs * float64(time.Second))
}

// cmdMCP is the `keyref mcp` entry point. stdout is the JSON-RPC
// channel; the CLI's own notices stay on stderr.
func cmdMCP(args []string) int {
	fs := flag.NewFlagSet("mcp", flag.ContinueOnError)
	fs.Usage = func() {
		fmt.Fprint(fs.Output(), "usage: keyref mcp\n\nServe the vault over stdio as an MCP JSON-RPC 2.0 server\n(tools: list, get, exec — pass refs, never secrets).\n")
	}
	prepareHelp(fs, args)
	rest, err := parseArgs(fs, args)
	if err != nil {
		return parseExit(err)
	}
	if len(rest) != 0 {
		return fatalf(2, "usage: keyref mcp")
	}
	exec.DisableCoreDumps()
	serveMCP(os.Stdin, os.Stdout)
	return 0
}
