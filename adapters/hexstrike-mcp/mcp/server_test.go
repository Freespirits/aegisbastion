package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"
)

// session drives a Server over pipes for one test.
type session struct {
	t   *testing.T
	in  io.Writer
	out *bufio.Scanner
}

func newSession(t *testing.T, s *Server) *session {
	t.Helper()
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() { _ = s.Serve(context.Background(), reqR, respW) }()
	sess := &session{t: t, in: reqW, out: bufio.NewScanner(respR)}
	t.Cleanup(func() { _ = reqW.Close() })
	return sess
}

// call sends one request and reads one response.
func (s *session) call(t *testing.T, msg string) Response {
	t.Helper()
	if _, err := io.WriteString(s.in, msg+"\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !s.out.Scan() {
		t.Fatalf("no response to %s", msg)
	}
	var resp Response
	if err := json.Unmarshal(s.out.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp
}

func echoTool(_ *CallContext, args json.RawMessage) (any, error) {
	var m map[string]any
	_ = json.Unmarshal(args, &m)
	return map[string]any{"echo": m}, nil
}

func newTestServer() *Server {
	s := NewServer("test-server", "0.0.1")
	s.RegisterTool(Tool{Name: "echo", Description: "echoes", InputSchema: map[string]any{"type": "object"}}, echoTool)
	s.RegisterTool(Tool{Name: "fail", Description: "fails", InputSchema: map[string]any{"type": "object"}}, func(_ *CallContext, _ json.RawMessage) (any, error) {
		return nil, io.ErrUnexpectedEOF
	})
	return s
}

func TestInitializeHandshake(t *testing.T) {
	sess := newSession(t, newTestServer())
	resp := sess.call(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","clientInfo":{"name":"hexstrike","version":"6.0"}}}`)
	if resp.Error != nil {
		t.Fatalf("initialize error: %+v", resp.Error)
	}
	result := resp.Result.(map[string]any)
	if result["protocolVersion"] != ProtocolVersion {
		t.Errorf("protocolVersion = %v, want %s", result["protocolVersion"], ProtocolVersion)
	}
	info := result["serverInfo"].(map[string]any)
	if info["name"] != "test-server" || info["version"] != "0.0.1" {
		t.Errorf("serverInfo = %+v", info)
	}
	caps := result["capabilities"].(map[string]any)
	if _, ok := caps["tools"]; !ok {
		t.Errorf("capabilities missing tools: %+v", caps)
	}
}

func TestToolsListAndCall(t *testing.T) {
	sess := newSession(t, newTestServer())
	resp := sess.call(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools := resp.Result.(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools/list returned %d tools, want 2", len(tools))
	}
	if tools[0].(map[string]any)["name"] != "echo" {
		t.Errorf("first tool = %v, want echo (registration order)", tools[0])
	}

	resp = sess.call(t, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"a":1}}}`)
	result, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("tools/call result malformed: %v", resp.Result)
	}
	content := result["content"].([]any)
	text := content[0].(map[string]any)["text"].(string)
	if !strings.Contains(text, `"a":1`) {
		t.Errorf("echo result = %s", text)
	}
	if isErr, _ := result["isError"].(bool); isErr {
		t.Errorf("isError should be false")
	}
}

func TestToolFailureIsResultNotProtocolError(t *testing.T) {
	sess := newSession(t, newTestServer())
	resp := sess.call(t, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"fail","arguments":{}}}`)
	if resp.Error != nil {
		t.Fatalf("tool failure must be a result, not a protocol error: %+v", resp.Error)
	}
	result := resp.Result.(map[string]any)
	if isErr, _ := result["isError"].(bool); !isErr {
		t.Errorf("isError = %v, want true", result["isError"])
	}
}

func TestProtocolErrors(t *testing.T) {
	sess := newSession(t, newTestServer())

	resp := sess.call(t, `{"jsonrpc":"2.0","id":5,"method":"no/such"}`)
	if resp.Error == nil || resp.Error.Code != codeMethodNotFound {
		t.Errorf("unknown method: %+v", resp.Error)
	}

	resp = sess.call(t, `{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"ghost","arguments":{}}}`)
	if resp.Error == nil || resp.Error.Code != codeInvalidParams {
		t.Errorf("unknown tool: %+v", resp.Error)
	}

	resp = sess.call(t, `not json`)
	if resp.Error == nil || resp.Error.Code != codeParseError {
		t.Errorf("parse error: %+v", resp.Error)
	}
	if string(resp.ID) != "null" {
		t.Errorf("parse-error id should be null, got %s", resp.ID)
	}
}

func TestNotificationGetsNoResponse(t *testing.T) {
	sess := newSession(t, newTestServer())
	if _, err := io.WriteString(sess.in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	// A notification must produce no output; the next request's response must
	// be the answer to THAT request, proving nothing was written in between.
	resp := sess.call(t, `{"jsonrpc":"2.0","id":7,"method":"ping"}`)
	if string(resp.ID) != "7" {
		t.Errorf("notification produced output; got response id %s", resp.ID)
	}
}

func TestServeCleanEOF(t *testing.T) {
	s := newTestServer()
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), strings.NewReader(""), io.Discard) }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("empty input should be a clean EOF, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Serve did not return on EOF")
	}
}
