package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"sync"
)

// Server speaks MCP over an io pair (stdin/stdout in production, pipes in
// tests). It is single-connection: the HexStrike client launches one adapter
// process per session.
type Server struct {
	name    string
	version string
	tools   map[string]ToolHandler
	descs   []Tool // registration order, for tools/list

	clientMu sync.Mutex
	client   *ClientInfo
}

// NewServer builds the protocol server. serverName/version are reported in
// the initialize handshake.
func NewServer(serverName, version string) *Server {
	return &Server{
		name:    serverName,
		version: version,
		tools:   map[string]ToolHandler{},
	}
}

// RegisterTool adds a tool. Order of registration is the tools/list order.
func (s *Server) RegisterTool(desc Tool, h ToolHandler) {
	s.tools[desc.Name] = h
	s.descs = append(s.descs, desc)
}

// ToolNames returns the registered tool names in registration order.
func (s *Server) ToolNames() []string {
	names := make([]string, 0, len(s.descs))
	for _, d := range s.descs {
		names = append(names, d.Name)
	}
	return names
}

// Serve reads newline-delimited JSON-RPC messages from in until EOF or a
// fatal write error, dispatching each and writing responses to out.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	sc := bufio.NewScanner(in)
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20) // plans can be large
	w := bufio.NewWriter(out)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		resp := s.dispatch(ctx, line)
		if resp == nil { // notification
			continue
		}
		b, err := json.Marshal(resp)
		if err != nil {
			return fmt.Errorf("mcp: marshal response: %w", err)
		}
		if _, err := w.Write(b); err != nil {
			return fmt.Errorf("mcp: write response: %w", err)
		}
		if err := w.WriteByte('\n'); err != nil {
			return fmt.Errorf("mcp: write response: %w", err)
		}
		if err := w.Flush(); err != nil {
			return fmt.Errorf("mcp: flush: %w", err)
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("mcp: read input: %w", err)
	}
	return nil // clean EOF: client exited
}

// dispatch handles one raw message and returns the response (nil for
// notifications).
func (s *Server) dispatch(ctx context.Context, raw []byte) *Response {
	var req Request
	if err := json.Unmarshal(raw, &req); err != nil {
		return &Response{JSONRPC: "2.0", ID: json.RawMessage("null"),
			Error: rpcError(codeParseError, "invalid JSON: %v", err)}
	}
	if req.JSONRPC != "2.0" || req.Method == "" {
		if req.Notification() {
			return nil
		}
		return &Response{JSONRPC: "2.0", ID: req.ID,
			Error: rpcError(codeInvalidRequest, "not a JSON-RPC 2.0 request")}
	}

	if req.Notification() {
		s.handleNotification(ctx, &req)
		return nil
	}

	switch req.Method {
	case "initialize":
		return s.onInitialize(&req)
	case "ping":
		return &Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{}}
	case "tools/list":
		return &Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{"tools": s.descs}}
	case "tools/call":
		return s.onToolCall(ctx, &req)
	default:
		return &Response{JSONRPC: "2.0", ID: req.ID,
			Error: rpcError(codeMethodNotFound, "method not found: %s", req.Method)}
	}
}

func (s *Server) handleNotification(_ context.Context, req *Request) {
	// notifications/initialized and friends need no action; unknown
	// notifications are ignored per JSON-RPC.
	log.Printf("mcp: notification %s", req.Method)
}

func (s *Server) onInitialize(req *Request) *Response {
	var params struct {
		ProtocolVersion string      `json:"protocolVersion"`
		ClientInfo      *ClientInfo `json:"clientInfo"`
	}
	_ = json.Unmarshal(req.Params, &params)
	s.clientMu.Lock()
	s.client = params.ClientInfo
	s.clientMu.Unlock()
	return &Response{JSONRPC: "2.0", ID: req.ID, Result: map[string]any{
		"protocolVersion": ProtocolVersion,
		"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
		"serverInfo":      map[string]string{"name": s.name, "version": s.version},
	}}
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func (s *Server) onToolCall(ctx context.Context, req *Request) *Response {
	var p toolCallParams
	if err := json.Unmarshal(req.Params, &p); err != nil || p.Name == "" {
		return &Response{JSONRPC: "2.0", ID: req.ID,
			Error: rpcError(codeInvalidParams, "tools/call params must include name and arguments")}
	}
	h, ok := s.tools[p.Name]
	if !ok {
		return &Response{JSONRPC: "2.0", ID: req.ID,
			Error: rpcError(codeInvalidParams, "unknown tool: %s", p.Name)}
	}
	s.clientMu.Lock()
	callCtx := &CallContext{ClientInfo: s.client}
	s.clientMu.Unlock()
	_ = ctx // reserved for future per-call cancellation plumbing

	result, err := h(callCtx, p.Arguments)
	if err != nil {
		return &Response{JSONRPC: "2.0", ID: req.ID, Result: CallResult{
			Content: []TextContent{{Type: "text", Text: err.Error()}},
			IsError: true,
		}}
	}
	text, err := json.Marshal(result)
	if err != nil {
		return &Response{JSONRPC: "2.0", ID: req.ID, Result: CallResult{
			Content: []TextContent{{Type: "text", Text: "marshal tool result: " + err.Error()}},
			IsError: true,
		}}
	}
	return &Response{JSONRPC: "2.0", ID: req.ID, Result: CallResult{
		Content: []TextContent{{Type: "text", Text: string(text)}},
	}}
}
