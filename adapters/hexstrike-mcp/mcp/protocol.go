// Package mcp implements the server side of the Model Context Protocol over
// stdio: newline-delimited JSON-RPC 2.0, per the MCP spec (transport used by
// the HexStrike client config hexstrike-ai-mcp.json, which launches a
// command and speaks stdio). Only the surface the adapter needs is
// implemented: initialize, notifications/initialized, ping, tools/list,
// tools/call.
//
// Protocol rules honoured here:
//   - stdout carries protocol messages only; all logging goes to stderr.
//   - Notifications (no "id", or method starting with "notifications/")
//     never get a response.
//   - Tool execution failures are returned as a tools/call *result* with
//     isError: true; protocol-level problems use JSON-RPC error codes.
package mcp

import (
	"encoding/json"
	"fmt"
)

// ProtocolVersion is the MCP revision this server speaks. Clients offering
// an older revision are answered with this one, per the spec's
// version-negotiation rule.
const ProtocolVersion = "2025-03-26"

// JSON-RPC 2.0 error codes.
const (
	codeParseError     = -32700
	codeInvalidRequest = -32600
	codeMethodNotFound = -32601
	codeInvalidParams  = -32602
	codeInternalError  = -32603
)

// Request is an inbound JSON-RPC message.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Notification reports whether the message expects no response.
func (r *Request) Notification() bool {
	return len(r.ID) == 0 || string(r.ID) == "null"
}

// Response is an outbound JSON-RPC message. Exactly one of Result / Error is
// set. The ID mirrors the request's (raw, so numbers and strings round-trip).
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *ErrorObject    `json:"error,omitempty"`
}

// ErrorObject is a JSON-RPC error.
type ErrorObject struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// rpcError builds a protocol-level error value.
func rpcError(code int, format string, args ...any) *ErrorObject {
	return &ErrorObject{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Tool describes one callable tool for tools/list.
type Tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

// ToolHandler executes one tools/call. The result is serialized to JSON and
// returned as the single text content block; a non-nil error becomes a
// result with isError: true.
type ToolHandler func(ctx *CallContext, arguments json.RawMessage) (any, error)

// CallContext carries per-call context to handlers.
type CallContext struct {
	// ClientInfo from the initialize handshake (may be nil).
	ClientInfo *ClientInfo
}

// ClientInfo identifies the connecting MCP client.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// TextContent is one content block in a tools/call result.
type TextContent struct {
	Type string `json:"type"` // always "text"
	Text string `json:"text"`
}

// CallResult is the tools/call result shape.
type CallResult struct {
	Content []TextContent `json:"content"`
	IsError bool          `json:"isError,omitempty"`
}
