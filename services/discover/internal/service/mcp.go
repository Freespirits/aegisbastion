// MCP surface (doc 02 §3.1 discover-mcp): the four tools +
// resources exposed to HexStrike's orchestration runtime, wrapping the same
// order service layer as the REST API — no logic forks (doc 02 §9).
//
// Transport: JSON-RPC 2.0 over a single HTTP POST endpoint (MCP "streamable
// HTTP", JSON responses). Implemented dependency-free — the MCP method
// surface used here (initialize/ping/tools/resources) is small and stable.
package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

// MCP is the JSON-RPC handler.
type MCP struct {
	svc *Service
}

// NewMCP builds the MCP surface over the service layer.
func NewMCP(svc *Service) *MCP { return &MCP{svc: svc} }

const (
	mcpProtocolVersion = "2025-03-26"
	mcpServerName      = "aegisbastion-discover-mcp"
	mcpServerVersion   = "0.1.0"
)

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ServeHTTP handles POST /mcp (mount wherever the binary chooses).
func (m *MCP) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeErr(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "MCP endpoint is POST-only")
		return
	}
	var req rpcRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeRPC(w, nil, nil, &rpcError{Code: -32700, Message: "parse error: " + err.Error()})
		return
	}
	// Notifications carry no id — acknowledge with 202, no body.
	if len(req.ID) == 0 || string(req.ID) == "null" {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	res, rpcErr := m.dispatch(r, req.Method, req.Params)
	writeRPC(w, req.ID, res, rpcErr)
}

func writeRPC(w http.ResponseWriter, id json.RawMessage, result any, e *rpcError) {
	resp := rpcResponse{JSONRPC: "2.0", ID: id, Result: result, Error: e}
	if id == nil {
		resp.ID = json.RawMessage("null")
	}
	writeJSON(w, http.StatusOK, resp)
}

func (m *MCP) dispatch(r *http.Request, method string, params json.RawMessage) (any, *rpcError) {
	switch method {
	case "initialize":
		return map[string]any{
			"protocolVersion": mcpProtocolVersion,
			"capabilities": map[string]any{
				"tools":     map[string]any{"listChanged": false},
				"resources": map[string]any{"subscribe": false, "listChanged": false},
			},
			"serverInfo": map[string]any{"name": mcpServerName, "version": mcpServerVersion},
		}, nil
	case "ping":
		return map[string]any{}, nil
	case "tools/list":
		return map[string]any{"tools": mcpTools()}, nil
	case "tools/call":
		return m.callTool(r, params)
	case "resources/list":
		return map[string]any{"resources": []any{}}, nil
	case "resources/templates/list":
		return map[string]any{"resourceTemplates": mcpResourceTemplates()}, nil
	case "resources/read":
		return m.readResource(r, params)
	}
	return nil, &rpcError{Code: -32601, Message: "method not found: " + method}
}

// ---------------------------------------------------------------------------
// tools (doc 02 §3.1)
// ---------------------------------------------------------------------------

func mcpTools() []map[string]any {
	schema := func(props map[string]any, required []string) map[string]any {
		return map[string]any{"type": "object", "properties": props, "required": required}
	}
	str := map[string]any{"type": "string"}
	return []map[string]any{
		{
			"name": "discover.submit_order",
			"description": "Submit a DiscoveryOrder (doc 02 §3.2). Returns {order_id} on acceptance " +
				"(HTTP 202 semantics); gatekeeper denials surface as tool errors carrying the reason codes.",
			"inputSchema": schema(map[string]any{"order": map[string]any{
				"type":        "object",
				"description": "DiscoveryOrder v1.1 (seeds, techniques, authorization.roe_id, options)",
			}}, []string{"order"}),
		},
		{
			"name":        "discover.get_status",
			"description": "Order status + progress + gate record (doc 02 §3.2 OrderStatus).",
			"inputSchema": schema(map[string]any{"order_id": str}, []string{"order_id"}),
		},
		{
			"name":        "discover.list_assets",
			"description": "Paginated assets for an order (or the tenant working store when order_id is empty and tenant_id is set).",
			"inputSchema": schema(map[string]any{
				"order_id":  str,
				"tenant_id": str,
				"cursor":    str,
				"limit":     map[string]any{"type": "integer"},
			}, []string{}),
		},
		{
			"name":        "discover.cancel",
			"description": "Cooperative cancellation of a RUNNING/PENDING order.",
			"inputSchema": schema(map[string]any{"order_id": str}, []string{"order_id"}),
		},
	}
}

func mcpResourceTemplates() []map[string]any {
	return []map[string]any{
		{
			"uriTemplate": "discover://orders/{order_id}",
			"name":        "discover-order-status",
			"description": "Live order status JSON (updated during RUNNING, doc 02 §3.3)",
			"mimeType":    "application/json",
		},
		{
			"uriTemplate": "discover://scopes/{roe_id}",
			"name":        "discover-effective-scope",
			"description": "Effective scope as resolved by gatekeeper for one RoE (read-only mirror, doc 02 §3.1/§6.1)",
			"mimeType":    "application/json",
		},
	}
}

type toolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

func toolResult(v any, isErr bool) (any, *rpcError) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, &rpcError{Code: -32603, Message: err.Error()}
	}
	return map[string]any{
		"content": []map[string]any{{"type": "text", "text": string(body)}},
		"isError": isErr,
	}, nil
}

func (m *MCP) callTool(r *http.Request, params json.RawMessage) (any, *rpcError) {
	var p toolCallParams
	if err := json.Unmarshal(params, &p); err != nil {
		return nil, &rpcError{Code: -32602, Message: "invalid tools/call params: " + err.Error()}
	}
	switch p.Name {
	case "discover.submit_order":
		var args struct {
			Order model.DiscoveryOrder `json:"order"`
		}
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return toolResult(map[string]any{"error": "arguments.order does not decode: " + err.Error()}, true)
		}
		st, err := m.svc.SubmitOrder(r.Context(), &args.Order)
		if err != nil {
			out := map[string]any{"error": err.Error()}
			if st != nil {
				out["status"] = st
			}
			return toolResult(out, true)
		}
		return toolResult(map[string]any{"order_id": st.OrderID, "state": st.State}, false)

	case "discover.get_status":
		var args struct {
			OrderID string `json:"order_id"`
		}
		if err := json.Unmarshal(p.Arguments, &args); err != nil || args.OrderID == "" {
			return toolResult(map[string]any{"error": "arguments.order_id is required"}, true)
		}
		st, err := m.svc.GetStatus(r.Context(), args.OrderID)
		if err != nil {
			return toolResult(map[string]any{"error": err.Error()}, true)
		}
		return toolResult(st, false)

	case "discover.list_assets":
		var args struct {
			OrderID  string `json:"order_id"`
			TenantID string `json:"tenant_id"`
			Cursor   string `json:"cursor"`
			Limit    int    `json:"limit"`
		}
		if err := json.Unmarshal(p.Arguments, &args); err != nil {
			return toolResult(map[string]any{"error": "invalid arguments: " + err.Error()}, true)
		}
		if args.OrderID != "" {
			assets, next, err := m.svc.ListOrderAssets(r.Context(), args.OrderID, args.Cursor, args.Limit)
			if err != nil {
				return toolResult(map[string]any{"error": err.Error()}, true)
			}
			return toolResult(map[string]any{"assets": assets, "next_cursor": next}, false)
		}
		if args.TenantID == "" {
			return toolResult(map[string]any{"error": "order_id or tenant_id is required"}, true)
		}
		assets, next, err := m.svc.ListAssets(r.Context(), store.AssetQuery{
			TenantID: args.TenantID, Cursor: args.Cursor, Limit: args.Limit,
		})
		if err != nil {
			return toolResult(map[string]any{"error": err.Error()}, true)
		}
		return toolResult(map[string]any{"assets": assets, "next_cursor": next}, false)

	case "discover.cancel":
		var args struct {
			OrderID string `json:"order_id"`
		}
		if err := json.Unmarshal(p.Arguments, &args); err != nil || args.OrderID == "" {
			return toolResult(map[string]any{"error": "arguments.order_id is required"}, true)
		}
		st, err := m.svc.Cancel(r.Context(), args.OrderID)
		if err != nil {
			return toolResult(map[string]any{"error": err.Error()}, true)
		}
		return toolResult(map[string]any{"order_id": st.OrderID, "state": st.State}, false)
	}
	return toolResult(map[string]any{"error": "unknown tool " + p.Name}, true)
}

// ---------------------------------------------------------------------------
// resources (doc 02 §3.1)
// ---------------------------------------------------------------------------

func (m *MCP) readResource(r *http.Request, params json.RawMessage) (any, *rpcError) {
	var p struct {
		URI string `json:"uri"`
	}
	if err := json.Unmarshal(params, &p); err != nil || p.URI == "" {
		return nil, &rpcError{Code: -32602, Message: "resources/read requires params.uri"}
	}
	contents := func(v any) (any, *rpcError) {
		body, err := json.MarshalIndent(v, "", "  ")
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return map[string]any{"contents": []map[string]any{{
			"uri": p.URI, "mimeType": "application/json", "text": string(body),
		}}}, nil
	}
	switch {
	case strings.HasPrefix(p.URI, "discover://orders/"):
		id := strings.TrimPrefix(p.URI, "discover://orders/")
		st, err := m.svc.GetStatus(r.Context(), id)
		if errors.Is(err, store.ErrNotFound) {
			return nil, &rpcError{Code: -32004, Message: "no such order: " + id}
		}
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: err.Error()}
		}
		return contents(st)
	case strings.HasPrefix(p.URI, "discover://scopes/"):
		roeID := strings.TrimPrefix(p.URI, "discover://scopes/")
		sc, err := m.svc.ResolvedScope(r.Context(), roeID)
		if err != nil {
			return nil, &rpcError{Code: -32603, Message: fmt.Sprintf("scope resolution failed (gatekeeper): %v", err)}
		}
		return contents(sc)
	}
	return nil, &rpcError{Code: -32004, Message: "unknown resource: " + p.URI}
}
