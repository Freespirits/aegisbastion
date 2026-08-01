// Package integration exercises both commander adapters against the
// generated aegisbastion.platform.v1.PlannerService contract end-to-end: the
// HexStrike adapter over the real MCP stdio protocol, the CAI adapter over
// its real REST surface, both talking gRPC (bufconn) to an in-memory
// PlannerService implementing the generated server stubs.
//
// When the platform-core Orchestrator (services/) ships, this suite's fake
// can be swapped for the real binary — the adapters see no difference
// because they code strictly to the generated client stubs.
package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	caiapp "github.com/aegisbastion/aegisbastion/adapters/cai/app"
	hexapp "github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/app"
	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/hx"
	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/mcp"
	"github.com/aegisbastion/aegisbastion/adapters/internal/plannerclient"
	"github.com/aegisbastion/aegisbastion/adapters/internal/plannerfake"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// mcpSession runs the HexStrike adapter's MCP server over pipes.
type mcpSession struct {
	t    *testing.T
	in   io.Writer
	scan *bufio.Scanner
}

func newMCPSession(t *testing.T, planner platformv1.PlannerServiceClient) *mcpSession {
	t.Helper()
	srv := mcp.NewServer("aegisbastion-hexstrike-adapter", "test")
	hexapp.RegisterTools(srv, &hexapp.Deps{
		Planner: planner,
		HX:      hx.NewMockClient(),
		Ledger:  hexapp.NewLedger(),
		Now:     time.Now,
	})
	reqR, reqW := io.Pipe()
	respR, respW := io.Pipe()
	go func() { _ = srv.Serve(context.Background(), reqR, respW) }()
	s := &mcpSession{t: t, in: reqW, scan: bufio.NewScanner(respR)}
	s.scan.Buffer(make([]byte, 0, 1<<20), 16<<20)
	t.Cleanup(func() { _ = reqW.Close() })
	return s
}

func (s *mcpSession) call(t *testing.T, msg string) map[string]any {
	t.Helper()
	if _, err := io.WriteString(s.in, msg+"\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	if !s.scan.Scan() {
		t.Fatal("no MCP response")
	}
	var resp map[string]any
	if err := json.Unmarshal(s.scan.Bytes(), &resp); err != nil {
		t.Fatalf("decode MCP response: %v", err)
	}
	if errObj, ok := resp["error"]; ok {
		t.Fatalf("MCP protocol error: %v", errObj)
	}
	return resp["result"].(map[string]any)
}

// rpc builds a compact single-line JSON-RPC request (the stdio transport is
// newline-delimited, so pretty-printed JSON would be split mid-message).
func rpc(t *testing.T, id int, method string, params any) string {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": id, "method": method, "params": params,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}
	return string(raw)
}

// toolResult unwraps a tools/call result into the tool's JSON payload.
func toolResult(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	if isErr, _ := result["isError"].(bool); isErr {
		t.Fatalf("tool returned isError: %v", result["content"])
	}
	text := result["content"].([]any)[0].(map[string]any)["text"].(string)
	var out map[string]any
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatalf("tool payload not JSON: %v", err)
	}
	return out
}

// The doc 01 §6.1/§6.3 commander loop over the real MCP wire: initialize →
// plan → verdict → execute approved only → TaskResult.
func TestHexStrikeAdapterOverMCPWire(t *testing.T) {
	fake := plannerfake.New()
	planner, cleanup := fake.Client()
	t.Cleanup(cleanup)

	// Readiness through the shared probe against the real gRPC client.
	if err := plannerclient.Ready(context.Background(), planner); err != nil {
		t.Fatalf("planner readiness: %v", err)
	}

	s := newMCPSession(t, planner)

	init := s.call(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","clientInfo":{"name":"hexstrike-ai","version":"6.0"}}}`)
	if init["protocolVersion"] != mcp.ProtocolVersion {
		t.Errorf("protocolVersion = %v", init["protocolVersion"])
	}
	if _, err := io.WriteString(s.in, `{"jsonrpc":"2.0","method":"notifications/initialized"}`+"\n"); err != nil {
		t.Fatalf("write notification: %v", err)
	}

	tools := s.call(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if len(tools["tools"].([]any)) != 5 {
		t.Errorf("tools/list = %d tools, want 5", len(tools["tools"].([]any)))
	}

	plan := toolResult(t, s.call(t, rpc(t, 3, "tools/call", map[string]any{
		"name": "submit_task_plan",
		"arguments": map[string]any{
			"mission_id": "msn_e2e",
			"tasks": []map[string]any{
				{"task_key": "port-scan", "capability": "recon.port_scan", "risk_class": "R1", "targets": []string{"203.0.113.10"}, "timeout_s": 60},
				{"task_key": "web-scan", "capability": "detect.scan.web", "risk_class": "R2", "targets": []string{"https://acme.com"}, "depends_on": []string{"port-scan"}, "timeout_s": 60},
			},
		},
	})))
	if plan["decision"] != "ACCEPTED" {
		t.Fatalf("decision = %v, want ACCEPTED", plan["decision"])
	}
	planID := plan["plan_id"].(string)

	exec := toolResult(t, s.call(t, rpc(t, 4, "tools/call", map[string]any{
		"name":      "execute_approved_task",
		"arguments": map[string]any{"plan_id": planID, "task_key": "web-scan"},
	})))
	if exec["status"] != "TASK_RESULT_STATUS_SUCCEEDED" {
		t.Errorf("status = %v", exec["status"])
	}
	if exec["agentId"] != hexapp.ExecutorID {
		t.Errorf("agentId = %v", exec["agentId"])
	}

	// The plan arrived at the PlannerService tagged COMMANDER_HEXSTRIKE with
	// the DAG intact.
	if len(fake.Plans()) != 1 {
		t.Fatalf("fake received %d plans, want 1", len(fake.Plans()))
	}
	got := fake.Plans()[0]
	if got.GetSubmittedBy() != platformv1.Commander_COMMANDER_HEXSTRIKE {
		t.Errorf("submitted_by = %v", got.GetSubmittedBy())
	}
	if got.GetTasks()[1].GetDependsOn()[0] != "port-scan" {
		t.Errorf("DAG edge lost: %+v", got.GetTasks()[1])
	}
}

// The MVP-A acceptance slice for the CAI stub: intent in → marked
// deterministic Discover-passive plan → ACCEPTED by the PlannerService.
func TestCAIStubEndToEnd(t *testing.T) {
	fake := plannerfake.New()
	planner, cleanup := fake.Client()
	t.Cleanup(cleanup)

	srv := caiapp.NewServer(caiapp.StubPlanner{}, planner)
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)

	resp, err := http.Post(ts.URL+"/v1/intents", "application/json",
		strings.NewReader(`{"mission_id":"msn_e2e","objective":"map acme.com attack surface","targets":["acme.com"]}`))
	if err != nil {
		t.Fatalf("POST /v1/intents: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var out struct {
		Submission struct {
			Decision string `json:"decision"`
		} `json:"submission"`
		Error string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Submission.Decision != "ACCEPTED" {
		t.Errorf("decision = %s, want ACCEPTED", out.Submission.Decision)
	}
	if len(fake.Plans()) != 1 || fake.Plans()[0].GetSubmittedBy() != platformv1.Commander_COMMANDER_CAI {
		t.Fatalf("CAI plan not recorded: %+v", fake.Plans())
	}
	for _, task := range fake.Plans()[0].GetTasks() {
		if !task.GetParams().GetFields()["stub"].GetBoolValue() {
			t.Errorf("task %s lost its stub marker over the wire", task.GetTaskKey())
		}
		if task.GetRiskClass() != platformv1.RiskClass_RISK_CLASS_R0 {
			t.Errorf("task %s risk = %v, want R0", task.GetTaskKey(), task.GetRiskClass())
		}
	}
}
