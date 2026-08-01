package app

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/hx"
	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/mcp"
	"github.com/aegisbastion/aegisbastion/adapters/internal/plannerfake"
)

func testDeps(t *testing.T) (*Deps, *plannerfake.Server) {
	t.Helper()
	fake := plannerfake.New()
	client, cleanup := fake.Client()
	t.Cleanup(cleanup)
	fixed := func() time.Time { return time.Unix(1754000000, 0).UTC() }
	return &Deps{
		Planner: client,
		HX:      hx.NewMockClient(),
		Ledger:  NewLedger(),
		Now:     fixed,
	}, fake
}

func call(t *testing.T, h mcp.ToolHandler, args string) (any, error) {
	t.Helper()
	return h(&mcp.CallContext{}, json.RawMessage(args))
}

// The full commander loop: propose → verdict → execute only what was
// accepted → TaskResult mapped back.
func TestSubmitThenExecuteApprovedTask(t *testing.T) {
	d, fake := testDeps(t)

	out, err := call(t, d.submitTaskPlan, `{
		"mission_id": "msn_test",
		"tasks": [
			{"task_key": "scan-web", "capability": "detect.scan.web", "risk_class": "R2",
			 "targets": ["https://acme.com"], "params": {"severity": "high"}},
			{"task_key": "bogus", "capability": "redteam.api_probe", "risk_class": "R3",
			 "targets": ["https://acme.com"]}
		]
	}`)
	if err != nil {
		t.Fatalf("submit_task_plan: %v", err)
	}
	sub := out.(submitPlanOut)
	if sub.Decision != "PARTIAL" {
		t.Fatalf("decision = %s, want PARTIAL (one task unregistered)", sub.Decision)
	}
	if !strings.HasPrefix(sub.PlanID, "pln_") {
		t.Errorf("plan_id = %q", sub.PlanID)
	}
	// The plan reached the PlannerService tagged as HexStrike's.
	if len(fake.Plans()) != 1 || fake.Plans()[0].GetSubmittedBy().String() != "COMMANDER_HEXSTRIKE" {
		t.Fatalf("submitted plan not recorded/tagged: %+v", fake.Plans())
	}

	// Executing the ACCEPTED task works and maps a TaskResult back.
	res, err := call(t, d.executeApprovedTask, `{"plan_id": "`+sub.PlanID+`", "task_key": "scan-web"}`)
	if err != nil {
		t.Fatalf("execute_approved_task: %v", err)
	}
	m := res.(map[string]any)
	if m["status"] != "TASK_RESULT_STATUS_SUCCEEDED" {
		t.Errorf("status = %v, want TASK_RESULT_STATUS_SUCCEEDED", m["status"])
	}
	if m["agentId"] != ExecutorID {
		t.Errorf("agentId = %v", m["agentId"])
	}
	metrics := m["metrics"].(map[string]any)
	if metrics["requestsSent"] != "1" {
		t.Errorf("requestsSent = %v", metrics["requestsSent"])
	}
	summary := m["summary"].(map[string]any)
	results := summary["results"].([]any)
	first := results[0].(map[string]any)
	toolResult := first["result"].(map[string]any)
	if toolResult["mock"] != true {
		t.Errorf("mock mode must be visible in the mapped result: %v", toolResult)
	}
	// The param override must have reached the tool call.
	toolArgs := toolResult["args"].(map[string]any)
	if toolArgs["severity"] != "high" {
		t.Errorf("severity override lost: %v", toolArgs)
	}

	// Executing the REJECTED task is refused — planner, not authorizer.
	_, err = call(t, d.executeApprovedTask, `{"plan_id": "`+sub.PlanID+`", "task_key": "bogus"}`)
	if err == nil {
		t.Fatal("rejected task must not execute")
	}
	if !strings.Contains(err.Error(), "not an authorizer") {
		t.Errorf("refusal should state the planner-not-authorizer rule, got: %v", err)
	}
}

func TestExecuteWithoutSubmissionRefused(t *testing.T) {
	d, _ := testDeps(t)
	_, err := call(t, d.executeApprovedTask, `{"plan_id": "pln_never", "task_key": "x"}`)
	if err == nil || !strings.Contains(err.Error(), "refused") {
		t.Fatalf("execution without a prior accepted verdict must be refused, got %v", err)
	}
}

func TestSubmitValidation(t *testing.T) {
	d, _ := testDeps(t)
	cases := []struct {
		name string
		args string
		want string
	}{
		{"no mission", `{"tasks":[{"task_key":"a","capability":"recon.ct","risk_class":"R0","targets":["x"]}]}`, "mission_id"},
		{"no tasks", `{"mission_id":"msn_x","tasks":[]}`, "at least one task"},
		{"dup keys", `{"mission_id":"msn_x","tasks":[
			{"task_key":"a","capability":"recon.ct","risk_class":"R0","targets":["x"]},
			{"task_key":"a","capability":"recon.ct","risk_class":"R0","targets":["x"]}]}`, "duplicate task_key"},
		{"bad risk", `{"mission_id":"msn_x","tasks":[{"task_key":"a","capability":"recon.ct","risk_class":"R9","targets":["x"]}]}`, "risk_class"},
		{"bad dep", `{"mission_id":"msn_x","tasks":[{"task_key":"a","capability":"recon.ct","risk_class":"R0","targets":["x"],"depends_on":["ghost"]}]}`, "unknown task_key"},
	}
	for _, tc := range cases {
		if _, err := call(t, d.submitTaskPlan, tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.want, err)
		}
	}
}

func TestReadTools(t *testing.T) {
	d, fake := testDeps(t)

	status, err := call(t, d.getMissionStatus, `{"mission_id": "msn_1"}`)
	if err != nil {
		t.Fatalf("get_mission_status: %v", err)
	}
	m := status.(map[string]any)["status"].(map[string]any)
	if m["inFlightTasks"] != float64(1) {
		t.Errorf("inFlightTasks = %v", m["inFlightTasks"])
	}

	caps, err := call(t, d.listCapabilities, `{"name_prefix": "recon.", "max_risk_class": "R1"}`)
	if err != nil {
		t.Fatalf("list_capabilities: %v", err)
	}
	list := caps.(map[string]any)["capabilities"].([]any)
	if len(list) == 0 {
		t.Error("expected recon.* capabilities")
	}
	for _, c := range list {
		name := c.(map[string]any)["capability"].(map[string]any)["name"].(string)
		if !strings.HasPrefix(name, "recon.") {
			t.Errorf("filter leaked capability %s", name)
		}
	}

	out, err := call(t, d.requestScopeChange, `{"mission_id": "msn_1", "justification": "need staging", "requested_additions": ["staging.acme.com"]}`)
	if err != nil {
		t.Fatalf("request_scope_change: %v", err)
	}
	if out.(map[string]any)["queued"] != true {
		t.Errorf("queued = %v", out)
	}
	if len(fake.ScopeChanges()) != 1 || fake.ScopeChanges()[0].GetJustification() != "need staging" {
		t.Errorf("scope change not forwarded: %+v", fake.ScopeChanges())
	}
}

// The MCP server exposes exactly the doc 01 §7.1 tool set plus the execution
// bridge.
func TestRegisteredToolSet(t *testing.T) {
	d, _ := testDeps(t)
	s := mcp.NewServer("test", "0")
	RegisterTools(s, d)
	want := []string{"submit_task_plan", "get_mission_status", "list_capabilities", "request_scope_change", "execute_approved_task"}
	if len(s.ToolNames()) != len(want) {
		t.Fatalf("registered tools = %v, want %v", s.ToolNames(), want)
	}
	for i, name := range want {
		if s.ToolNames()[i] != name {
			t.Errorf("tool[%d] = %s, want %s", i, s.ToolNames()[i], name)
		}
	}
}
