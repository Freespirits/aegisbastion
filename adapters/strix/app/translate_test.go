package app

import (
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/aegisbastion/aegisbastion/adapters/strix/strixcli"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

func spec(t *testing.T, capability string, targets []string, params map[string]any) *platformv1.TaskSpec {
	t.Helper()
	var ps *structpb.Struct
	if params != nil {
		var err error
		ps, err = structpb.NewStruct(params)
		if err != nil {
			t.Fatalf("params: %v", err)
		}
	}
	return &platformv1.TaskSpec{
		TaskKey:    "t1",
		Capability: capability,
		RiskClass:  platformv1.RiskClass_RISK_CLASS_R2,
		Targets:    targets,
		Params:     ps,
	}
}

func TestTranslateTaskMappings(t *testing.T) {
	cases := []struct {
		capability string
		scanMode   string
	}{
		{"recon.port_scan", "quick"},
		{"recon.web_surface", "quick"},
		{"detect.scan.web", "standard"},
		{"detect.scan.api", "standard"},
		{"detect.scan.full", "deep"},
	}
	for _, tc := range cases {
		calls, err := TranslateTask(spec(t, tc.capability, []string{"https://acme.com"}, nil))
		if err != nil {
			t.Errorf("%s: %v", tc.capability, err)
			continue
		}
		if len(calls) != 1 {
			t.Errorf("%s: got %d calls, want 1", tc.capability, len(calls))
			continue
		}
		c := calls[0]
		if c.ScanMode != tc.scanMode {
			t.Errorf("%s: scan mode = %s, want %s", tc.capability, c.ScanMode, tc.scanMode)
		}
		if c.Target != "https://acme.com" {
			t.Errorf("%s: target = %q", tc.capability, c.Target)
		}
		if c.Instruction == "" {
			t.Errorf("%s: mapping must carry a steering instruction", tc.capability)
		}
		if strings.Contains(strings.ToLower(c.Instruction), "exploitation") &&
			strings.HasPrefix(tc.capability, "recon.") &&
			!strings.Contains(c.Instruction, "Do not attempt exploitation") {
			t.Errorf("%s: recon mappings must forbid exploitation", tc.capability)
		}
	}
	// The PoC-validation promise: detect-class mappings demand proof-of-exploit.
	for _, cap := range []string{"detect.scan.web", "detect.scan.api", "detect.scan.full"} {
		calls, _ := TranslateTask(spec(t, cap, []string{"https://acme.com"}, nil))
		if !strings.Contains(calls[0].Instruction, "proof-of-exploit") {
			t.Errorf("%s: detect-class mappings must require PoC validation", cap)
		}
	}
}

func TestTranslateTaskFanoutPerTarget(t *testing.T) {
	calls, err := TranslateTask(spec(t, "detect.scan.web", []string{"a.acme.com", "b.acme.com"}, nil))
	if err != nil {
		t.Fatalf("TranslateTask: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("got %d calls, want 2 (one per target)", len(calls))
	}
	if calls[0].Target != "a.acme.com" || calls[1].Target != "b.acme.com" {
		t.Errorf("targets not fanned out in order: %+v", calls)
	}
}

func TestTranslateTaskParamOverrides(t *testing.T) {
	calls, err := TranslateTask(spec(t, "detect.scan.api", []string{"https://api.acme.com"}, map[string]any{
		"instruction": "Focus on BOLA and broken authentication.",
		"scan_mode":   "deep",
	}))
	if err != nil {
		t.Fatalf("TranslateTask: %v", err)
	}
	if calls[0].Instruction != "Focus on BOLA and broken authentication." {
		t.Errorf("instruction override not applied: %q", calls[0].Instruction)
	}
	if calls[0].ScanMode != "deep" {
		t.Errorf("scan_mode override not applied: %q", calls[0].ScanMode)
	}

	// An invalid scan_mode is a translation error, not a silent default.
	if _, err := TranslateTask(spec(t, "detect.scan.api", []string{"https://api.acme.com"}, map[string]any{
		"scan_mode": "ludicrous",
	})); err == nil || !strings.Contains(err.Error(), "invalid scan_mode") {
		t.Errorf("invalid scan_mode must be refused, got %v", err)
	}

	// Unknown params must NOT leak into the scan request. ScanRequest has no
	// free-form args at all, so the leak check is that translation ignores
	// them without error.
	calls, err = TranslateTask(spec(t, "detect.scan.web", []string{"https://acme.com"}, map[string]any{
		"evil_arg": "rm -rf /",
	}))
	if err != nil {
		t.Fatalf("TranslateTask: %v", err)
	}
	if strings.Contains(calls[0].Instruction, "rm -rf") {
		t.Errorf("unknown param leaked into the instruction: %q", calls[0].Instruction)
	}
}

func TestTranslateTaskRefusals(t *testing.T) {
	if _, err := TranslateTask(spec(t, "redteam.api_probe", []string{"acme.com"}, nil)); err == nil {
		t.Error("unmapped capability must be refused, not improvised")
	} else if !strings.Contains(err.Error(), "no Strix scan mapping") {
		t.Errorf("unexpected refusal message: %v", err)
	}
	if _, err := TranslateTask(spec(t, "detect.scan.web", nil, nil)); err == nil {
		t.Error("target-less task must be refused")
	}
	if _, err := TranslateTask(nil); err == nil {
		t.Error("nil spec must be refused")
	}
}

func TestMapResultStatusFolding(t *testing.T) {
	s := spec(t, "detect.scan.web", []string{"a.acme.com", "b.acme.com"}, nil)
	calls, err := TranslateTask(s)
	if err != nil {
		t.Fatalf("TranslateTask: %v", err)
	}
	start := time.Unix(1754000000, 0).UTC()
	end := start.Add(3 * time.Second)

	mkOK := func(findings ...strixcli.Finding) *strixcli.ScanResult {
		return &strixcli.ScanResult{Success: true, Mock: true, Note: "mock", Findings: findings}
	}

	// All success → SUCCEEDED with honest targets_touched and finding counts.
	res := MapResult(s, calls,
		[]*strixcli.ScanResult{
			mkOK(strixcli.Finding{ID: "VULN-001", Title: "SQLi", Severity: "high", Target: "a.acme.com"}),
			mkOK(),
		},
		[]error{nil, nil}, start, end)
	if res.GetStatus() != platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED {
		t.Errorf("status = %v, want SUCCEEDED", res.GetStatus())
	}
	if got := res.GetMetrics().GetTargetsTouched(); len(got) != 2 || got[0] != "a.acme.com" {
		t.Errorf("targets_touched = %v", got)
	}
	if res.GetMetrics().GetRequestsSent() != 2 {
		t.Errorf("requests_sent = %d, want 2", res.GetMetrics().GetRequestsSent())
	}
	if res.GetAgentId() != ExecutorID {
		t.Errorf("agent_id = %q, want %q", res.GetAgentId(), ExecutorID)
	}
	if res.GetError() != "" {
		t.Errorf("error = %q, want empty", res.GetError())
	}
	sum := res.GetSummary().AsMap()
	if sum["finding_count"] != float64(1) {
		t.Errorf("finding_count = %v, want 1", sum["finding_count"])
	}
	sev := sum["severity_counts"].(map[string]any)
	if sev["high"] != float64(1) {
		t.Errorf("severity_counts = %v, want high:1", sev)
	}

	// One scan-level failure → FAILED with the failing target named.
	res = MapResult(s, calls,
		[]*strixcli.ScanResult{mkOK(), {Success: false, Note: "strix crashed"}},
		[]error{nil, nil}, start, end)
	if res.GetStatus() != platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED {
		t.Errorf("status = %v, want FAILED", res.GetStatus())
	}
	if !strings.Contains(res.GetError(), "b.acme.com") {
		t.Errorf("error %q should name the failing target", res.GetError())
	}

	// A transport error is a failure too.
	res = MapResult(s, calls,
		[]*strixcli.ScanResult{mkOK(), nil},
		[]error{nil, fakeErr("boom")}, start, end)
	if res.GetStatus() != platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED {
		t.Errorf("status = %v, want FAILED", res.GetStatus())
	}
}

type fakeErr string

func (e fakeErr) Error() string { return string(e) }

// The ledger gate: the adapter's only "authorization" input is the
// Orchestrator's verdict.
func TestLedgerGate(t *testing.T) {
	l := NewLedger()
	s := spec(t, "detect.scan.web", []string{"acme.com"}, nil)
	plan := &platformv1.TaskPlan{
		PlanId:    "pln_test",
		MissionId: "msn_test",
		Tasks:     []*platformv1.TaskSpec{s},
	}

	// Before any submission: refused.
	if _, _, ok := l.Approved("pln_test", "t1"); ok {
		t.Fatal("unknown plan must be refused")
	}

	// Rejected task: refused, with the reason.
	l.Record(plan, &platformv1.SubmitTaskPlanResponse{
		Decision:     platformv1.PlanDecision_PLAN_DECISION_REJECTED,
		TaskVerdicts: []*platformv1.TaskVerdict{{TaskKey: "t1", Accepted: false, Reason: "target excluded by RoE"}},
	})
	_, refusal, ok := l.Approved("pln_test", "t1")
	if ok {
		t.Fatal("rejected task must be refused")
	}
	if !strings.Contains(refusal, "NOT accepted") || !strings.Contains(refusal, "target excluded by RoE") {
		t.Errorf("refusal should carry the verdict reason, got: %s", refusal)
	}

	// Accepted task: allowed, and returns the spec.
	l.Record(plan, &platformv1.SubmitTaskPlanResponse{
		Decision:     platformv1.PlanDecision_PLAN_DECISION_ACCEPTED,
		TaskVerdicts: []*platformv1.TaskVerdict{{TaskKey: "t1", Accepted: true}},
	})
	got, _, ok := l.Approved("pln_test", "t1")
	if !ok {
		t.Fatal("accepted task must be approved")
	}
	if got.GetCapability() != "detect.scan.web" {
		t.Errorf("spec capability = %q", got.GetCapability())
	}

	// Unknown task_key in a known plan: refused.
	if _, _, ok := l.Approved("pln_test", "nope"); ok {
		t.Fatal("unknown task_key must be refused")
	}
}
