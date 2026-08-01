package app

import (
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

func testIntent() Intent {
	return Intent{
		MissionID: "msn_01J8ZKTEST",
		Objective: "map acme.com attack surface",
		Targets:   []string{"acme.com", "*.acme.com"},
	}
}

// The stub contract: same intent → byte-identical plan (ids included);
// replays are idempotent.
func TestStubPlannerDeterministic(t *testing.T) {
	p := StubPlanner{}
	a, err := p.PlanMission(testIntent())
	if err != nil {
		t.Fatalf("PlanMission: %v", err)
	}
	b, err := p.PlanMission(testIntent())
	if err != nil {
		t.Fatalf("PlanMission: %v", err)
	}
	if !proto.Equal(a, b) {
		t.Fatalf("same intent produced different plans:\nA: %v\nB: %v", a, b)
	}
	// Target ordering in the request must not change the plan.
	shuffled := testIntent()
	shuffled.Targets = []string{"*.acme.com", "acme.com"}
	c, err := p.PlanMission(shuffled)
	if err != nil {
		t.Fatalf("PlanMission: %v", err)
	}
	if !proto.Equal(a, c) {
		t.Fatalf("target order changed the plan:\nA: %v\nC: %v", a, c)
	}
	// A different intent must produce a different plan id (no collisions).
	other := testIntent()
	other.MissionID = "msn_01J8ZKOTHER"
	d, err := p.PlanMission(other)
	if err != nil {
		t.Fatalf("PlanMission: %v", err)
	}
	if d.GetPlanId() == a.GetPlanId() || d.GetIdempotencyKey() == a.GetIdempotencyKey() {
		t.Fatalf("different intents produced identical ids")
	}
}

func TestStubPlanShape(t *testing.T) {
	plan, err := StubPlanner{}.PlanMission(testIntent())
	if err != nil {
		t.Fatalf("PlanMission: %v", err)
	}

	if got := plan.GetSubmittedBy(); got != platformv1.Commander_COMMANDER_CAI {
		t.Errorf("submitted_by = %v, want COMMANDER_CAI", got)
	}
	if !strings.HasPrefix(plan.GetPlanId(), "pln_caistub_") {
		t.Errorf("plan_id %q lacks the stub marker prefix", plan.GetPlanId())
	}
	if !strings.HasPrefix(plan.GetIdempotencyKey(), "cai:msn_01J8ZKTEST:plan:") {
		t.Errorf("idempotency_key %q malformed", plan.GetIdempotencyKey())
	}
	if plan.GetDelegatedBy() != "" {
		t.Errorf("delegated_by should be empty for an owner-submitted plan, got %q", plan.GetDelegatedBy())
	}

	wantKeys := []string{
		"discover-passive-dns",
		"discover-ct",
		"discover-subdomain-passive",
		"discover-ip-netblock",
		"discover-cloud-credentialed",
	}
	if len(plan.GetTasks()) != len(wantKeys) {
		t.Fatalf("got %d tasks, want %d", len(plan.GetTasks()), len(wantKeys))
	}
	keys := map[string]bool{}
	for i, task := range plan.GetTasks() {
		if task.GetTaskKey() != wantKeys[i] {
			t.Errorf("tasks[%d] key = %q, want %q (fixed passive order)", i, task.GetTaskKey(), wantKeys[i])
		}
		keys[task.GetTaskKey()] = true

		// Every stub task is R0 passive — the stub must never propose
		// target-contact work.
		if task.GetRiskClass() != platformv1.RiskClass_RISK_CLASS_R0 {
			t.Errorf("task %s risk_class = %v, want R0", task.GetTaskKey(), task.GetRiskClass())
		}
		// Stub marker must be explicit in every task.
		f := task.GetParams().GetFields()
		if !f["stub"].GetBoolValue() {
			t.Errorf("task %s missing stub=true marker", task.GetTaskKey())
		}
		if f["generator"].GetStringValue() != StubGenerator {
			t.Errorf("task %s generator = %q, want %q", task.GetTaskKey(), f["generator"].GetStringValue(), StubGenerator)
		}
		if !strings.Contains(f["plan_note"].GetStringValue(), "STUB PLAN") {
			t.Errorf("task %s plan_note does not clearly mark the stub", task.GetTaskKey())
		}
		// DAG integrity.
		for _, dep := range task.GetDependsOn() {
			if !keys[dep] && dep != wantKeys[0] {
				t.Errorf("task %s depends on unknown/later task %q", task.GetTaskKey(), dep)
			}
		}
		if task.GetTimeoutS() == 0 {
			t.Errorf("task %s timeout_s must be set", task.GetTaskKey())
		}
	}
}

func TestStubPlannerValidation(t *testing.T) {
	p := StubPlanner{}
	if _, err := p.PlanMission(Intent{Targets: []string{"acme.com"}}); err == nil {
		t.Error("missing mission_id should fail")
	}
	if _, err := p.PlanMission(Intent{MissionID: "msn_x"}); err == nil {
		t.Error("empty targets should fail")
	}
}

func TestNewPlannerModes(t *testing.T) {
	if _, err := NewPlanner("stub"); err != nil {
		t.Errorf("stub mode should construct: %v", err)
	}
	if _, err := NewPlanner("http"); err == nil {
		t.Error("unknown mode must fail fast, not silently run the stub")
	}
	if _, err := NewPlanner(""); err == nil {
		t.Error("empty mode must fail fast")
	}
}
