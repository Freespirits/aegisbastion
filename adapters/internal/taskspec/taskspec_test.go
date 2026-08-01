package taskspec

import (
	"strings"
	"testing"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

func TestRiskClassRoundTrip(t *testing.T) {
	for _, s := range []string{"R0", "R1", "R2", "R3"} {
		rc, err := ParseRiskClass(s)
		if err != nil {
			t.Fatalf("ParseRiskClass(%s): %v", s, err)
		}
		if FormatRiskClass(rc) != s {
			t.Errorf("round trip %s → %s", s, FormatRiskClass(rc))
		}
	}
	if _, err := ParseRiskClass("R4"); err == nil {
		t.Error("R4 must be rejected")
	}
	if _, err := ParseRiskClass(""); err == nil {
		t.Error("empty risk class must be rejected (UNSPECIFIED is never valid on the wire)")
	}
}

func TestBuildPlanHappyPath(t *testing.T) {
	plan, err := BuildPlan(platformv1.Commander_COMMANDER_CAI, "", &PlanJSON{
		MissionID: "msn_1",
		Tasks: []TaskSpecJSON{
			{TaskKey: "a", Capability: "recon.ct", RiskClass: "R0", Targets: []string{"acme.com"}},
			{TaskKey: "b", Capability: "recon.passive_dns", RiskClass: "R0", Targets: []string{"acme.com"}, DependsOn: []string{"a"}},
		},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if !strings.HasPrefix(plan.GetPlanId(), "pln_") {
		t.Errorf("plan_id = %q", plan.GetPlanId())
	}
	if plan.GetSubmittedBy() != platformv1.Commander_COMMANDER_CAI {
		t.Errorf("submitted_by = %v", plan.GetSubmittedBy())
	}
	if !strings.HasPrefix(plan.GetIdempotencyKey(), "cai:msn_1:plan:") {
		t.Errorf("idempotency_key = %q", plan.GetIdempotencyKey())
	}
	if len(plan.GetTasks()) != 2 || plan.GetTasks()[1].GetDependsOn()[0] != "a" {
		t.Errorf("tasks = %+v", plan.GetTasks())
	}
}

func TestBuildPlanCallerSuppliedIDAndKey(t *testing.T) {
	plan, err := BuildPlan(platformv1.Commander_COMMANDER_HEXSTRIKE, "pln_fixed", &PlanJSON{
		MissionID:      "msn_1",
		IdempotencyKey: "hexstrike:msn_1:plan:7",
		Tasks:          []TaskSpecJSON{{TaskKey: "a", Capability: "recon.ct", RiskClass: "R0", Targets: []string{"x"}}},
	})
	if err != nil {
		t.Fatalf("BuildPlan: %v", err)
	}
	if plan.GetPlanId() != "pln_fixed" || plan.GetIdempotencyKey() != "hexstrike:msn_1:plan:7" {
		t.Errorf("caller-supplied ids not honoured: %q %q", plan.GetPlanId(), plan.GetIdempotencyKey())
	}
}

func TestBuildPlanValidation(t *testing.T) {
	base := TaskSpecJSON{TaskKey: "a", Capability: "recon.ct", RiskClass: "R0", Targets: []string{"x"}}
	cases := []struct {
		name string
		plan PlanJSON
		want string
	}{
		{"no mission", PlanJSON{Tasks: []TaskSpecJSON{base}}, "mission_id"},
		{"no tasks", PlanJSON{MissionID: "m"}, "at least one task"},
		{"no key", PlanJSON{MissionID: "m", Tasks: []TaskSpecJSON{{Capability: "c", RiskClass: "R0"}}}, "task_key"},
		{"dup key", PlanJSON{MissionID: "m", Tasks: []TaskSpecJSON{base, base}}, "duplicate"},
		{"no capability", PlanJSON{MissionID: "m", Tasks: []TaskSpecJSON{{TaskKey: "a", RiskClass: "R0"}}}, "capability"},
		{"bad risk", PlanJSON{MissionID: "m", Tasks: []TaskSpecJSON{{TaskKey: "a", Capability: "c", RiskClass: "T1"}}}, "risk_class"},
		{"dangling dep", PlanJSON{MissionID: "m", Tasks: []TaskSpecJSON{
			base, {TaskKey: "b", Capability: "c", RiskClass: "R0", DependsOn: []string{"ghost"}},
		}}, "unknown task_key"},
	}
	for _, tc := range cases {
		if _, err := BuildPlan(platformv1.Commander_COMMANDER_CAI, "", &tc.plan); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", tc.name, tc.want, err)
		}
	}
}
