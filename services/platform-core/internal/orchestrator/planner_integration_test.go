package orchestrator

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/pep"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// Doc 01 §6.1 steps 3–5: plan intake validates each TaskSpec (capability,
// risk, RoE scope with exclusions winning), queues valid tasks, strips
// unauthorized ones with reasons, and is idempotent on idempotency_key.
func TestPlanner_SubmitTaskPlan_ValidationAndIdempotency(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	// Agent offering only detect.scan (R2) — other capabilities unregistered.
	e.seedAgent(t, "detect", "detect.scan", store.RiskR2, 4, false)

	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), allowROE())
	svc := NewPlannerService(o)

	plan := &platformv1.TaskPlan{
		MissionId:      m.MissionID,
		SubmittedBy:    platformv1.Commander_COMMANDER_HEXSTRIKE,
		IdempotencyKey: "itest:planner:1",
		Tasks: []*platformv1.TaskSpec{
			{TaskKey: "ok", Capability: "detect.scan", RiskClass: platformv1.RiskClass_RISK_CLASS_R2,
				Targets: []string{"api.acme.com"}, TimeoutS: 300},
			{TaskKey: "unregistered", Capability: "redteam.api_probe", RiskClass: platformv1.RiskClass_RISK_CLASS_R3,
				Targets: []string{"api.acme.com"}},
			{TaskKey: "excluded", Capability: "detect.scan", RiskClass: platformv1.RiskClass_RISK_CLASS_R2,
				Targets: []string{"status.acme.com"}}, // exclusion must win over wildcard include
			{TaskKey: "out-of-scope", Capability: "detect.scan", RiskClass: platformv1.RiskClass_RISK_CLASS_R2,
				Targets: []string{"evil.example.net"}},
		},
	}
	resp, err := svc.SubmitTaskPlan(ctx, &platformv1.SubmitTaskPlanRequest{Plan: plan})
	if err != nil {
		t.Fatalf("SubmitTaskPlan: %v", err)
	}
	if resp.GetDecision() != platformv1.PlanDecision_PLAN_DECISION_PARTIAL {
		t.Fatalf("decision = %s, want PARTIAL", resp.GetDecision())
	}
	verdicts := map[string]*platformv1.TaskVerdict{}
	for _, v := range resp.GetTaskVerdicts() {
		verdicts[v.GetTaskKey()] = v
	}
	if !verdicts["ok"].GetAccepted() {
		t.Errorf("valid task must be accepted: %v", verdicts["ok"].GetReason())
	}
	if verdicts["unregistered"].GetAccepted() {
		t.Error("unregistered capability must be stripped")
	}
	if verdicts["excluded"].GetAccepted() {
		t.Error("excluded target must be stripped (exclusions always win)")
	}
	if verdicts["out-of-scope"].GetAccepted() {
		t.Error("out-of-scope target must be stripped")
	}

	// Accepted task is QUEUED with a decision-audited plan.
	rows, err := e.st.Pool.Query(ctx,
		`SELECT task_key, state FROM platform.tasks WHERE mission_id = $1`, m.MissionID)
	if err != nil {
		t.Fatalf("tasks query: %v", err)
	}
	defer rows.Close()
	states := map[string]string{}
	for rows.Next() {
		var k, s string
		if err := rows.Scan(&k, &s); err != nil {
			t.Fatalf("scan: %v", err)
		}
		states[k] = s
	}
	if states["ok"] != store.TaskQueued {
		t.Errorf("ok task state = %s, want QUEUED", states["ok"])
	}
	for _, k := range []string{"unregistered", "excluded", "out-of-scope"} {
		if states[k] != store.TaskRejectedUnauthorized {
			t.Errorf("%s state = %s, want REJECTED_UNAUTHORIZED", k, states[k])
		}
	}

	// Idempotent replay returns the stored verdict without duplicating tasks.
	resp2, err := svc.SubmitTaskPlan(ctx, &platformv1.SubmitTaskPlanRequest{Plan: plan})
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if resp2.GetDecision() != resp.GetDecision() || len(resp2.GetTaskVerdicts()) != 4 {
		t.Fatalf("idempotent replay mismatch: %s / %d verdicts", resp2.GetDecision(), len(resp2.GetTaskVerdicts()))
	}
	var n int
	if err := e.st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM platform.tasks WHERE mission_id = $1`, m.MissionID).Scan(&n); err != nil || n != 4 {
		t.Fatalf("task count after replay = %d, want 4 (no duplicates)", n)
	}
}

// Commander risk bound (doc 01 §4.1): CAI may not propose R3.
func TestPlanner_CAICannotProposeR3(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	// Mission owned by CAI.
	if err := e.st.Pool.QueryRow(ctx,
		`UPDATE platform.missions SET owning_commander = 'cai' WHERE mission_id = $1 RETURNING mission_id`,
		m.MissionID).Scan(&m.MissionID); err != nil {
		t.Fatalf("update commander: %v", err)
	}
	m.OwningCommander = "cai"
	e.seedAgent(t, "ai-red-team", "redteam.api_probe", store.RiskR3, 1, true)

	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), allowROE())
	svc := NewPlannerService(o)

	resp, err := svc.SubmitTaskPlan(ctx, &platformv1.SubmitTaskPlanRequest{Plan: &platformv1.TaskPlan{
		MissionId:      m.MissionID,
		SubmittedBy:    platformv1.Commander_COMMANDER_CAI,
		IdempotencyKey: "itest:planner:cai-r3",
		Tasks: []*platformv1.TaskSpec{{
			TaskKey: "r3", Capability: "redteam.api_probe",
			RiskClass: platformv1.RiskClass_RISK_CLASS_R3, Targets: []string{"api.acme.com"},
		}},
	}})
	if err != nil {
		t.Fatalf("SubmitTaskPlan: %v", err)
	}
	if resp.GetDecision() != platformv1.PlanDecision_PLAN_DECISION_REJECTED {
		t.Fatalf("CAI R3 plan must be REJECTED, got %s", resp.GetDecision())
	}
}

// Delegation (doc 01 §4.2 rule 1): the non-owning commander needs
// delegated_by = owner.
func TestPlanner_DelegationRule(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive) // owned by hexstrike
	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), allowROE())
	svc := NewPlannerService(o)

	_, err := svc.SubmitTaskPlan(ctx, &platformv1.SubmitTaskPlanRequest{Plan: &platformv1.TaskPlan{
		MissionId:      m.MissionID,
		SubmittedBy:    platformv1.Commander_COMMANDER_CAI,
		IdempotencyKey: "itest:planner:delegation",
		Tasks: []*platformv1.TaskSpec{{
			TaskKey: "x", Capability: "detect.scan",
			RiskClass: platformv1.RiskClass_RISK_CLASS_R1, Targets: []string{"acme.com"},
		}},
	}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("undelegated cross-commander plan must be PermissionDenied, got %v", err)
	}
}
