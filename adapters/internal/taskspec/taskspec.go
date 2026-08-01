// Package taskspec holds the shared translation from commander-side JSON
// shapes into the platform TaskPlan contract (proto aegisbastion.platform.v1;
// doc 01 §5.2). Both adapters build plans through BuildPlan so validation
// and field semantics stay identical across commanders.
package taskspec

import (
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"

	"github.com/aegisbastion/aegisbastion/adapters/internal/ids"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// ParseRiskClass converts the wire string ("R0".."R3") to the proto enum.
// The zero value RISK_CLASS_UNSPECIFIED is never valid for a real task
// (types.proto), so an unknown string is an error, not a default.
func ParseRiskClass(s string) (platformv1.RiskClass, error) {
	switch s {
	case "R0":
		return platformv1.RiskClass_RISK_CLASS_R0, nil
	case "R1":
		return platformv1.RiskClass_RISK_CLASS_R1, nil
	case "R2":
		return platformv1.RiskClass_RISK_CLASS_R2, nil
	case "R3":
		return platformv1.RiskClass_RISK_CLASS_R3, nil
	default:
		return platformv1.RiskClass_RISK_CLASS_UNSPECIFIED,
			fmt.Errorf("invalid risk_class %q (want R0|R1|R2|R3)", s)
	}
}

// FormatRiskClass renders the enum as its wire string.
func FormatRiskClass(rc platformv1.RiskClass) string {
	switch rc {
	case platformv1.RiskClass_RISK_CLASS_R0:
		return "R0"
	case platformv1.RiskClass_RISK_CLASS_R1:
		return "R1"
	case platformv1.RiskClass_RISK_CLASS_R2:
		return "R2"
	case platformv1.RiskClass_RISK_CLASS_R3:
		return "R3"
	default:
		return "UNSPECIFIED"
	}
}

// FormatDecision renders a PlanDecision as its doc 01 §7.2 token.
func FormatDecision(d platformv1.PlanDecision) string {
	switch d {
	case platformv1.PlanDecision_PLAN_DECISION_ACCEPTED:
		return "ACCEPTED"
	case platformv1.PlanDecision_PLAN_DECISION_PARTIAL:
		return "PARTIAL"
	case platformv1.PlanDecision_PLAN_DECISION_REJECTED:
		return "REJECTED"
	default:
		return "UNSPECIFIED"
	}
}

// TaskSpecJSON is the JSON form of one TaskSpec as commander adapters accept
// it (doc 01 §5.2's JSON representation, wire-exact field names).
type TaskSpecJSON struct {
	TaskKey    string         `json:"task_key"`
	Capability string         `json:"capability"`
	RiskClass  string         `json:"risk_class"`
	Targets    []string       `json:"targets"`
	Params     map[string]any `json:"params"`
	DependsOn  []string       `json:"depends_on"`
	TimeoutS   uint32         `json:"timeout_s"`
	MaxRetries uint32         `json:"max_retries"`
}

// PlanJSON is the JSON form of a plan submission.
type PlanJSON struct {
	MissionID      string         `json:"mission_id"`
	IdempotencyKey string         `json:"idempotency_key"`
	DelegatedBy    string         `json:"delegated_by"`
	Tasks          []TaskSpecJSON `json:"tasks"`
}

// BuildPlan validates a PlanJSON and builds the wire TaskPlan. Validation is
// schema-level only (required fields, unique task_keys, depends_on referential
// integrity, risk-class syntax): adapters are thin — all policy lives in the
// Orchestrator/gatekeeper (doc 01 §7.1). An empty planID mints a fresh
// "pln_" ULID; the CAI stub passes its deterministic id instead.
func BuildPlan(commander platformv1.Commander, planID string, args *PlanJSON) (*platformv1.TaskPlan, error) {
	if args.MissionID == "" {
		return nil, fmt.Errorf("mission_id is required")
	}
	if len(args.Tasks) == 0 {
		return nil, fmt.Errorf("tasks must contain at least one task")
	}
	seen := map[string]bool{}
	tasks := make([]*platformv1.TaskSpec, 0, len(args.Tasks))
	for i, t := range args.Tasks {
		if t.TaskKey == "" {
			return nil, fmt.Errorf("tasks[%d]: task_key is required", i)
		}
		if seen[t.TaskKey] {
			return nil, fmt.Errorf("tasks[%d]: duplicate task_key %q", i, t.TaskKey)
		}
		seen[t.TaskKey] = true
		if t.Capability == "" {
			return nil, fmt.Errorf("tasks[%d] (%s): capability is required", i, t.TaskKey)
		}
		rc, err := ParseRiskClass(t.RiskClass)
		if err != nil {
			return nil, fmt.Errorf("tasks[%d] (%s): %v", i, t.TaskKey, err)
		}
		var params *structpb.Struct
		if t.Params != nil {
			params, err = structpb.NewStruct(t.Params)
			if err != nil {
				return nil, fmt.Errorf("tasks[%d] (%s): params: %v", i, t.TaskKey, err)
			}
		}
		tasks = append(tasks, &platformv1.TaskSpec{
			TaskKey:    t.TaskKey,
			Capability: t.Capability,
			RiskClass:  rc,
			Targets:    t.Targets,
			Params:     params,
			DependsOn:  t.DependsOn,
			TimeoutS:   t.TimeoutS,
			MaxRetries: t.MaxRetries,
		})
	}
	// DAG sanity: every depends_on edge must reference a known task_key.
	// (Cycle detection is the Orchestrator's job; the adapter stays thin.)
	for _, t := range tasks {
		for _, dep := range t.GetDependsOn() {
			if !seen[dep] {
				return nil, fmt.Errorf("task %q depends on unknown task_key %q", t.GetTaskKey(), dep)
			}
		}
	}

	if planID == "" {
		planID = ids.NewULID("pln")
	}
	idem := args.IdempotencyKey
	if idem == "" {
		idem = fmt.Sprintf("%s:%s:plan:%s", commanderTag(commander), args.MissionID, ids.NewULID(""))
	}
	return &platformv1.TaskPlan{
		PlanId:         planID,
		MissionId:      args.MissionID,
		SubmittedBy:    commander,
		DelegatedBy:    args.DelegatedBy,
		IdempotencyKey: idem,
		Tasks:          tasks,
	}, nil
}

// commanderTag is the doc 01 §5.2 submitted_by token.
func commanderTag(c platformv1.Commander) string {
	switch c {
	case platformv1.Commander_COMMANDER_CAI:
		return "cai"
	case platformv1.Commander_COMMANDER_HEXSTRIKE:
		return "hexstrike"
	default:
		return "unknown"
	}
}
