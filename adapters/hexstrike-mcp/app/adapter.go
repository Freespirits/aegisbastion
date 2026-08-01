package app

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/hx"
	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/mcp"
	"github.com/aegisbastion/aegisbastion/adapters/internal/taskspec"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// rpcTimeout bounds PlannerService calls from tool handlers.
const rpcTimeout = 30 * time.Second

// defaultTaskTimeoutS applies when a task spec omits timeout_s.
const defaultTaskTimeoutS = 900

// Deps are the adapter's external dependencies, injected so tests can wire
// the adapter to a bufconn PlannerService and the mock HexStrike client.
type Deps struct {
	// Planner is the client side of aegisbastion.platform.v1.PlannerService.
	Planner platformv1.PlannerServiceClient
	// HX invokes HexStrike tools (mock by default).
	HX hx.Client
	// Ledger records Orchestrator verdicts; the execution gate.
	Ledger *Ledger
	// Now is the clock (tests inject a fixed one).
	Now func() time.Time
}

// RegisterTools exposes the doc 01 §7.1 tool surface on the MCP server:
// submit_task_plan, get_mission_status, list_capabilities,
// request_scope_change — plus execute_approved_task, which translates an
// Orchestrator-accepted task into HexStrike MCP tool calls and maps the
// results back to a TaskResult.
func RegisterTools(s *mcp.Server, d *Deps) {
	s.RegisterTool(mcp.Tool{
		Name: "submit_task_plan",
		Description: "Submit a TaskPlan (DAG of TaskSpecs) for a mission to the AegisBastion Orchestrator. " +
			"Returns the PlanVerdict: ACCEPTED | PARTIAL | REJECTED with per-task verdicts. The adapter only " +
			"proposes — the Orchestrator and gatekeeper decide; unauthorized tasks are stripped or rejected.",
		InputSchema: submitPlanSchema,
	}, d.submitTaskPlan)

	s.RegisterTool(mcp.Tool{
		Name: "get_mission_status",
		Description: "Point-in-time mission view: mission record, task counts by state, in-flight count " +
			"(commander quota accounting).",
		InputSchema: objectSchema(map[string]any{
			"mission_id": stringProp("Mission ULID, e.g. msn_01J8ZK…"),
		}, "mission_id"),
	}, d.getMissionStatus)

	s.RegisterTool(mcp.Tool{
		Name: "list_capabilities",
		Description: "Live view of capabilities registered in the Agent Registry. Optional filters: " +
			"name_prefix (substring) and max_risk_class (R0..R3 ceiling).",
		InputSchema: objectSchema(map[string]any{
			"name_prefix":    stringProp("Substring filter on capability name"),
			"max_risk_class": enumProp("Only capabilities with risk_class_max ≤ this", "R0", "R1", "R2", "R3"),
		}),
	}, d.listCapabilities)

	s.RegisterTool(mcp.Tool{
		Name: "request_scope_change",
		Description: "Ask an operator to widen/narrow the mission's RoE scope. Routed to the operator " +
			"approval queue — NEVER auto-granted (doc 01 §7.2).",
		InputSchema: objectSchema(map[string]any{
			"mission_id":          stringProp("Mission ULID"),
			"justification":       stringProp("Human-readable justification shown to the operator"),
			"requested_additions": stringArrayProp("Proposed scope additions (domains, CIDRs, …)"),
			"requested_removals":  stringArrayProp("Proposed scope removals"),
		}, "mission_id", "justification"),
	}, d.requestScopeChange)

	s.RegisterTool(mcp.Tool{
		Name: "execute_approved_task",
		Description: "Translate one Orchestrator-ACCEPTED task (by plan_id + task_key from a prior " +
			"submit_task_plan verdict) into HexStrike MCP tool calls and return the TaskResult. Refuses any " +
			"task the Orchestrator did not accept: the adapter is a planner, not an authorizer.",
		InputSchema: objectSchema(map[string]any{
			"plan_id":  stringProp("Plan ULID returned by submit_task_plan"),
			"task_key": stringProp("task_key within that plan"),
		}, "plan_id", "task_key"),
	}, d.executeApprovedTask)
}

// ---------------------------------------------------------------------------
// submit_task_plan
// ---------------------------------------------------------------------------

type taskVerdictOut struct {
	TaskKey  string `json:"task_key"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

type submitPlanOut struct {
	PlanID       string           `json:"plan_id"`
	Decision     string           `json:"decision"`
	TaskVerdicts []taskVerdictOut `json:"task_verdicts"`
}

func (d *Deps) submitTaskPlan(_ *mcp.CallContext, raw json.RawMessage) (any, error) {
	var args taskspec.PlanJSON
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	plan, err := taskspec.BuildPlan(platformv1.Commander_COMMANDER_HEXSTRIKE, "", &args)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	resp, err := d.Planner.SubmitTaskPlan(ctx, &platformv1.SubmitTaskPlanRequest{Plan: plan})
	if err != nil {
		return nil, fmt.Errorf("planner SubmitTaskPlan: %v", err)
	}
	d.Ledger.Record(plan, resp)

	out := submitPlanOut{
		PlanID:   plan.GetPlanId(),
		Decision: taskspec.FormatDecision(resp.GetDecision()),
	}
	for _, v := range resp.GetTaskVerdicts() {
		out.TaskVerdicts = append(out.TaskVerdicts, taskVerdictOut{
			TaskKey:  v.GetTaskKey(),
			Accepted: v.GetAccepted(),
			Reason:   v.GetReason(),
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// get_mission_status / list_capabilities / request_scope_change
// ---------------------------------------------------------------------------

func (d *Deps) getMissionStatus(_ *mcp.CallContext, raw json.RawMessage) (any, error) {
	var args struct {
		MissionID string `json:"mission_id"`
	}
	if err := json.Unmarshal(raw, &args); err != nil || args.MissionID == "" {
		return nil, fmt.Errorf("mission_id is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	resp, err := d.Planner.GetMissionStatus(ctx, &platformv1.GetMissionStatusRequest{
		Mission: &platformv1.MissionRef{MissionId: args.MissionID},
	})
	if err != nil {
		return nil, fmt.Errorf("planner GetMissionStatus: %v", err)
	}
	return toJSON(resp)
}

func (d *Deps) listCapabilities(_ *mcp.CallContext, raw json.RawMessage) (any, error) {
	var args struct {
		NamePrefix   string `json:"name_prefix"`
		MaxRiskClass string `json:"max_risk_class"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	query := &platformv1.CapabilityQuery{NamePrefix: args.NamePrefix}
	if args.MaxRiskClass != "" {
		rc, err := taskspec.ParseRiskClass(args.MaxRiskClass)
		if err != nil {
			return nil, err
		}
		query.MaxRiskClass = rc
	}
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	resp, err := d.Planner.ListCapabilities(ctx, &platformv1.ListCapabilitiesRequest{Query: query})
	if err != nil {
		return nil, fmt.Errorf("planner ListCapabilities: %v", err)
	}
	return toJSON(resp)
}

func (d *Deps) requestScopeChange(_ *mcp.CallContext, raw json.RawMessage) (any, error) {
	var args struct {
		MissionID          string   `json:"mission_id"`
		Justification      string   `json:"justification"`
		RequestedAdditions []string `json:"requested_additions"`
		RequestedRemovals  []string `json:"requested_removals"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	if args.MissionID == "" || args.Justification == "" {
		return nil, fmt.Errorf("mission_id and justification are required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), rpcTimeout)
	defer cancel()
	resp, err := d.Planner.RequestScopeChange(ctx, &platformv1.RequestScopeChangeRequest{
		MissionId:          args.MissionID,
		RequestedBy:        platformv1.Commander_COMMANDER_HEXSTRIKE,
		Justification:      args.Justification,
		RequestedAdditions: args.RequestedAdditions,
		RequestedRemovals:  args.RequestedRemovals,
	})
	if err != nil {
		return nil, fmt.Errorf("planner RequestScopeChange: %v", err)
	}
	return map[string]any{"queued": resp.GetQueued()}, nil
}

// ---------------------------------------------------------------------------
// execute_approved_task
// ---------------------------------------------------------------------------

func (d *Deps) executeApprovedTask(_ *mcp.CallContext, raw json.RawMessage) (any, error) {
	var args struct {
		PlanID  string `json:"plan_id"`
		TaskKey string `json:"task_key"`
	}
	if err := json.Unmarshal(raw, &args); err != nil {
		return nil, fmt.Errorf("invalid arguments: %v", err)
	}
	if args.PlanID == "" || args.TaskKey == "" {
		return nil, fmt.Errorf("plan_id and task_key are required")
	}

	// THE GATE: only Orchestrator-accepted tasks may be translated into tool
	// calls. This is the adapter's enforcement that it is a planner, not an
	// authorizer.
	spec, refusal, ok := d.Ledger.Approved(args.PlanID, args.TaskKey)
	if !ok {
		return nil, fmt.Errorf("execute_approved_task refused: %s", refusal)
	}
	calls, err := TranslateTask(spec)
	if err != nil {
		return nil, err
	}

	timeout := time.Duration(spec.GetTimeoutS()) * time.Second
	if timeout <= 0 {
		timeout = defaultTaskTimeoutS * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	started := d.Now()
	results := make([]map[string]any, len(calls))
	callErrs := make([]error, len(calls))
	for i, call := range calls {
		results[i], callErrs[i] = d.HX.CallTool(ctx, call.Endpoint, call.Args)
		if ctx.Err() != nil {
			// Stop fanning out once the task deadline is hit; remaining calls
			// are recorded as failures by the timeout.
			for j := i + 1; j < len(calls); j++ {
				callErrs[j] = ctx.Err()
			}
			break
		}
	}
	finished := d.Now()

	result := MapResult(spec, calls, results, callErrs, started, finished)
	return toJSON(result)
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// toJSON renders a proto message as generic JSON (protojson semantics:
// snake_case fields, enum names) so MCP/REST callers see the doc 01 wire
// shapes rather than Go struct formatting.
func toJSON(m proto.Message) (any, error) {
	raw, err := protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(m)
	if err != nil {
		return nil, fmt.Errorf("encode response: %v", err)
	}
	var out any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("encode response: %v", err)
	}
	return out, nil
}

// JSON-schema helpers for tool declarations.

func stringProp(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func enumProp(desc string, values ...string) map[string]any {
	return map[string]any{"type": "string", "description": desc, "enum": values}
}

func stringArrayProp(desc string) map[string]any {
	return map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": desc}
}

func objectSchema(props map[string]any, required ...string) map[string]any {
	return map[string]any{
		"type":       "object",
		"properties": props,
		"required":   required,
	}
}

var submitPlanSchema = objectSchema(map[string]any{
	"mission_id":      stringProp("Mission ULID this plan belongs to"),
	"idempotency_key": stringProp("Optional commander-scoped idempotency key, e.g. hexstrike:msn_01J8ZK:plan:7"),
	"delegated_by":    stringProp("Owning commander id when this is a delegated sub-plan"),
	"tasks": map[string]any{
		"type":        "array",
		"description": "The task DAG. Every task needs task_key, capability, risk_class, targets.",
		"items": objectSchema(map[string]any{
			"task_key":    stringProp("Unique within the plan; depended on by other tasks"),
			"capability":  stringProp("Registered capability name, e.g. detect.scan.web"),
			"risk_class":  enumProp("Declared risk class", "R0", "R1", "R2", "R3"),
			"targets":     stringArrayProp("Concrete targets; must match RoE scope (enforced downstream)"),
			"params":      map[string]any{"type": "object", "description": "Capability-specific parameters"},
			"depends_on":  stringArrayProp("task_keys this task depends on"),
			"timeout_s":   map[string]any{"type": "integer", "description": "Per-task timeout in seconds"},
			"max_retries": map[string]any{"type": "integer", "description": "Max redeliveries before DEAD"},
		}, "task_key", "capability", "risk_class", "targets"),
	},
}, "mission_id", "tasks")
