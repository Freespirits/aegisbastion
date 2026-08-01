package orchestrator

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/pep"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// PlannerService implements platformv1.PlannerServiceServer — the
// commander-facing gRPC surface (doc 01 §7.2). Adapters are thin; ALL policy
// lives here and in gatekeeper.
type PlannerService struct {
	platformv1.UnimplementedPlannerServiceServer
	o *Orchestrator
}

// NewPlannerService builds the service.
func NewPlannerService(o *Orchestrator) *PlannerService { return &PlannerService{o: o} }

// commanderName maps the proto enum to the DB string.
func commanderName(c platformv1.Commander) string {
	switch c {
	case platformv1.Commander_COMMANDER_CAI:
		return "cai"
	case platformv1.Commander_COMMANDER_HEXSTRIKE:
		return "hexstrike"
	case platformv1.Commander_COMMANDER_STRIX:
		return "strix"
	case platformv1.Commander_COMMANDER_PENTESTGPT:
		return "pentestgpt"
	}
	return ""
}

// commanderMaxRisk bounds what a commander may propose (doc 01 §4.1):
// CAI R0–R2, HexStrike R0–R3; Strix (R1 recon + R2 detect) and PentestGPT
// (R0 recon + R1/R2 detect) both sit in the CAI band, R0–R2.
func commanderMaxRisk(commander string) int {
	switch commander {
	case "cai", "strix", "pentestgpt":
		return store.RiskRank(store.RiskR2)
	case "hexstrike":
		return store.RiskRank(store.RiskR3)
	}
	// Fail-closed: an unknown commander gets the tightest bound, never the
	// widest. Unknown names are already rejected at plan intake
	// (commanderName → InvalidArgument), so this is defense in depth.
	return store.RiskRank(store.RiskR0)
}

type taskVerdict struct {
	TaskKey  string `json:"task_key"`
	Accepted bool   `json:"accepted"`
	Reason   string `json:"reason,omitempty"`
}

// SubmitTaskPlan validates and intakes a commander plan (doc 01 §6.1 steps
// 3–5): idempotent on idempotency_key; per-task validation; accepted tasks
// are queued, rejected tasks return with reasons for replanning.
func (s *PlannerService) SubmitTaskPlan(ctx context.Context, req *platformv1.SubmitTaskPlanRequest) (*platformv1.SubmitTaskPlanResponse, error) {
	o := s.o
	plan := req.GetPlan()
	if plan == nil {
		return nil, status.Error(codes.InvalidArgument, "plan is required")
	}
	commander := commanderName(plan.GetSubmittedBy())
	if plan.GetMissionId() == "" || commander == "" || plan.GetIdempotencyKey() == "" {
		return nil, status.Error(codes.InvalidArgument, "mission_id, submitted_by and idempotency_key are required")
	}
	if len(plan.GetTasks()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "plan has no tasks")
	}

	mission, err := o.store.GetMission(ctx, plan.GetMissionId())
	if err == store.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "mission %s not found", plan.GetMissionId())
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load mission: %v", err)
	}
	if mission.State != store.MissionActive {
		return nil, status.Errorf(codes.FailedPrecondition,
			"mission %s is %s — plans only accepted for ACTIVE missions", mission.MissionID, mission.State)
	}
	// Ownership / delegation (doc 01 §4.2 rule 1).
	if commander != mission.OwningCommander && plan.GetDelegatedBy() != mission.OwningCommander {
		return nil, status.Errorf(codes.PermissionDenied,
			"mission is owned by %s; %s plans require delegated_by=%s",
			mission.OwningCommander, commander, mission.OwningCommander)
	}

	// RoE (fail-closed, doc 01 §10.1 plan validation): transient gatekeeper
	// errors surface as Unavailable so the commander retries the same
	// idempotency key — no plan row is written yet.
	roe, err := o.ROE(ctx, mission)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "plan validation requires gatekeeper RoE: %v", err)
	}
	if !roe.Active(time.Now()) {
		return nil, status.Errorf(codes.FailedPrecondition,
			"RoE %s v%d is not active/in-window", mission.RoeID, mission.RoeVersion)
	}

	// Idempotent intake (doc 01 §5.2).
	planID := plan.GetPlanId()
	if planID == "" {
		planID = ids.New("pln")
	}
	row := &store.Plan{
		PlanID: planID, MissionID: mission.MissionID, SubmittedBy: commander,
		DelegatedBy: plan.GetDelegatedBy(), IdempotencyKey: plan.GetIdempotencyKey(),
	}
	existed, err := o.store.InsertPlan(ctx, row)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "insert plan: %v", err)
	}
	if existed {
		return verdictFromRow(row)
	}

	// Commander quota (doc 01 §4.2 rule 4).
	inFlight, err := o.store.CountInFlightByCommander(ctx, commander)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "commander quota: %v", err)
	}

	// Validate the DAG shape first.
	keys := map[string]bool{}
	for _, t := range plan.GetTasks() {
		if t.GetTaskKey() == "" {
			return nil, status.Error(codes.InvalidArgument, "every task needs a task_key")
		}
		if keys[t.GetTaskKey()] {
			return nil, status.Errorf(codes.InvalidArgument, "duplicate task_key %q", t.GetTaskKey())
		}
		keys[t.GetTaskKey()] = true
	}

	verdicts := make([]taskVerdict, 0, len(plan.GetTasks()))
	accepted := 0
	budget := o.cfg.CommanderQuota - inFlight
	for _, spec := range plan.GetTasks() {
		reason := s.validateTask(ctx, spec, keys, roe, commander)
		if reason == "" && accepted >= budget {
			reason = fmt.Sprintf("commander in-flight quota %d exceeded", o.cfg.CommanderQuota)
		}
		v := taskVerdict{TaskKey: spec.GetTaskKey(), Accepted: reason == "", Reason: reason}
		verdicts = append(verdicts, v)
		if err := s.persistTask(ctx, row, mission, spec, v); err != nil {
			return nil, status.Errorf(codes.Internal, "persist task %q: %v", spec.GetTaskKey(), err)
		}
		if v.Accepted {
			accepted++
		}
	}

	decision := platformv1.PlanDecision_PLAN_DECISION_REJECTED
	switch {
	case accepted == len(plan.GetTasks()):
		decision = platformv1.PlanDecision_PLAN_DECISION_ACCEPTED
	case accepted > 0:
		decision = platformv1.PlanDecision_PLAN_DECISION_PARTIAL
	}
	if err := o.store.SavePlanVerdict(ctx, row.PlanID, decisionName(decision), detailJSON(verdicts)); err != nil {
		return nil, status.Errorf(codes.Internal, "save verdict: %v", err)
	}
	if err := o.AuditLog(ctx, audit.PlanSubmitted,
		audit.Subject{MissionID: mission.MissionID, RoeID: mission.RoeID},
		map[string]any{
			"plan_id":      row.PlanID,
			"submitted_by": commander,
			"decision":     decisionName(decision),
			"tasks_total":  len(plan.GetTasks()),
			"tasks_queued": accepted,
		}); err != nil {
		o.log.Error("audit PLAN_SUBMITTED", "err", err)
	}

	return &platformv1.SubmitTaskPlanResponse{
		Decision:     decision,
		TaskVerdicts: toProtoVerdicts(verdicts),
	}, nil
}

// validateTask runs doc 01 §6.1 step 4 for one spec. "" means accepted.
func (s *PlannerService) validateTask(ctx context.Context, spec *platformv1.TaskSpec, keys map[string]bool, roe *roeRecord, commander string) string {
	capability := spec.GetCapability()
	risk := pep.RiskFromProto(spec.GetRiskClass())
	if capability == "" || risk == "" {
		return "capability and risk_class are required"
	}
	// capability must exist in the registry (doc 01 §9 item 2).
	exists, riskMax, err := s.o.store.CapabilityExists(ctx, capability)
	if err != nil {
		return "registry lookup failed"
	}
	if !exists {
		return fmt.Sprintf("capability %q not registered", capability)
	}
	if store.RiskRank(risk) > store.RiskRank(riskMax) {
		return fmt.Sprintf("risk %s exceeds capability ceiling %s", risk, riskMax)
	}
	// commander risk bound (doc 01 §4.1).
	if store.RiskRank(risk) > commanderMaxRisk(commander) {
		return fmt.Sprintf("commander %s may not propose %s", commander, risk)
	}
	// risk class ≤ RoE max (doc 01 §6.1 step 4).
	if store.RiskRank(risk) > store.RiskRank(roe.MaxRiskClass) {
		return fmt.Sprintf("risk %s exceeds RoE max %s", risk, roe.MaxRiskClass)
	}
	// capability ∈ RoE allowed_capabilities.
	if !roe.AllowsCapability(capability) {
		return fmt.Sprintf("capability %q not allowed by RoE", capability)
	}
	// every target ∈ scope ∧ ∉ exclusions (exclusions win).
	if err := roe.Scope.CheckAll(spec.GetTargets()); err != nil {
		return err.Error()
	}
	// dependencies must reference known keys.
	for _, dep := range spec.GetDependsOn() {
		if !keys[dep] {
			return fmt.Sprintf("unknown dependency %q", dep)
		}
	}
	return ""
}

// persistTask writes a validated task and walks it PENDING → VALIDATING →
// QUEUED (accepted) or → REJECTED_UNAUTHORIZED (stripped, doc 01 §4.2 rule
// 2).
func (s *PlannerService) persistTask(ctx context.Context, plan *store.Plan, mission *store.Mission, spec *platformv1.TaskSpec, v taskVerdict) error {
	o := s.o
	params := []byte(`{}`)
	if spec.GetParams() != nil {
		if b, err := spec.GetParams().MarshalJSON(); err == nil {
			params = b
		}
	}
	t := &store.Task{
		TaskID:     ids.New("tsk"),
		PlanID:     plan.PlanID,
		MissionID:  mission.MissionID,
		TaskKey:    spec.GetTaskKey(),
		Capability: spec.GetCapability(),
		RiskClass:  pep.RiskFromProto(spec.GetRiskClass()),
		Targets:    spec.GetTargets(),
		Params:     params,
		DependsOn:  spec.GetDependsOn(),
		TimeoutS:   int(spec.GetTimeoutS()),
		MaxRetries: int(spec.GetMaxRetries()),
		State:      store.TaskPending,
	}
	if t.TimeoutS <= 0 {
		t.TimeoutS = 900
	}
	if err := o.store.InsertTask(ctx, t); err != nil {
		return err
	}
	if err := o.transition(ctx, t, []string{store.TaskPending}, store.TaskValidating, "plan intake"); err != nil {
		return err
	}
	if v.Accepted {
		return o.transition(ctx, t, []string{store.TaskValidating}, store.TaskQueued, "validation passed")
	}
	return o.transition(ctx, t, []string{store.TaskValidating}, store.TaskRejectedUnauthorized, v.Reason,
		store.TaskField{Column: "rejection_reason", Value: v.Reason})
}

// GetMissionStatus returns the commander's point-in-time view (doc 01 §7.2).
func (s *PlannerService) GetMissionStatus(ctx context.Context, req *platformv1.GetMissionStatusRequest) (*platformv1.GetMissionStatusResponse, error) {
	missionID := req.GetMission().GetMissionId()
	mission, err := s.o.store.GetMission(ctx, missionID)
	if err == store.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "mission %s not found", missionID)
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	counts, err := s.o.store.TaskCountsByState(ctx, missionID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	protoCounts := map[string]uint32{}
	var inFlight uint32
	for st, n := range counts {
		protoCounts[st] = uint32(n)
		if !store.TerminalStates[st] {
			inFlight += uint32(n)
		}
	}
	return &platformv1.GetMissionStatusResponse{
		Status: &platformv1.MissionStatus{
			Mission:       missionToProto(mission),
			TaskCounts:    protoCounts,
			InFlightTasks: inFlight,
		},
	}, nil
}

// StreamMissionEvents streams the mission.events broker (doc 01 §6.5:
// event-driven replanning, not polling).
func (s *PlannerService) StreamMissionEvents(req *platformv1.StreamMissionEventsRequest, stream platformv1.PlannerService_StreamMissionEventsServer) error {
	missionID := req.GetMission().GetMissionId()
	if _, err := s.o.store.GetMission(stream.Context(), missionID); err != nil {
		return status.Errorf(codes.NotFound, "mission %s not found", missionID)
	}
	ch, unsub := s.o.SubscribeMissionEvents(missionID)
	defer unsub()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case ev, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(&platformv1.StreamMissionEventsResponse{Event: ev}); err != nil {
				return err
			}
		}
	}
}

// ListCapabilities returns the live registry view (doc 01 §7.2).
func (s *PlannerService) ListCapabilities(ctx context.Context, req *platformv1.ListCapabilitiesRequest) (*platformv1.ListCapabilitiesResponse, error) {
	all, err := s.o.store.RegisteredCapabilities(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	q := req.GetQuery()
	out := []*platformv1.RegisteredCapability{}
	for _, entries := range all {
		for _, e := range entries {
			if q.GetNamePrefix() != "" && len(e.Capability.Name) >= len(q.GetNamePrefix()) {
				if e.Capability.Name[:len(q.GetNamePrefix())] != q.GetNamePrefix() {
					continue
				}
			} else if q.GetNamePrefix() != "" {
				continue
			}
			if q.GetMaxRiskClass() != platformv1.RiskClass_RISK_CLASS_UNSPECIFIED &&
				store.RiskRank(e.Capability.RiskClassMax) > store.RiskRank(pep.RiskFromProto(q.GetMaxRiskClass())) {
				continue
			}
			out = append(out, &platformv1.RegisteredCapability{
				Capability: &platformv1.Capability{
					Name:          e.Capability.Name,
					RiskClassMax:  pep.RiskToProto(e.Capability.RiskClassMax),
					SchemaVersion: e.Capability.SchemaVersion,
				},
				AgentType: agentTypeToProto(e.AgentType),
			})
		}
	}
	return &platformv1.ListCapabilitiesResponse{Capabilities: out}, nil
}

// RequestScopeChange routes scope changes to the operator approval queue —
// NEVER auto-granted (doc 01 §7.2).
func (s *PlannerService) RequestScopeChange(ctx context.Context, req *platformv1.RequestScopeChangeRequest) (*platformv1.RequestScopeChangeResponse, error) {
	mission, err := s.o.store.GetMission(ctx, req.GetMissionId())
	if err == store.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "mission %s not found", req.GetMissionId())
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	s.o.EmitMissionEvent(ctx, mission.MissionID, "SCOPE_CHANGE_REQUESTED", "", map[string]any{
		"requested_by":        commanderName(req.GetRequestedBy()),
		"justification":       req.GetJustification(),
		"requested_additions": anySlice(req.GetRequestedAdditions()),
		"requested_removals":  anySlice(req.GetRequestedRemovals()),
		"status":              "queued_for_operator",
	})
	return &platformv1.RequestScopeChangeResponse{Queued: true}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func verdictFromRow(row *store.Plan) (*platformv1.SubmitTaskPlanResponse, error) {
	var verdicts []taskVerdict
	_ = json.Unmarshal(row.VerdictDetail, &verdicts)
	return &platformv1.SubmitTaskPlanResponse{
		Decision:     decisionFromName(row.Verdict),
		TaskVerdicts: toProtoVerdicts(verdicts),
	}, nil
}

func toProtoVerdicts(vs []taskVerdict) []*platformv1.TaskVerdict {
	out := make([]*platformv1.TaskVerdict, 0, len(vs))
	for _, v := range vs {
		out = append(out, &platformv1.TaskVerdict{
			TaskKey:  v.TaskKey,
			Accepted: v.Accepted,
			Reason:   v.Reason,
		})
	}
	return out
}

func decisionName(d platformv1.PlanDecision) string {
	switch d {
	case platformv1.PlanDecision_PLAN_DECISION_ACCEPTED:
		return "ACCEPTED"
	case platformv1.PlanDecision_PLAN_DECISION_PARTIAL:
		return "PARTIAL"
	default:
		return "REJECTED"
	}
}

func decisionFromName(s string) platformv1.PlanDecision {
	switch s {
	case "ACCEPTED":
		return platformv1.PlanDecision_PLAN_DECISION_ACCEPTED
	case "PARTIAL":
		return platformv1.PlanDecision_PLAN_DECISION_PARTIAL
	default:
		return platformv1.PlanDecision_PLAN_DECISION_REJECTED
	}
}

func missionToProto(m *store.Mission) *platformv1.Mission {
	return &platformv1.Mission{
		MissionId:       m.MissionID,
		Name:            m.Name,
		OwningCommander: commanderToProto(m.OwningCommander),
		Objective:       m.Objective,
		RoeId:           m.RoeID,
		RoeVersion:      uint64(m.RoeVersion),
		Priority:        priorityToProto(m.Priority),
		Labels:          m.Labels,
		CreatedBy:       m.CreatedBy,
		State:           missionStateToProto(m.State),
	}
}

func commanderToProto(c string) platformv1.Commander {
	switch c {
	case "cai":
		return platformv1.Commander_COMMANDER_CAI
	case "hexstrike":
		return platformv1.Commander_COMMANDER_HEXSTRIKE
	case "strix":
		return platformv1.Commander_COMMANDER_STRIX
	case "pentestgpt":
		return platformv1.Commander_COMMANDER_PENTESTGPT
	}
	return platformv1.Commander_COMMANDER_UNSPECIFIED
}

func priorityToProto(p string) platformv1.Priority {
	switch p {
	case "P0_KILL":
		return platformv1.Priority_PRIORITY_P0_KILL
	case "P1_OPERATOR":
		return platformv1.Priority_PRIORITY_P1_OPERATOR
	case "P2_CHANGE":
		return platformv1.Priority_PRIORITY_P2_CHANGE
	case "P3_PLANNED":
		return platformv1.Priority_PRIORITY_P3_PLANNED
	case "P4_BACKGROUND":
		return platformv1.Priority_PRIORITY_P4_BACKGROUND
	}
	return platformv1.Priority_PRIORITY_UNSPECIFIED
}

func missionStateToProto(s string) platformv1.MissionState {
	switch s {
	case store.MissionDraft:
		return platformv1.MissionState_MISSION_STATE_DRAFT
	case store.MissionActive:
		return platformv1.MissionState_MISSION_STATE_ACTIVE
	case store.MissionPaused:
		return platformv1.MissionState_MISSION_STATE_PAUSED
	case store.MissionCompleted:
		return platformv1.MissionState_MISSION_STATE_COMPLETED
	case store.MissionPlannerDegraded:
		return platformv1.MissionState_MISSION_STATE_PLANNER_DEGRADED
	case store.MissionKilled:
		return platformv1.MissionState_MISSION_STATE_KILLED
	}
	return platformv1.MissionState_MISSION_STATE_UNSPECIFIED
}

func agentTypeToProto(t string) platformv1.AgentType {
	switch t {
	case "discover":
		return platformv1.AgentType_AGENT_TYPE_DISCOVER
	case "monitor":
		return platformv1.AgentType_AGENT_TYPE_MONITOR
	case "detect":
		return platformv1.AgentType_AGENT_TYPE_DETECT
	case "alert":
		return platformv1.AgentType_AGENT_TYPE_ALERT
	case "ddos":
		return platformv1.AgentType_AGENT_TYPE_DDOS_ENGINE
	case "phishcatcher":
		return platformv1.AgentType_AGENT_TYPE_PHISH_CATCHER
	case "ai-red-team":
		return platformv1.AgentType_AGENT_TYPE_AI_RED_TEAM
	}
	return platformv1.AgentType_AGENT_TYPE_UNSPECIFIED
}

func agentTypeFromProto(t platformv1.AgentType) string {
	switch t {
	case platformv1.AgentType_AGENT_TYPE_DISCOVER:
		return "discover"
	case platformv1.AgentType_AGENT_TYPE_MONITOR:
		return "monitor"
	case platformv1.AgentType_AGENT_TYPE_DETECT:
		return "detect"
	case platformv1.AgentType_AGENT_TYPE_ALERT:
		return "alert"
	case platformv1.AgentType_AGENT_TYPE_DDOS_ENGINE:
		return "ddos"
	case platformv1.AgentType_AGENT_TYPE_PHISH_CATCHER:
		return "phishcatcher"
	case platformv1.AgentType_AGENT_TYPE_AI_RED_TEAM:
		return "ai-red-team"
	}
	return ""
}
