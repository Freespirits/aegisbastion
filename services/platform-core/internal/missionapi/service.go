// Package missionapi implements the operator-facing Mission API (doc 01
// §7.3): MissionService gRPC + a REST/JSON gateway. All mutating calls
// require an operator identity and emit audit events. ApproveRoE/RevokeRoE
// are proxied to gatekeeper — the Mission API keeps no RoE state.
package missionapi

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/config"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/gatekeeper"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/orchestrator"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// Service implements platformv1.MissionServiceServer.
type Service struct {
	platformv1.UnimplementedMissionServiceServer
	cfg    *config.Config
	st     *store.Store
	o      *orchestrator.Orchestrator
	roes   gatekeeper.ROEStore
	approv gatekeeper.ApprovalQueue
	audit  *audit.Logger
}

// New builds the Mission API service.
func New(cfg *config.Config, st *store.Store, o *orchestrator.Orchestrator, roes gatekeeper.ROEStore, approv gatekeeper.ApprovalQueue, al *audit.Logger) *Service {
	return &Service{cfg: cfg, st: st, o: o, roes: roes, approv: approv, audit: al}
}

// operatorIdentity extracts the caller identity from gRPC metadata
// (x-operator-id) — the MVP RBAC shim pending gatekeeper rbac-service
// wiring (doc 01 §7.3 requires operator roles on mutating calls).
func (s *Service) checkOperator(ctx context.Context, identity string) error {
	if identity == "" {
		return status.Error(codes.Unauthenticated, "operator identity required (x-operator-id)")
	}
	if !s.cfg.OperatorAllowed(identity) {
		return status.Errorf(codes.PermissionDenied, "identity %q lacks the operator role", identity)
	}
	return nil
}

// CreateMission validates the RoE against gatekeeper (fail-closed, doc 01
// §6.1 step 2) and persists the mission in DRAFT; ResumeMission activates.
func (s *Service) CreateMission(ctx context.Context, req *platformv1.CreateMissionRequest) (*platformv1.CreateMissionResponse, error) {
	if err := s.checkOperator(ctx, req.GetCreatedBy()); err != nil {
		return nil, err
	}
	commander := commanderString(req.GetOwningCommander())
	if req.GetName() == "" || commander == "" || req.GetRoeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "name, owning_commander and roe_id are required")
	}

	// Mission admission (doc 01 §10.1): RoE must exist, be active, in-window.
	if s.roes == nil {
		return nil, status.Error(codes.Unavailable, "gatekeeper client not configured — mission admission is fail-closed")
	}
	roe, err := s.roes.GetROE(ctx, req.GetRoeId(), 0)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "RoE validation against gatekeeper failed (fail-closed): %v", err)
	}
	if roe.GetStatus().String() != "ROE_STATUS_ACTIVE" {
		return nil, status.Errorf(codes.FailedPrecondition, "RoE %s is %s, not ACTIVE", req.GetRoeId(), roe.GetStatus())
	}
	now := time.Now()
	if roe.GetValidFrom() != nil && now.Before(roe.GetValidFrom().AsTime()) {
		return nil, status.Error(codes.FailedPrecondition, "RoE validity window not open yet")
	}
	if roe.GetValidUntil() != nil && now.After(roe.GetValidUntil().AsTime()) {
		return nil, status.Error(codes.FailedPrecondition, "RoE validity window closed")
	}

	m := &store.Mission{
		MissionID:       ids.New("msn"),
		Name:            req.GetName(),
		OwningCommander: commander,
		Objective:       req.GetObjective(),
		RoeID:           req.GetRoeId(),
		RoeVersion:      int(roe.GetVersion()),
		Priority:        priorityString(req.GetPriority()),
		Labels:          req.GetLabels(),
		CreatedBy:       req.GetCreatedBy(),
		State:           store.MissionDraft,
	}
	if err := s.st.CreateMission(ctx, m); err != nil {
		return nil, status.Errorf(codes.Internal, "create mission: %v", err)
	}
	if err := s.audit.Log(ctx, audit.MissionCreated,
		audit.Actor{Kind: "user", ID: req.GetCreatedBy()},
		audit.Subject{MissionID: m.MissionID, RoeID: m.RoeID},
		map[string]any{
			"name":             m.Name,
			"owning_commander": m.OwningCommander,
			"objective":        m.Objective,
			"roe_version":      m.RoeVersion,
			"priority":         m.Priority,
		}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit MISSION_CREATED: %v", err)
	}
	return &platformv1.CreateMissionResponse{Mission: missionProto(m)}, nil
}

// GetMission fetches one mission.
func (s *Service) GetMission(ctx context.Context, req *platformv1.GetMissionRequest) (*platformv1.GetMissionResponse, error) {
	m, err := s.st.GetMission(ctx, req.GetMissionId())
	if err == store.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "mission %s not found", req.GetMissionId())
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &platformv1.GetMissionResponse{Mission: missionProto(m)}, nil
}

// PauseMission halts new dispatches (ACTIVE/PLANNER_DEGRADED → PAUSED).
func (s *Service) PauseMission(ctx context.Context, req *platformv1.PauseMissionRequest) (*platformv1.PauseMissionResponse, error) {
	if err := s.checkOperator(ctx, operatorFromContext(ctx)); err != nil {
		return nil, err
	}
	m, err := s.setState(ctx, req.GetMissionId(), store.MissionPaused,
		[]string{store.MissionActive, store.MissionPlannerDegraded}, "operator pause")
	if err != nil {
		return nil, err
	}
	s.o.EmitMissionEvent(ctx, m.MissionID, "MISSION_PAUSED", "", nil)
	return &platformv1.PauseMissionResponse{Mission: missionProto(m)}, nil
}

// ResumeMission resumes a paused mission — and activates a DRAFT mission
// (doc 01 §6.1: creation → validation → commander notified; activation is
// the explicit operator step that opens plan intake).
func (s *Service) ResumeMission(ctx context.Context, req *platformv1.ResumeMissionRequest) (*platformv1.ResumeMissionResponse, error) {
	if err := s.checkOperator(ctx, operatorFromContext(ctx)); err != nil {
		return nil, err
	}
	before, err := s.st.GetMission(ctx, req.GetMissionId())
	if err == store.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "mission %s not found", req.GetMissionId())
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	m, err := s.setState(ctx, req.GetMissionId(), store.MissionActive,
		[]string{store.MissionPaused, store.MissionDraft}, "operator resume")
	if err != nil {
		return nil, err
	}
	if before.State == store.MissionDraft {
		// Commander notification (doc 01 §6.1 step 2).
		s.o.EmitMissionEvent(ctx, m.MissionID, "MISSION_ACTIVATED", "", map[string]any{
			"owning_commander": m.OwningCommander,
			"roe_id":           m.RoeID,
		})
	} else {
		s.o.EmitMissionEvent(ctx, m.MissionID, "MISSION_RESUMED", "", nil)
	}
	return &platformv1.ResumeMissionResponse{Mission: missionProto(m)}, nil
}

// KillMission engages the per-mission kill switch (doc 01 §10.5).
func (s *Service) KillMission(ctx context.Context, req *platformv1.KillMissionRequest) (*platformv1.KillMissionResponse, error) {
	operator := operatorFromContext(ctx)
	if err := s.checkOperator(ctx, operator); err != nil {
		return nil, err
	}
	if _, err := s.st.GetMission(ctx, req.GetMissionId()); err == store.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "mission %s not found", req.GetMissionId())
	}
	reason := req.GetReason()
	if reason == "" {
		reason = "operator kill"
	}
	if _, err := s.o.KillMission(ctx, req.GetMissionId(), reason, operator); err != nil {
		return nil, status.Errorf(codes.Internal, "kill mission: %v", err)
	}
	m, err := s.st.GetMission(ctx, req.GetMissionId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return &platformv1.KillMissionResponse{Mission: missionProto(m)}, nil
}

// ApproveRoE proxies an approver vote to gatekeeper approval-service (the
// Mission API keeps no RoE state, doc 01 §7.3).
func (s *Service) ApproveRoE(ctx context.Context, req *platformv1.ApproveRoERequest) (*platformv1.ApproveRoEResponse, error) {
	if err := s.checkOperator(ctx, req.GetApprover()); err != nil {
		return nil, err
	}
	if s.approv == nil {
		return nil, status.Error(codes.Unavailable, "gatekeeper client not configured")
	}
	pending, err := s.approv.ListPendingApprovals(ctx, req.GetRoeId())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "approval-service: %v", err)
	}
	if len(pending) == 0 {
		return nil, status.Errorf(codes.FailedPrecondition,
			"no pending approval for RoE %s — request one via gatekeeper approval-service first", req.GetRoeId())
	}
	target := pending[len(pending)-1]
	if req.GetRoeVersion() != 0 && target.GetRoeVersion() != req.GetRoeVersion() {
		return nil, status.Errorf(codes.FailedPrecondition,
			"pending approval %s is for RoE version %d, not %d",
			target.GetApprovalId(), target.GetRoeVersion(), req.GetRoeVersion())
	}
	appr, err := s.approv.RecordApprovalDecision(ctx, target.GetApprovalId(), req.GetApprover(), true)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "record approval decision: %v", err)
	}
	return &platformv1.ApproveRoEResponse{ApprovalId: appr.GetApprovalId()}, nil
}

// RevokeRoE proxies revocation to gatekeeper roe-service; the resulting
// revocation event drives the kill of in-flight tasks (doc 01 §10.5).
func (s *Service) RevokeRoE(ctx context.Context, req *platformv1.RevokeRoERequest) (*platformv1.RevokeRoEResponse, error) {
	if err := s.checkOperator(ctx, operatorFromContext(ctx)); err != nil {
		return nil, err
	}
	if s.roes == nil {
		return nil, status.Error(codes.Unavailable, "gatekeeper client not configured")
	}
	if _, err := s.roes.RevokeROE(ctx, req.GetRoeId(), req.GetReason()); err != nil {
		return nil, status.Errorf(codes.Unavailable, "roe-service.RevokeROE: %v", err)
	}
	if err := s.audit.Log(ctx, audit.ROERevoked,
		audit.Actor{Kind: "user", ID: operatorFromContext(ctx)},
		audit.Subject{RoeID: req.GetRoeId()},
		map[string]any{"reason": req.GetReason(), "proxied_to": "gatekeeper.roe-service"}); err != nil {
		return nil, status.Errorf(codes.Internal, "audit ROE_REVOKED: %v", err)
	}
	return &platformv1.RevokeRoEResponse{Revoked: true}, nil
}

// GetAuditTrail reads the mission's hash-chained audit events (doc 01 §7.3).
func (s *Service) GetAuditTrail(ctx context.Context, req *platformv1.GetAuditTrailRequest) (*platformv1.GetAuditTrailResponse, error) {
	events, err := s.audit.Trail(ctx, req.GetMissionId(), req.GetAfterSeq(), req.GetLimit())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "audit trail: %v", err)
	}
	out := make([]*platformv1.AuditEvent, 0, len(events))
	for _, ev := range events {
		payload, _ := structpb.NewStruct(ev.Payload)
		out = append(out, &platformv1.AuditEvent{
			EventId: ev.EventID,
			Seq:     ev.Seq,
			Ts:      timestamppb.New(ev.TS),
			Type:    auditTypeToProto(ev.Type),
			Actor: &platformv1.AuditActor{
				Kind: ev.Actor.Kind,
				Id:   ev.Actor.ID,
			},
			Subject: &platformv1.AuditSubject{
				MissionId: ev.Subject.MissionID,
				TaskId:    ev.Subject.TaskID,
				RoeId:     ev.Subject.RoeID,
			},
			Payload:  payload,
			PrevHash: ev.PrevHash,
			Hash:     ev.Hash,
		})
	}
	return &platformv1.GetAuditTrailResponse{Events: out}, nil
}

// setState transitions a mission and returns the updated row.
func (s *Service) setState(ctx context.Context, missionID, to string, from []string, reason string) (*store.Mission, error) {
	if err := s.st.SetMissionState(ctx, missionID, to, from...); err != nil {
		if err == store.ErrInvalidTransition {
			return nil, status.Errorf(codes.FailedPrecondition,
				"mission %s cannot transition to %s from its current state", missionID, to)
		}
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	m, err := s.st.GetMission(ctx, missionID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	return m, nil
}

func auditTypeToProto(t audit.EventType) platformv1.AuditEventType {
	switch t {
	case audit.MissionCreated:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_MISSION_CREATED
	case audit.PlanSubmitted:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_PLAN_SUBMITTED
	case audit.AuthzDecision:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_AUTHZ_DECISION
	case audit.TaskDispatched:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_TASK_DISPATCHED
	case audit.TargetTouched:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_TARGET_TOUCHED
	case audit.TaskResult:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_TASK_RESULT
	case audit.ROERevoked:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_ROE_REVOKED
	case audit.KillSwitch:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_KILL_SWITCH
	case audit.ScopeViolation:
		return platformv1.AuditEventType_AUDIT_EVENT_TYPE_SCOPE_VIOLATION
	}
	return platformv1.AuditEventType_AUDIT_EVENT_TYPE_UNSPECIFIED
}

func missionProto(m *store.Mission) *platformv1.Mission {
	return &platformv1.Mission{
		MissionId:       m.MissionID,
		Name:            m.Name,
		OwningCommander: commanderProto(m.OwningCommander),
		Objective:       m.Objective,
		RoeId:           m.RoeID,
		RoeVersion:      uint64(m.RoeVersion),
		Priority:        priorityProto(m.Priority),
		Labels:          m.Labels,
		CreatedBy:       m.CreatedBy,
		CreatedAt:       timestamppb.New(m.CreatedAt),
		State:           missionStateProto(m.State),
	}
}

func commanderString(c platformv1.Commander) string {
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

func commanderProto(c string) platformv1.Commander {
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

func priorityString(p platformv1.Priority) string {
	switch p {
	case platformv1.Priority_PRIORITY_P0_KILL:
		return "P0_KILL"
	case platformv1.Priority_PRIORITY_P1_OPERATOR:
		return "P1_OPERATOR"
	case platformv1.Priority_PRIORITY_P2_CHANGE:
		return "P2_CHANGE"
	case platformv1.Priority_PRIORITY_P3_PLANNED:
		return "P3_PLANNED"
	case platformv1.Priority_PRIORITY_P4_BACKGROUND:
		return "P4_BACKGROUND"
	}
	return "P3_PLANNED"
}

func priorityProto(p string) platformv1.Priority {
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

func missionStateProto(s string) platformv1.MissionState {
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
