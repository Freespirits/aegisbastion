// Package echoplanner is the minimal deterministic commander stub used for
// testing (doc 01 §14: "CAI adapter stubbed behind the same PlannerAPI"; the
// real commanders are adapters/hexstrike-mcp and adapters/cai). It reacts to
// MISSION_ACTIVATED mission events by submitting one deterministic plan
// through PlannerService.SubmitTaskPlan — the same contract every commander
// uses (commanders propose; the Orchestrator disposes).
package echoplanner

import (
	"context"
	"log/slog"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/structpb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// PlannerClient is the subset of the generated PlannerService client the
// stub needs (the generated client satisfies it; LocalAdapter adapts the
// in-process server for serve mode).
type PlannerClient interface {
	SubmitTaskPlan(ctx context.Context, in *platformv1.SubmitTaskPlanRequest, opts ...grpc.CallOption) (*platformv1.SubmitTaskPlanResponse, error)
	GetMissionStatus(ctx context.Context, in *platformv1.GetMissionStatusRequest, opts ...grpc.CallOption) (*platformv1.GetMissionStatusResponse, error)
}

// LocalAdapter exposes an in-process PlannerService server as a
// PlannerClient (no network) for serve mode.
type LocalAdapter struct {
	Srv platformv1.PlannerServiceServer
}

// SubmitTaskPlan calls the server directly.
func (a *LocalAdapter) SubmitTaskPlan(ctx context.Context, in *platformv1.SubmitTaskPlanRequest, _ ...grpc.CallOption) (*platformv1.SubmitTaskPlanResponse, error) {
	return a.Srv.SubmitTaskPlan(ctx, in)
}

// GetMissionStatus calls the server directly.
func (a *LocalAdapter) GetMissionStatus(ctx context.Context, in *platformv1.GetMissionStatusRequest, _ ...grpc.CallOption) (*platformv1.GetMissionStatusResponse, error) {
	return a.Srv.GetMissionStatus(ctx, in)
}

// Stub is the echo planner.
type Stub struct {
	client     PlannerClient
	capability string
	targets    []string
	risk       platformv1.RiskClass
	log        *slog.Logger
}

// New builds a stub that plans one task with the given capability/targets.
// Deterministic: idempotency key and task_key derive from the mission id.
func New(client PlannerClient, capability string, targets []string, risk platformv1.RiskClass, log *slog.Logger) *Stub {
	if log == nil {
		log = slog.Default()
	}
	return &Stub{client: client, capability: capability, targets: targets, risk: risk, log: log}
}

// OnMissionActivated submits the stub's deterministic plan for a freshly
// activated mission.
func (s *Stub) OnMissionActivated(ctx context.Context, missionID string) error {
	statusResp, err := s.client.GetMissionStatus(ctx, &platformv1.GetMissionStatusRequest{
		Mission: &platformv1.MissionRef{MissionId: missionID},
	})
	if err != nil {
		return err
	}
	owner := statusResp.GetStatus().GetMission().GetOwningCommander()
	params, _ := structpb.NewStruct(map[string]any{"echo": true})
	plan := &platformv1.TaskPlan{
		MissionId:      missionID,
		SubmittedBy:    owner,
		IdempotencyKey: "echo:" + missionID + ":plan:1",
		Tasks: []*platformv1.TaskSpec{{
			TaskKey:    "echo-1",
			Capability: s.capability,
			RiskClass:  s.risk,
			Targets:    s.targets,
			Params:     params,
			TimeoutS:   300,
			MaxRetries: 1,
		}},
	}
	resp, err := s.client.SubmitTaskPlan(ctx, &platformv1.SubmitTaskPlanRequest{Plan: plan})
	if err != nil {
		return err
	}
	s.log.Info("echo plan submitted",
		"mission", missionID, "decision", resp.GetDecision().String())
	return nil
}

// HandleMissionEvent routes broker events; only activations trigger plans.
func (s *Stub) HandleMissionEvent(ctx context.Context, ev *platformv1.MissionEvent) {
	if ev.GetKind() != "MISSION_ACTIVATED" {
		return
	}
	if err := s.OnMissionActivated(ctx, ev.GetMissionId()); err != nil {
		s.log.Error("echo plan failed", "mission", ev.GetMissionId(), "err", err)
	}
}
