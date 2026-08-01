// Package registry implements the AgentService gRPC surface (doc 01 §5.8,
// §8.3): Register / Heartbeat / AckTask / ReportProgress / ReportResult /
// StreamTasks, backed by the platform.agents registry store.
package registry

import (
	"context"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/orchestrator"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/pep"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// Service is the AgentService server. The Orchestrator reference is needed
// for AckTask/ReportResult state transitions and the StreamTasks broker.
type Service struct {
	platformv1.UnimplementedAgentServiceServer
	st *store.Store
	o  *orchestrator.Orchestrator
}

// New builds the registry service.
func New(st *store.Store, o *orchestrator.Orchestrator) *Service {
	return &Service{st: st, o: o}
}

// Register upserts an agent manifest (doc 01 §9 item 1): first registration
// assigns agent_id; re-registration on version change keeps the identity.
// Quarantined/revoked agents are refused (doc 01 §10.5).
func (s *Service) Register(ctx context.Context, req *platformv1.RegisterRequest) (*platformv1.RegisterResponse, error) {
	m := req.GetManifest()
	if m == nil {
		return nil, status.Error(codes.InvalidArgument, "manifest is required")
	}
	agentType := agentTypeString(m.GetAgentType())
	if agentType == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_type is required")
	}
	if m.GetIdentity().GetSpiffeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "identity.spiffe_id is required (mTLS identity binding)")
	}
	if len(m.GetCapabilities()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "at least one capability is required")
	}
	if m.GetVersion() == "" {
		return nil, status.Error(codes.InvalidArgument, "version is required")
	}
	caps := make([]store.Capability, 0, len(m.GetCapabilities()))
	for _, c := range m.GetCapabilities() {
		risk := pep.RiskFromProto(c.GetRiskClassMax())
		if c.GetName() == "" || risk == "" {
			return nil, status.Errorf(codes.InvalidArgument,
				"capability %q needs name and risk_class_max", c.GetName())
		}
		caps = append(caps, store.Capability{
			Name:          c.GetName(),
			RiskClassMax:  risk,
			SchemaVersion: c.GetSchemaVersion(),
		})
	}

	agentID := m.GetAgentId()
	if agentID == "" {
		agentID = ids.New("agent")
	}
	a := &store.Agent{
		AgentID:       agentID,
		AgentType:     agentType,
		Version:       m.GetVersion(),
		BuildHash:     m.GetBuildHash(),
		Capabilities:  caps,
		SpiffeID:      m.GetIdentity().GetSpiffeId(),
		MaxConcurrent: int(m.GetLimits().GetMaxConcurrentTasks()),
		Region:        m.GetRegion(),
		Sandboxed:     m.GetSandboxed(),
	}
	if err := s.st.RegisterAgent(ctx, a); err != nil {
		return nil, status.Errorf(codes.Internal, "register: %v", err)
	}
	if a.Status == store.AgentQuarantined || a.Status == store.AgentRevoked {
		return nil, status.Errorf(codes.PermissionDenied,
			"agent %s is %s — contact an operator", a.AgentID, a.Status)
	}
	return &platformv1.RegisterResponse{AgentId: a.AgentID}, nil
}

// Heartbeat records liveness (10 s cadence; 30 s TTL) and returns whether a
// kill switch is active for this agent (doc 01 §10.5).
func (s *Service) Heartbeat(ctx context.Context, req *platformv1.HeartbeatRequest) (*platformv1.HeartbeatResponse, error) {
	if req.GetAgentId() == "" {
		return nil, status.Error(codes.InvalidArgument, "agent_id is required")
	}
	a, err := s.st.TouchHeartbeat(ctx, req.GetAgentId())
	if err == store.ErrNotFound {
		return nil, status.Errorf(codes.NotFound,
			"agent %s unknown or blocked — re-register", req.GetAgentId())
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "heartbeat: %v", err)
	}
	kills, err := s.st.KillSwitchesEngaged(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "kill switches: %v", err)
	}
	killActive := kills[store.KillScopeGlobal+"/"] || kills[store.KillScopeAgent+"/"+a.AgentID]
	return &platformv1.HeartbeatResponse{KillActive: killActive}, nil
}

// AckTask transitions DISPATCHED → RUNNING (doc 01 §9 item 3: ACK within
// 10 s or the task redelivers).
func (s *Service) AckTask(ctx context.Context, req *platformv1.AckTaskRequest) (*platformv1.AckTaskResponse, error) {
	t, err := s.st.GetTask(ctx, req.GetTaskId())
	if err == store.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "task %s not found", req.GetTaskId())
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	if t.AssignedAgentID != req.GetAgentId() {
		return nil, status.Errorf(codes.PermissionDenied,
			"task %s is not assigned to agent %s", t.TaskID, req.GetAgentId())
	}
	if t.State == store.TaskRunning {
		return &platformv1.AckTaskResponse{Acked: true}, nil // idempotent re-ACK
	}
	if t.State != store.TaskDispatched {
		return nil, status.Errorf(codes.FailedPrecondition,
			"task %s is %s, cannot ACK", t.TaskID, t.State)
	}
	if err := s.st.Transition(ctx, t.TaskID, []string{store.TaskDispatched}, store.TaskRunning,
		req.GetAgentId(), "agent ACK", store.TaskField{Column: "started_at", Value: time.Now().UTC()}); err != nil {
		return nil, status.Errorf(codes.Internal, "ack: %v", err)
	}
	return &platformv1.AckTaskResponse{Acked: true}, nil
}

// ReportProgress forwards progress to mission.events (commander visibility).
func (s *Service) ReportProgress(ctx context.Context, req *platformv1.ReportProgressRequest) (*platformv1.ReportProgressResponse, error) {
	t, err := s.st.GetTask(ctx, req.GetTaskId())
	if err == store.ErrNotFound {
		return nil, status.Errorf(codes.NotFound, "task %s not found", req.GetTaskId())
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}
	if t.AssignedAgentID != req.GetAgentId() {
		return nil, status.Errorf(codes.PermissionDenied, "task not assigned to this agent")
	}
	detail := map[string]any{"agent_id": req.GetAgentId()}
	if req.GetProgress() != nil {
		detail["progress"] = req.GetProgress().AsMap()
	}
	s.o.EmitMissionEvent(ctx, t.MissionID, "TASK_PROGRESS", t.TaskID, detail)
	return &platformv1.ReportProgressResponse{Recorded: true}, nil
}

// ReportResult applies the terminal result (idempotent on task_id).
func (s *Service) ReportResult(ctx context.Context, req *platformv1.ReportResultRequest) (*platformv1.ReportResultResponse, error) {
	res := req.GetResult()
	if res == nil || res.GetTaskId() == "" {
		return nil, status.Error(codes.InvalidArgument, "result.task_id is required")
	}
	if err := s.o.HandleResult(ctx, res); err != nil {
		return nil, status.Errorf(codes.Internal, "report result: %v", err)
	}
	return &platformv1.ReportResultResponse{Recorded: true}, nil
}

// StreamTasks is the long-poll assignment transport (doc 01 §8.3): same
// TaskAssignment payload as the bus path.
func (s *Service) StreamTasks(req *platformv1.StreamTasksRequest, stream platformv1.AgentService_StreamTasksServer) error {
	agentID := req.GetAgentId()
	if agentID == "" {
		return status.Error(codes.InvalidArgument, "agent_id is required")
	}
	a, err := s.st.GetAgent(stream.Context(), agentID)
	if err == store.ErrNotFound {
		return status.Errorf(codes.NotFound, "agent %s not registered", agentID)
	}
	if err != nil {
		return status.Errorf(codes.Internal, "%v", err)
	}
	if a.Status != store.AgentOnline {
		return status.Errorf(codes.PermissionDenied, "agent %s is %s", agentID, a.Status)
	}
	ch, unsub := s.o.SubscribeAssignments(agentID)
	defer unsub()
	for {
		select {
		case <-stream.Context().Done():
			return nil
		case assignment, ok := <-ch:
			if !ok {
				return nil
			}
			if err := stream.Send(&platformv1.StreamTasksResponse{Assignment: assignment}); err != nil {
				return err
			}
		}
	}
}

func agentTypeString(t platformv1.AgentType) string {
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
