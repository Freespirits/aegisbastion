// Package plannerfake is an in-memory implementation of the generated
// aegisbastion.platform.v1.PlannerService server contract, for adapter tests. It
// implements the documented Orchestrator behaviour the adapters depend on
// (doc 01 §6.1 step 4, §7.2): per-task validation (capability registered,
// risk class ≤ capability ceiling, targets present) and ACCEPTED / PARTIAL /
// REJECTED verdicts. It is deliberately strict — coded against the generated
// planner_grpc.pb.go stubs, exactly as the real Orchestrator contract is.
package plannerfake

import (
	"context"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// Server is the fake PlannerService. Safe for concurrent use.
type Server struct {
	platformv1.UnimplementedPlannerServiceServer

	mu           sync.Mutex
	capabilities map[string]platformv1.RiskClass // capability → risk_class_max
	plans        []*platformv1.TaskPlan
	scopeChanges []*platformv1.RequestScopeChangeRequest
}

// New returns a fake pre-loaded with a representative capability registry.
func New() *Server {
	return &Server{
		capabilities: map[string]platformv1.RiskClass{
			"recon.passive_dns":        platformv1.RiskClass_RISK_CLASS_R0,
			"recon.ct":                 platformv1.RiskClass_RISK_CLASS_R0,
			"recon.subdomain_passive":  platformv1.RiskClass_RISK_CLASS_R0,
			"recon.ip_netblock":        platformv1.RiskClass_RISK_CLASS_R0,
			"recon.cloud_credentialed": platformv1.RiskClass_RISK_CLASS_R0,
			"recon.port_scan":          platformv1.RiskClass_RISK_CLASS_R1,
			"web.dirbust":              platformv1.RiskClass_RISK_CLASS_R1,
			"detect.scan.network":      platformv1.RiskClass_RISK_CLASS_R2,
			"detect.scan.web":          platformv1.RiskClass_RISK_CLASS_R2,
			"web.nikto":                platformv1.RiskClass_RISK_CLASS_R2,
			"web.sqlmap":               platformv1.RiskClass_RISK_CLASS_R2,
			"monitor.watch":            platformv1.RiskClass_RISK_CLASS_R1,
		},
	}
}

// Plans returns the plans received so far (submission order).
func (f *Server) Plans() []*platformv1.TaskPlan {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*platformv1.TaskPlan, len(f.plans))
	copy(out, f.plans)
	return out
}

// ScopeChanges returns the scope-change requests received so far.
func (f *Server) ScopeChanges() []*platformv1.RequestScopeChangeRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*platformv1.RequestScopeChangeRequest, len(f.scopeChanges))
	copy(out, f.scopeChanges)
	return out
}

// SubmitTaskPlan implements the doc 01 §7.2 verdict semantics.
func (f *Server) SubmitTaskPlan(_ context.Context, req *platformv1.SubmitTaskPlanRequest) (*platformv1.SubmitTaskPlanResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	plan := req.GetPlan()
	f.plans = append(f.plans, plan)

	resp := &platformv1.SubmitTaskPlanResponse{}
	accepted := 0
	for _, t := range plan.GetTasks() {
		verdict := &platformv1.TaskVerdict{TaskKey: t.GetTaskKey()}
		maxRC, registered := f.capabilities[t.GetCapability()]
		switch {
		case !registered:
			verdict.Reason = "capability not registered"
		case len(t.GetTargets()) == 0:
			verdict.Reason = "no targets"
		case t.GetRiskClass() > maxRC:
			verdict.Reason = "risk class exceeds capability risk_class_max"
		default:
			verdict.Accepted = true
			accepted++
		}
		resp.TaskVerdicts = append(resp.TaskVerdicts, verdict)
	}
	switch {
	case accepted == len(plan.GetTasks()):
		resp.Decision = platformv1.PlanDecision_PLAN_DECISION_ACCEPTED
	case accepted == 0:
		resp.Decision = platformv1.PlanDecision_PLAN_DECISION_REJECTED
	default:
		resp.Decision = platformv1.PlanDecision_PLAN_DECISION_PARTIAL
	}
	return resp, nil
}

// GetMissionStatus returns a canned ACTIVE mission view.
func (f *Server) GetMissionStatus(_ context.Context, req *platformv1.GetMissionStatusRequest) (*platformv1.GetMissionStatusResponse, error) {
	return &platformv1.GetMissionStatusResponse{
		Status: &platformv1.MissionStatus{
			Mission: &platformv1.Mission{
				MissionId: req.GetMission().GetMissionId(),
				Name:      "fake-mission",
				State:     platformv1.MissionState_MISSION_STATE_ACTIVE,
				CreatedAt: timestamppb.New(time.Unix(1754000000, 0).UTC()),
			},
			TaskCounts:    map[string]uint32{"RUNNING": 1},
			InFlightTasks: 1,
		},
	}, nil
}

// ListCapabilities returns the fake registry with the contract's filters.
func (f *Server) ListCapabilities(_ context.Context, req *platformv1.ListCapabilitiesRequest) (*platformv1.ListCapabilitiesResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	q := req.GetQuery()
	resp := &platformv1.ListCapabilitiesResponse{}
	names := make([]string, 0, len(f.capabilities))
	for name := range f.capabilities {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if p := q.GetNamePrefix(); p != "" && !strings.Contains(name, p) {
			continue
		}
		rc := f.capabilities[name]
		if max := q.GetMaxRiskClass(); max != platformv1.RiskClass_RISK_CLASS_UNSPECIFIED && rc > max {
			continue
		}
		resp.Capabilities = append(resp.Capabilities, &platformv1.RegisteredCapability{
			Capability: &platformv1.Capability{
				Name:          name,
				RiskClassMax:  rc,
				SchemaVersion: "v1",
			},
			AgentType: platformv1.AgentType_AGENT_TYPE_DISCOVER,
		})
	}
	return resp, nil
}

// RequestScopeChange records the request and queues it (never grants).
func (f *Server) RequestScopeChange(_ context.Context, req *platformv1.RequestScopeChangeRequest) (*platformv1.RequestScopeChangeResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.scopeChanges = append(f.scopeChanges, req)
	return &platformv1.RequestScopeChangeResponse{Queued: true}, nil
}

// Client serves the fake over an in-process bufconn and returns a real
// platformv1.PlannerServiceClient connected to it — the same generated
// client stub the adapters use in production. cleanup closes everything.
func (f *Server) Client() (platformv1.PlannerServiceClient, func()) {
	lis := bufconn.Listen(1 << 20)
	grpcSrv := grpc.NewServer()
	platformv1.RegisterPlannerServiceServer(grpcSrv, f)
	go func() { _ = grpcSrv.Serve(lis) }()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		panic("plannerfake: dial bufconn: " + err.Error())
	}
	cleanup := func() {
		_ = conn.Close()
		grpcSrv.Stop()
		_ = lis.Close()
	}
	return platformv1.NewPlannerServiceClient(conn), cleanup
}
