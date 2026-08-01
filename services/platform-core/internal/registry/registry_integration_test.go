package registry

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bootstrap"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/itlock"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// These use the same env-gated infra as the orchestrator integration tests.
func regSetup(t *testing.T) *store.Store {
	t.Helper()
	dsn := testDatabaseURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	st, err := store.New(ctx, dsn, "platform")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	// Registered BEFORE itlock.Acquire so the lock connection is released
	// before the pool closes (LIFO cleanup order).
	t.Cleanup(st.Close)
	itlock.Acquire(t, st.Pool)
	if err := bootstrap.Ensure(ctx, st.Pool); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	for _, table := range []string{"agents", "kill_switches", "tasks", "plans", "missions"} {
		if _, err := st.Pool.Exec(ctx, "TRUNCATE platform."+table+" RESTART IDENTITY CASCADE"); err != nil {
			t.Fatalf("truncate: %v", err)
		}
	}
	return st
}

func manifest(agentType platformv1.AgentType, spiffe string, caps ...*platformv1.Capability) *platformv1.AgentManifest {
	return &platformv1.AgentManifest{
		AgentType:    agentType,
		Version:      "0.1.0",
		BuildHash:    "sha256:test",
		Capabilities: caps,
		Identity:     &platformv1.AgentIdentity{SpiffeId: spiffe},
		Limits:       &platformv1.AgentLimits{MaxConcurrentTasks: 2},
	}
}

func TestRegisterAndReregister(t *testing.T) {
	st := regSetup(t)
	svc := New(st, nil)
	ctx := context.Background()

	m := manifest(platformv1.AgentType_AGENT_TYPE_DETECT,
		"spiffe://aegisbastion/agent/detect/test-1",
		&platformv1.Capability{Name: "detect.scan", RiskClassMax: platformv1.RiskClass_RISK_CLASS_R2, SchemaVersion: "v1"})
	resp, err := svc.Register(ctx, &platformv1.RegisterRequest{Manifest: m})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if resp.GetAgentId() == "" {
		t.Fatal("agent_id must be assigned at first registration")
	}

	// Re-registration on version change keeps the identity (doc 01 §9 item 1).
	m.Version = "0.2.0"
	m.AgentId = resp.GetAgentId()
	resp2, err := svc.Register(ctx, &platformv1.RegisterRequest{Manifest: m})
	if err != nil {
		t.Fatalf("re-register: %v", err)
	}
	if resp2.GetAgentId() != resp.GetAgentId() {
		t.Fatalf("re-registration changed identity: %s → %s", resp.GetAgentId(), resp2.GetAgentId())
	}
	a, err := st.GetAgent(ctx, resp.GetAgentId())
	if err != nil || a.Version != "0.2.0" {
		t.Fatalf("version not updated: %v", a)
	}

	// Invalid manifests are refused.
	if _, err := svc.Register(ctx, &platformv1.RegisterRequest{Manifest: &platformv1.AgentManifest{}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("empty manifest must be InvalidArgument, got %v", err)
	}
}

func TestHeartbeatKillActive(t *testing.T) {
	st := regSetup(t)
	svc := New(st, nil)
	ctx := context.Background()

	resp, err := svc.Register(ctx, &platformv1.RegisterRequest{Manifest: manifest(
		platformv1.AgentType_AGENT_TYPE_MONITOR, "spiffe://aegisbastion/agent/monitor/test-1",
		&platformv1.Capability{Name: "monitor.watch", RiskClassMax: platformv1.RiskClass_RISK_CLASS_R1, SchemaVersion: "v1"})})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	hb, err := svc.Heartbeat(ctx, &platformv1.HeartbeatRequest{AgentId: resp.GetAgentId()})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if hb.GetKillActive() {
		t.Fatal("kill_active must be false with no engaged switches")
	}
	// Global kill flips the heartbeat signal (doc 01 §10.5).
	if err := st.EngageKillSwitch(ctx, store.KillScopeGlobal, "", "test", "test"); err != nil {
		t.Fatalf("engage: %v", err)
	}
	hb, err = svc.Heartbeat(ctx, &platformv1.HeartbeatRequest{AgentId: resp.GetAgentId()})
	if err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	if !hb.GetKillActive() {
		t.Fatal("kill_active must be true with global kill engaged")
	}
	// Unknown agents get NotFound (must re-register).
	if _, err := svc.Heartbeat(ctx, &platformv1.HeartbeatRequest{AgentId: "agent_nope"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown agent heartbeat must be NotFound, got %v", err)
	}
}

func TestQuarantinedAgentCannotReregister(t *testing.T) {
	st := regSetup(t)
	svc := New(st, nil)
	ctx := context.Background()

	resp, err := svc.Register(ctx, &platformv1.RegisterRequest{Manifest: manifest(
		platformv1.AgentType_AGENT_TYPE_DETECT, "spiffe://aegisbastion/agent/detect/test-q",
		&platformv1.Capability{Name: "detect.scan", RiskClassMax: platformv1.RiskClass_RISK_CLASS_R2, SchemaVersion: "v1"})})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if err := st.SetAgentStatus(ctx, resp.GetAgentId(), store.AgentQuarantined); err != nil {
		t.Fatalf("quarantine: %v", err)
	}
	// Re-registration must NOT lift the quarantine (doc 01 §10.5).
	m := manifest(platformv1.AgentType_AGENT_TYPE_DETECT, "spiffe://aegisbastion/agent/detect/test-q",
		&platformv1.Capability{Name: "detect.scan", RiskClassMax: platformv1.RiskClass_RISK_CLASS_R2, SchemaVersion: "v1"})
	m.AgentId = resp.GetAgentId()
	if _, err := svc.Register(ctx, &platformv1.RegisterRequest{Manifest: m}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("quarantined re-registration must be PermissionDenied, got %v", err)
	}
	a, _ := st.GetAgent(ctx, resp.GetAgentId())
	if a.Status != store.AgentQuarantined {
		t.Fatalf("status = %s, quarantine must persist", a.Status)
	}
}
