package missionapi

import (
	"context"
	"os"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bootstrap"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/config"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/gatekeeper"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/itlock"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/orchestrator"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/pep"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

type fakeROEs struct {
	roe *gatekeeperv1.RulesOfEngagement
	err error
}

func (f *fakeROEs) GetROE(context.Context, string, uint64) (*gatekeeperv1.RulesOfEngagement, error) {
	return f.roe, f.err
}

func (f *fakeROEs) RevokeROE(_ context.Context, roeID, _ string) (*gatekeeperv1.RulesOfEngagement, error) {
	r := proto.Clone(f.roe).(*gatekeeperv1.RulesOfEngagement)
	r.RoeId = roeID
	r.Status = gatekeeperv1.ROEStatus_ROE_STATUS_REVOKED
	return r, nil
}

func activeROE() *gatekeeperv1.RulesOfEngagement {
	return &gatekeeperv1.RulesOfEngagement{
		RoeId:      "roe_msn_test",
		Version:    2,
		Status:     gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE,
		ValidFrom:  timestamppb.New(time.Now().Add(-time.Hour)),
		ValidUntil: timestamppb.New(time.Now().Add(time.Hour)),
	}
}

func apiSetup(t *testing.T, roes gatekeeper.ROEStore, operators []string) (*Service, *store.Store) {
	t.Helper()
	dsn := os.Getenv("AEGISBASTION_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("integration test needs AEGISBASTION_TEST_DATABASE_URL")
	}
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
	if _, err := st.Pool.Exec(ctx,
		`TRUNCATE platform.task_state_transitions, platform.tasks, platform.plans,
		 platform.missions, platform.agents, platform.outbox, platform.kill_switches,
		 platform.audit_events RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	cfg := &config.Config{Operators: operators, InstanceID: "itest", ArtifactBucket: "artifacts"}
	o := orchestrator.New(cfg, st, pep.New(nil, nil, "itest"), roes, nil, nil,
		audit.NewLogger(st.Pool, ""), nil)
	svc := New(cfg, st, o, roes, nil, audit.NewLogger(st.Pool, ""))
	return svc, st
}

// Mission admission is fail-closed (doc 01 §10.1): gatekeeper unreachable →
// CreateMission fails, no mission row.
func TestCreateMission_FailClosedWhenGatekeeperDown(t *testing.T) {
	svc, st := apiSetup(t, &fakeROEs{err: status.Error(codes.Unavailable, "connection refused")}, nil)

	_, err := svc.CreateMission(context.Background(), &platformv1.CreateMissionRequest{
		Name:            "m1",
		OwningCommander: platformv1.Commander_COMMANDER_CAI,
		RoeId:           "roe_x",
		CreatedBy:       "op_jane@example.com",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable (fail-closed), got %v", err)
	}
	var n int
	if err := st.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM platform.missions`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("mission must not be persisted on admission failure (n=%d)", n)
	}
}

// Happy path: RoE validated, mission persisted DRAFT with pinned RoE version,
// MISSION_CREATED audited; ResumeMission activates; RBAC shim enforced.
func TestMissionLifecycleAndRBAC(t *testing.T) {
	svc, st := apiSetup(t, &fakeROEs{roe: activeROE()}, []string{"op_jane@example.com"})
	ctx := context.Background()

	// RBAC shim: unknown operator is denied on mutating calls.
	if _, err := svc.CreateMission(ctx, &platformv1.CreateMissionRequest{
		Name: "m1", OwningCommander: platformv1.Commander_COMMANDER_HEXSTRIKE,
		RoeId: "roe_msn_test", CreatedBy: "mallory@evil.io",
	}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("non-operator must be denied, got %v", err)
	}

	resp, err := svc.CreateMission(ctx, &platformv1.CreateMissionRequest{
		Name:            "m1",
		OwningCommander: platformv1.Commander_COMMANDER_HEXSTRIKE,
		Objective:       "test",
		RoeId:           "roe_msn_test",
		CreatedBy:       "op_jane@example.com",
	})
	if err != nil {
		t.Fatalf("CreateMission: %v", err)
	}
	m := resp.GetMission()
	if m.GetState() != platformv1.MissionState_MISSION_STATE_DRAFT {
		t.Fatalf("new mission state = %s, want DRAFT", m.GetState())
	}
	if m.GetRoeVersion() != 2 {
		t.Fatalf("RoE version must be pinned at admission (2), got %d", m.GetRoeVersion())
	}

	// Mutating calls carry the operator identity (REST injects the header
	// into gRPC metadata the same way).
	opCtx := metadata.NewIncomingContext(ctx, metadata.Pairs(OperatorHeader, "op_jane@example.com"))

	// Plans require ACTIVE — activation via ResumeMission.
	if _, err := svc.ResumeMission(opCtx, &platformv1.ResumeMissionRequest{MissionId: m.GetMissionId()}); err != nil {
		t.Fatalf("ResumeMission: %v", err)
	}
	got, err := svc.GetMission(ctx, &platformv1.GetMissionRequest{MissionId: m.GetMissionId()})
	if err != nil || got.GetMission().GetState() != platformv1.MissionState_MISSION_STATE_ACTIVE {
		t.Fatalf("state after resume = %v", got.GetMission().GetState())
	}

	// Pause → plans halt; Kill is terminal.
	if _, err := svc.PauseMission(opCtx, &platformv1.PauseMissionRequest{MissionId: m.GetMissionId()}); err != nil {
		t.Fatalf("PauseMission: %v", err)
	}
	killResp, err := svc.KillMission(opCtx, &platformv1.KillMissionRequest{
		MissionId: m.GetMissionId(), Reason: "operator test kill",
	})
	if err != nil {
		t.Fatalf("KillMission: %v", err)
	}
	if killResp.GetMission().GetState() != platformv1.MissionState_MISSION_STATE_KILLED {
		t.Fatalf("state after kill = %s", killResp.GetMission().GetState())
	}
	// KILLED is terminal: resume is refused.
	if _, err := svc.ResumeMission(opCtx, &platformv1.ResumeMissionRequest{MissionId: m.GetMissionId()}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("resume of KILLED mission must fail, got %v", err)
	}

	// Audit trail: MISSION_CREATED + KILL_SWITCH present, chain verifies.
	trail, err := svc.GetAuditTrail(ctx, &platformv1.GetAuditTrailRequest{MissionId: m.GetMissionId()})
	if err != nil {
		t.Fatalf("GetAuditTrail: %v", err)
	}
	var sawCreated, sawKill bool
	for _, ev := range trail.GetEvents() {
		switch ev.GetType() {
		case platformv1.AuditEventType_AUDIT_EVENT_TYPE_MISSION_CREATED:
			sawCreated = true
		case platformv1.AuditEventType_AUDIT_EVENT_TYPE_KILL_SWITCH:
			sawKill = true
		}
	}
	if !sawCreated || !sawKill {
		t.Fatalf("audit trail incomplete (created=%v kill=%v)", sawCreated, sawKill)
	}
	bad, err := audit.NewLogger(st.Pool, "").VerifyChain(ctx)
	if err != nil || bad != 0 {
		t.Fatalf("chain invalid at seq %d: %v", bad, err)
	}
}
