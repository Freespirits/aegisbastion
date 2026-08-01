// Integration tests run against the compose infra tier (Postgres 16 + NATS
// 2.11 — deploy/docker-compose.yml --profile infra) and are env-gated:
//
//	AEGISBASTION_TEST_DATABASE_URL   postgres://aegisbastion:aegisbastion-dev@localhost:5432/aegisbastion?sslmode=disable
//	AEGISBASTION_TEST_NATS_URL       nats://localhost:4222
//
// When unset they skip, keeping `go test ./...` hermetic.
package orchestrator

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bootstrap"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/config"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/gatekeeper"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/itlock"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/leases"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/pep"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// ---------------------------------------------------------------------------
// fakes for the gatekeeper surface (the PDP/minter/RoE store are interfaces —
// the acceptance tests that matter use a REAL unreachable gRPC client).
// ---------------------------------------------------------------------------

type fakePDP struct {
	decision *gatekeeperv1.DecisionEvent
	err      error
	calls    int
}

func (f *fakePDP) Authorize(_ context.Context, req *gatekeeperv1.AuthorizationRequest) (*gatekeeperv1.DecisionEvent, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	d := proto.Clone(f.decision).(*gatekeeperv1.DecisionEvent)
	d.RequestId = req.GetRequestId()
	d.RoeId = req.GetRoeId()
	d.RoeVersion = req.GetRoeVersion()
	return d, nil
}

type fakeMinter struct {
	err error
}

func (f *fakeMinter) MintToken(_ context.Context, req *gatekeeperv1.MintTokenRequest) (*gatekeeperv1.MintTokenResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &gatekeeperv1.MintTokenResponse{
		Token: "eyJhbGciOiJFZERTQSJ9.itest.signature",
		Claims: &gatekeeperv1.ScopeTokenClaims{
			Jti:        ids.New("tok"),
			TaskId:     req.GetTaskId(),
			Sub:        req.GetSubject(),
			ScopeBound: req.GetScopeBound(),
		},
	}, nil
}

type fakeROE struct {
	roe *gatekeeperv1.RulesOfEngagement
	err error
}

func (f *fakeROE) GetROE(_ context.Context, _ string, _ uint64) (*gatekeeperv1.RulesOfEngagement, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.roe, nil
}

func (f *fakeROE) RevokeROE(_ context.Context, roeID, _ string) (*gatekeeperv1.RulesOfEngagement, error) {
	r := proto.Clone(f.roe).(*gatekeeperv1.RulesOfEngagement)
	r.RoeId = roeID
	r.Status = gatekeeperv1.ROEStatus_ROE_STATUS_REVOKED
	return r, nil
}

func allowROE() *fakeROE {
	return &fakeROE{roe: &gatekeeperv1.RulesOfEngagement{
		RoeId:   "roe_itest",
		Version: 1,
		Status:  gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE,
		Constraints: &gatekeeperv1.Constraints{
			MaxRiskClass:        platformv1.RiskClass_RISK_CLASS_R3,
			AllowedCapabilities: []string{"detect.scan", "monitor.watch", "monitor.rescan", "monitor.feed.sync", "redteam.api_probe"},
			RateCaps: map[string]*gatekeeperv1.RateCapEntry{
				"detect.*": {Rps: 200, MaxConcurrent: 4},
			},
		},
		Scope: &gatekeeperv1.Scope{
			Domains:          []string{"acme.com", "*.acme.com"},
			Cidrs:            []string{"203.0.113.0/24"},
			ExplicitExcludes: []string{"status.acme.com"},
		},
		ValidFrom:  timestamppb.New(time.Now().Add(-time.Hour)),
		ValidUntil: timestamppb.New(time.Now().Add(time.Hour)),
	}}
}

func allowDecision() *gatekeeperv1.DecisionEvent {
	return &gatekeeperv1.DecisionEvent{
		DecisionId: ids.New("dec"),
		Decision:   gatekeeperv1.Decision_DECISION_ALLOW,
	}
}

// ---------------------------------------------------------------------------
// env
// ---------------------------------------------------------------------------

type itEnv struct {
	cfg *config.Config
	st  *store.Store
	b   *bus.Bus
	ls  *leases.KVStore
	al  *audit.Logger
}

func itSetup(t *testing.T) *itEnv {
	t.Helper()
	dsn := os.Getenv("AEGISBASTION_TEST_DATABASE_URL")
	natsURL := os.Getenv("AEGISBASTION_TEST_NATS_URL")
	if dsn == "" || natsURL == "" {
		t.Skip("integration test needs AEGISBASTION_TEST_DATABASE_URL + AEGISBASTION_TEST_NATS_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	st, err := store.New(ctx, dsn, "platform")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	// Cleanup order matters: this is registered BEFORE itlock.Acquire so the
	// advisory-lock connection is released before the pool closes (LIFO).
	t.Cleanup(st.Close)
	itlock.Acquire(t, st.Pool)
	if err := bootstrap.Ensure(ctx, st.Pool); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	for _, table := range []string{
		"task_state_transitions", "tasks", "plans", "missions",
		"agents", "outbox", "kill_switches", "audit_events",
	} {
		if _, err := st.Pool.Exec(ctx, "TRUNCATE platform."+table+" RESTART IDENTITY CASCADE"); err != nil {
			t.Fatalf("truncate %s: %v", table, err)
		}
	}
	b, err := bus.Connect(natsURL, "platform-core-itest")
	if err != nil {
		t.Fatalf("bus: %v", err)
	}
	if b.Leases == nil {
		t.Fatal("leases KV bucket missing — run deploy/jetstream-bootstrap")
	}
	if keys, err := b.Leases.Keys(); err == nil {
		for _, k := range keys {
			_ = b.Leases.Delete(k)
		}
	}

	cfg := &config.Config{
		SchedulerTick:                 50 * time.Millisecond,
		ReaperTick:                    100 * time.Millisecond,
		AckTimeout:                    10 * time.Second,
		AgentHeartbeatTTL:             30 * time.Second,
		QueueTTL:                      time.Hour,
		CommanderQuota:                50,
		DefaultMaxConcurrentIntrusive: 4,
		DefaultR1MaxRPS:               100,
		ArtifactBucket:                "artifacts",
		InstanceID:                    "itest",
		GatekeeperDialTimeout:         1500 * time.Millisecond,
	}
	e := &itEnv{cfg: cfg, st: st, b: b, ls: leases.NewKVStore(b.Leases), al: audit.NewLogger(st.Pool, "")}
	t.Cleanup(b.Close)
	return e
}

func (e *itEnv) orchestrator(p *pep.PEP, roes gatekeeper.ROEStore) *Orchestrator {
	return New(e.cfg, e.st, p, roes, e.ls, e.b, e.al, slog.Default())
}

func (e *itEnv) seedMission(t *testing.T, state string) *store.Mission {
	t.Helper()
	m := &store.Mission{
		MissionID:       ids.New("msn"),
		Name:            ids.New("itest-mission"),
		OwningCommander: "hexstrike",
		Objective:       "integration test",
		RoeID:           ids.New("roe"),
		RoeVersion:      1,
		Priority:        "P3_PLANNED",
		CreatedBy:       "op_itest",
		State:           store.MissionDraft,
	}
	if err := e.st.CreateMission(context.Background(), m); err != nil {
		t.Fatalf("seed mission: %v", err)
	}
	if state != store.MissionDraft {
		if err := e.st.SetMissionState(context.Background(), m.MissionID, state, store.MissionDraft); err != nil {
			t.Fatalf("activate mission: %v", err)
		}
		m.State = state
	}
	return m
}

func (e *itEnv) seedPlan(t *testing.T, missionID string) *store.Plan {
	t.Helper()
	p := &store.Plan{
		PlanID: ids.New("pln"), MissionID: missionID, SubmittedBy: "hexstrike",
		IdempotencyKey: ids.New("itest-idem"),
	}
	if _, err := e.st.InsertPlan(context.Background(), p); err != nil {
		t.Fatalf("seed plan: %v", err)
	}
	return p
}

func (e *itEnv) seedAgent(t *testing.T, agentType, capability, riskMax string, maxConcurrent int, sandboxed bool) *store.Agent {
	t.Helper()
	a := &store.Agent{
		AgentID:   ids.New("agent"),
		AgentType: agentType,
		Version:   "0.0.1",
		BuildHash: "sha256:itest",
		Capabilities: []store.Capability{{
			Name: capability, RiskClassMax: riskMax, SchemaVersion: "v1",
		}},
		SpiffeID:      "spiffe://aegisbastion/agent/" + agentType + "/" + ids.New(""),
		MaxConcurrent: maxConcurrent,
		Sandboxed:     sandboxed,
	}
	if err := e.st.RegisterAgent(context.Background(), a); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	return a
}

func (e *itEnv) seedQueuedTask(t *testing.T, m *store.Mission, p *store.Plan, capability, risk string, targets []string, maxRetries int) *store.Task {
	t.Helper()
	task := &store.Task{
		TaskID: ids.New("tsk"), PlanID: p.PlanID, MissionID: m.MissionID,
		TaskKey: ids.New("k"), Capability: capability, RiskClass: risk,
		Targets: targets, TimeoutS: 300, MaxRetries: maxRetries,
		DependsOn: []string{}, State: store.TaskPending,
	}
	if err := e.st.InsertTask(context.Background(), task); err != nil {
		t.Fatalf("seed task: %v", err)
	}
	if err := e.st.Transition(context.Background(), task.TaskID, []string{store.TaskPending}, store.TaskValidating, "itest", ""); err != nil {
		t.Fatalf("seed transition: %v", err)
	}
	if err := e.st.Transition(context.Background(), task.TaskID, []string{store.TaskValidating}, store.TaskQueued, "itest", ""); err != nil {
		t.Fatalf("seed queue: %v", err)
	}
	task.State = store.TaskQueued
	return task
}

func (e *itEnv) auditForTask(t *testing.T, taskID, typ string) []map[string]any {
	t.Helper()
	rows, err := e.st.Pool.Query(context.Background(), `
		SELECT payload FROM platform.audit_events
		WHERE subject ->> 'task_id' = $1 AND type = $2 ORDER BY seq`, taskID, typ)
	if err != nil {
		t.Fatalf("audit query: %v", err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var p map[string]any
		if err := rows.Scan(&p); err != nil {
			t.Fatalf("audit scan: %v", err)
		}
		out = append(out, p)
	}
	return out
}

func (e *itEnv) outboxFor(t *testing.T, subjectLike string) [][]byte {
	t.Helper()
	rows, err := e.st.Pool.Query(context.Background(), `
		SELECT payload FROM platform.outbox WHERE subject LIKE $1 ORDER BY id`, subjectLike)
	if err != nil {
		t.Fatalf("outbox query: %v", err)
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			t.Fatalf("outbox scan: %v", err)
		}
		payload, err := store.DecodeOutboxPayload(raw)
		if err != nil {
			t.Fatalf("outbox decode: %v", err)
		}
		out = append(out, payload)
	}
	return out
}

func (e *itEnv) task(t *testing.T, taskID string) *store.Task {
	t.Helper()
	task, err := e.st.GetTask(context.Background(), taskID)
	if err != nil {
		t.Fatalf("reload task: %v", err)
	}
	return task
}

var errGatekeeperDown = errors.New("gatekeeper unreachable (test)")
