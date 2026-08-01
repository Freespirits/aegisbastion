package service_test

// Order-intake suite (doc 02 §2.3 step 1 + §6): gatekeeper-backed gate,
// fail-closed postures, denial persistence with reason codes, cancel. The PDP
// is the in-process gatekeeper fake (bufconn) — Discover never mints, it only
// re-checks.

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"

	"github.com/aegisbastion/aegisbastion/services/discover/internal/service"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/testutil"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/auditfwd"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/connectors"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/pepclient"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/planner"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/queue"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

type intake struct {
	t   *testing.T
	st  *store.Store
	js  nats.JetStreamContext
	svc *service.Service
	fk  *testutil.FakeGatekeeper
}

func newIntake(t *testing.T) *intake {
	t.Helper()
	dsn := testutil.PostgresDSN(t)
	natsURL := testutil.NATSURL(t)
	ensureSchema(t, dsn)

	st, err := store.Connect(context.Background(), dsn, "discover")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	nc, err := nats.Connect(natsURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := nc.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	if err := queue.EnsureStream(js); err != nil {
		t.Fatal(err)
	}

	fk := &testutil.FakeGatekeeper{
		AllowCaps: map[string]bool{
			"discover.passive.dns":         true,
			"discover.passive.ct":          true,
			"discover.passive.subdomain":   true,
			"discover.passive.ip_netblock": true,
			"discover.cloud.credentialed":  true,
		},
		Scope: &gatekeeperv1.Scope{
			Domains: []string{"example.com", "*.example.com"},
		},
	}
	conn := fk.Dial(t)
	pep := pepclient.New(conn, nil, nil)

	sources := planner.Sources{
		model.TechniquePassiveDNS:       {connectors.SecurityTrailsName},
		model.TechniqueCT:               {connectors.CrtSHName},
		model.TechniqueSubdomainPassive: {connectors.RapidDNSName},
	}
	svc := service.New(service.Deps{
		Store:   st,
		PEP:     pep,
		Planner: planner.New(sources),
		JS:      js,
		Audit:   auditfwd.NewEmitter(st, "discover-orchestrator-test"),
	})
	return &intake{t: t, st: st, js: js, svc: svc, fk: fk}
}

func ensureSchema(t *testing.T, dsn string) {
	t.Helper()
	st, err := store.Connect(context.Background(), dsn, "")
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	var reg *string
	if err := st.Pool().QueryRow(context.Background(),
		`SELECT to_regclass('discover.assets')::text`).Scan(&reg); err == nil && reg != nil {
		return
	}
	raw, err := os.ReadFile(testutil.MigrationPath(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Pool().Exec(context.Background(), string(raw)); err != nil {
		t.Fatalf("apply migration 000004: %v", err)
	}
}

func order(seeds []model.Seed, techniques ...model.Technique) *model.DiscoveryOrder {
	return &model.DiscoveryOrder{
		TenantID:      uuid.NewString(),
		RequestedBy:   model.RequestedBy{Commander: "cai", AgentID: "cai-1", HumanPrincipal: "op@example.com"},
		Seeds:         seeds,
		Techniques:    techniques,
		Authorization: model.Authorization{ROEID: "roe_intake1", TicketRef: "CHG-42"},
	}
}

func TestIntakeAllowDispatches(t *testing.T) {
	in := newIntake(t)
	st, err := in.svc.SubmitOrder(context.Background(), order(
		[]model.Seed{{Type: model.SeedDomain, Value: "example.com"}},
		model.TechniqueCT, model.TechniquePassiveDNS,
	))
	if err != nil {
		t.Fatalf("allow path: %v", err)
	}
	if st.State != model.OrderRunning {
		t.Errorf("state = %s, want RUNNING", st.State)
	}
	if st.Gate == nil || st.Gate.Decision != "allow" || st.Gate.DecisionID == "" {
		t.Errorf("gate = %+v", st.Gate)
	}
	// Tasks: ct→crt.sh lane ct; passive_dns→securitytrails lane passive.
	if st.Progress.TasksTotal != 2 {
		t.Errorf("tasks_total = %d, want 2", st.Progress.TasksTotal)
	}
	// Lane tasks are on the bus.
	ct, err := in.js.PullSubscribe(model.LaneCT, "", nats.ManualAck())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	foundCT := false
	for time.Now().Before(deadline) && !foundCT {
		msgs, _ := ct.Fetch(5, nats.MaxWait(time.Second))
		for _, m := range msgs {
			task, err := queue.DecodeTask(m)
			if err != nil {
				_ = m.Term()
				continue
			}
			if task.OrderID == st.OrderID {
				foundCT = true
				if task.RiskClass != "R0" || task.ROEID != "roe_intake1" {
					t.Errorf("task = %+v", task)
				}
				_ = m.Ack()
			} else {
				_ = m.Nak()
			}
		}
	}
	if !foundCT {
		t.Error("no ct lane task for the order")
	}
	// Audit spool recorded submit + gate decision + dispatches.
	var n int
	if err := in.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM audit_spool WHERE target=$1 OR payload->>'order_id'=$1`,
		st.OrderID).Scan(&n); err != nil || n < 3 {
		t.Errorf("audit spool rows for order = %d (%v), want ≥3 (submit, gate, 2 dispatches)", n, err)
	}
}

func TestIntakeDenyPersistsDenied(t *testing.T) {
	in := newIntake(t)
	st, err := in.svc.SubmitOrder(context.Background(), order(
		[]model.Seed{{Type: model.SeedDomain, Value: "denied.example.com"}},
		model.TechniqueCT,
	))
	if !errors.Is(err, service.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if st == nil || st.State != model.OrderDenied {
		t.Fatalf("status = %+v", st)
	}
	// Gatekeeper reason code surfaced verbatim (doc 02 §3.3).
	joined := ""
	for _, r := range st.Gate.Reasons {
		joined += r + ";"
	}
	if st.Gate.Decision != "deny" || !strings.Contains(joined, "TARGET_NOT_IN_SCOPE") {
		t.Errorf("gate = %+v", st.Gate)
	}
	// Persisted DENIED.
	row, err := in.st.GetOrder(context.Background(), st.OrderID)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != model.OrderDenied {
		t.Errorf("persisted state = %s", row.State)
	}
}

func TestIntakeGatekeeperDownFailsClosed(t *testing.T) {
	in := newIntake(t)
	in.fk.Down = true
	_, err := in.svc.SubmitOrder(context.Background(), order(
		[]model.Seed{{Type: model.SeedDomain, Value: "example.com"}},
		model.TechniqueCT,
	))
	if !errors.Is(err, service.ErrGatekeeperDown) {
		t.Fatalf("intake must fail closed when gatekeeper is unreachable, got %v", err)
	}
}

func TestIntakeActiveTechniqueDropped(t *testing.T) {
	in := newIntake(t)
	// Only active techniques requested ⇒ nothing allowed ⇒ DENIED with
	// ACTIVE_NOT_ALLOWED (doc 02 §8).
	st, err := in.svc.SubmitOrder(context.Background(), order(
		[]model.Seed{{Type: model.SeedDomain, Value: "example.com"}},
		model.TechniqueSubdomainActive,
	))
	if !errors.Is(err, service.ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	joined := ""
	for _, r := range st.Gate.Reasons {
		joined += r + ";"
	}
	if !strings.Contains(joined, model.ReasonActiveNotAllowed) {
		t.Errorf("reasons = %v, want ACTIVE_NOT_ALLOWED", st.Gate.Reasons)
	}
}

func TestIntakeMixedActivePassiveRunsPassiveOnly(t *testing.T) {
	in := newIntake(t)
	st, err := in.svc.SubmitOrder(context.Background(), order(
		[]model.Seed{{Type: model.SeedDomain, Value: "example.com"}},
		model.TechniqueSubdomainActive, model.TechniqueCT,
	))
	if err != nil {
		t.Fatalf("mixed order: %v", err)
	}
	if st.State != model.OrderRunning {
		t.Errorf("state = %s — passive part must run", st.State)
	}
	joined := ""
	for _, r := range st.Gate.Reasons {
		joined += r + ";"
	}
	if !strings.Contains(joined, model.ReasonActiveNotAllowed) {
		t.Errorf("reasons = %v, want ACTIVE_NOT_ALLOWED recorded", st.Gate.Reasons)
	}
	if st.Progress.TasksTotal != 1 {
		t.Errorf("tasks_total = %d, want 1 (only the passive task)", st.Progress.TasksTotal)
	}
}

func TestIntakeCancel(t *testing.T) {
	in := newIntake(t)
	st, err := in.svc.SubmitOrder(context.Background(), order(
		[]model.Seed{{Type: model.SeedDomain, Value: "example.com"}},
		model.TechniqueCT,
	))
	if err != nil {
		t.Fatal(err)
	}
	cancelled, err := in.svc.Cancel(context.Background(), st.OrderID)
	if err != nil {
		t.Fatal(err)
	}
	if cancelled.State != model.OrderCancelled {
		t.Errorf("state = %s", cancelled.State)
	}
	// Second cancel ⇒ conflict.
	if _, err := in.svc.Cancel(context.Background(), st.OrderID); !errors.Is(err, service.ErrConflict) {
		t.Errorf("double cancel must conflict, got %v", err)
	}
}

func TestIntakeValidationRejected(t *testing.T) {
	in := newIntake(t)
	bad := order(nil, model.TechniqueCT)
	if _, err := in.svc.SubmitOrder(context.Background(), bad); !errors.Is(err, service.ErrValidation) {
		t.Errorf("seedless order must be a validation error, got %v", err)
	}
}
