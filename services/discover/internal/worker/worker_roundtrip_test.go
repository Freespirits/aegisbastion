package worker_test

// Bus round-trip against the compose infra (doc 02 §2.3): lane task → worker
// (fixture connector, offline) → discover.results → reducer → working store +
// DP Ingest API + AssetChange on hub.discover.asset.changed, plus the
// fail-closed refusal path (R1 task without a Scope Token → DLQ + audit).

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/nats-io/nats.go"

	"github.com/aegisbastion/aegisbastion/sdks/go/pep"
	sdkscope "github.com/aegisbastion/aegisbastion/sdks/go/scope"

	"github.com/aegisbastion/aegisbastion/services/discover/internal/testutil"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/worker"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/auditfwd"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/connectors"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/dpingest"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/pepclient"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/queue"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/reducer"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

// roundtrip wires the full path for one order.
type roundtrip struct {
	t      *testing.T
	st     *store.Store
	js     nats.JetStreamContext
	nc     *nats.Conn
	tenant string
	order  model.DiscoveryOrder

	mu      sync.Mutex
	changes []*model.AssetChange
	batches []map[string]any
}

func newRoundtrip(t *testing.T) *roundtrip {
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
	// DISCOVER_EVENTS is provisioned by jetstream-bootstrap; create when the
	// test runs against a bare NATS. nats.go v1.39's legacy AddStream unwraps
	// APIError 10058 into the ErrStreamNameAlreadyInUse sentinel (a *jsError),
	// so match it with errors.Is rather than a *nats.APIError type assert.
	_, err = js.AddStream(&nats.StreamConfig{
		Name:      "DISCOVER_EVENTS",
		Subjects:  []string{model.SubjectOrderStatusChanged, model.SubjectAssetChanged},
		Retention: nats.LimitsPolicy,
	})
	if err != nil && !errors.Is(err, nats.ErrStreamNameAlreadyInUse) {
		t.Fatalf("DISCOVER_EVENTS: %v", err)
	}

	rt := &roundtrip{t: t, st: st, js: js, nc: nc, tenant: uuid.NewString()}
	rt.order = model.DiscoveryOrder{
		SchemaVersion: model.SchemaVersion,
		OrderID:       uuid.NewString(),
		TenantID:      rt.tenant,
		RequestedBy:   model.RequestedBy{Commander: "cai", AgentID: "cai-test"},
		Seeds:         []model.Seed{{Type: model.SeedDomain, Value: "example.com"}},
		Techniques:    []model.Technique{model.TechniqueSubdomainPassive},
		Authorization: model.Authorization{ROEID: "roe_rt1"},
		Options:       model.DefaultOrderOptions(),
	}
	reqJSON, _ := json.Marshal(rt.order)
	if err := st.InsertOrder(context.Background(), &store.OrderRow{
		OrderID: rt.order.OrderID, TenantID: rt.tenant, Request: reqJSON,
		State: model.OrderRunning, Progress: model.Progress{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := st.SetProgressTotal(context.Background(), rt.order.OrderID, 1); err != nil {
		t.Fatal(err)
	}
	return rt
}

// ensureSchema applies migration 000004 once per database.
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

// fixtureRegistry serves the recorded securitytrails response offline.
func fixtureRegistry(t *testing.T) *connectors.Registry {
	t.Helper()
	body, err := os.ReadFile("../../testdata/fixtures/securitytrails.json")
	if err != nil {
		t.Fatal(err)
	}
	fetch := connectors.FetcherFunc(func(context.Context, *connectors.Request) ([]byte, error) {
		return body, nil
	})
	keys := connectors.KeyProviderFunc(func(context.Context, string, string) (string, error) {
		return "fixture-key", nil
	})
	reg := connectors.NewRegistry(keys)
	reg.Register(connectors.NewSecurityTrails(fetch, keys))
	return reg
}

// fakeDP runs a capture-ingest server.
func (rt *roundtrip) fakeDP() *dpingest.Client {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &b)
		rt.mu.Lock()
		rt.batches = append(rt.batches, b)
		rt.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"idempotency_key": b["idempotency_key"], "status": "accepted"})
	}))
	rt.t.Cleanup(srv.Close)
	return &dpingest.Client{BaseURL: srv.URL, Principal: "svc-discover"}
}

// driveReducer consumes discover.results until the order's done marker is
// processed (or the deadline passes).
func (rt *roundtrip) driveReducer(deadline time.Duration) {
	cons, err := queue.SubscribeResults(rt.js)
	if err != nil {
		rt.t.Fatal(err)
	}
	defer cons.Close()

	sc := &sdkscope.Scope{Domains: []string{"example.com", "*.example.com"}}
	red := reducer.New(reducer.Deps{
		Store: rt.st,
		DP:    rt.fakeDP(),
		PublishChange: func(_ context.Context, ch *model.AssetChange) error {
			rt.mu.Lock()
			rt.changes = append(rt.changes, ch)
			rt.mu.Unlock()
			// Also publish onto the real bus (hub.discover.asset.changed) so
			// the round-trip covers the event subject.
			body, _ := json.Marshal(ch)
			_, err := rt.js.Publish(model.SubjectAssetChanged, body)
			return err
		},
		ScopeFor: func(_ context.Context, orderID string) (*model.DiscoveryOrder, string, *sdkscope.Scope, error) {
			if orderID != rt.order.OrderID {
				return nil, "", nil, nil
			}
			return &rt.order, model.OrderRunning, sc, nil
		},
	})

	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		msgs, err := cons.Fetch(8, time.Second)
		if err != nil {
			rt.t.Fatal(err)
		}
		for _, msg := range msgs {
			m, err := queue.DecodeResult(msg)
			if err != nil {
				_ = msg.Term()
				continue
			}
			disp := red.Process(context.Background(), m, queue.Deliveries(msg))
			if disp == reducer.Ack {
				_ = msg.Ack()
			} else {
				_ = msg.Nak()
			}
			if m.Kind == model.ResultDone && m.OrderID == rt.order.OrderID {
				return
			}
		}
	}
	rt.t.Fatal("done marker not observed before the deadline")
}

func TestBusRoundTrip(t *testing.T) {
	rt := newRoundtrip(t)

	// Worker with the fixture registry; PEP verifies nothing (R0, no token).
	w := worker.New(worker.Deps{
		Lane:     model.LanePassive,
		JS:       rt.js,
		Registry: fixtureRegistry(t),
		PEP:      &pepclient.Client{Revocations: pep.NewRevocationCache()},
		Store:    rt.st,
		Audit:    auditfwd.NewEmitter(rt.st, "discover-worker-passive-test"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	task := model.Task{
		TaskID:    uuid.NewString(),
		OrderID:   rt.order.OrderID,
		TenantID:  rt.tenant,
		Technique: model.TechniqueSubdomainPassive,
		Source:    connectors.SecurityTrailsName,
		Seed:      model.Seed{Type: model.SeedDomain, Value: "example.com"},
		Attempt:   1,
		Deadline:  time.Now().Add(time.Minute).UTC(),
		ROEID:     "roe_rt1",
		RiskClass: "R0",
	}
	if err := queue.PublishTask(context.Background(), rt.js, task); err != nil {
		t.Fatal(err)
	}

	rt.driveReducer(30 * time.Second)
	cancel()

	// Assets from the fixture (relative labels joined to the apex).
	for _, want := range []string{"www.example.com", "api.example.com", "dev.api.example.com"} {
		if _, err := rt.st.GetAsset(context.Background(), rt.tenant, model.AssetSubdomain, want); err != nil {
			t.Errorf("asset %s missing: %v", want, err)
		}
	}
	// AssetChange events (one "new" per fixture subdomain).
	rt.mu.Lock()
	kinds := map[string]int{}
	for _, ch := range rt.changes {
		kinds[ch.Kind]++
	}
	rt.mu.Unlock()
	if kinds[model.ChangeNew] != 3 {
		t.Errorf("AssetChange kinds = %v, want 3 new", kinds)
	}
	// DP ingest batches received.
	rt.mu.Lock()
	nb := len(rt.batches)
	rt.mu.Unlock()
	if nb != 3 {
		t.Errorf("dp batches = %d, want 3", nb)
	}
	// hub.discover.asset.changed carries the events on the bus.
	info, err := rt.js.StreamInfo("DISCOVER_EVENTS")
	if err != nil {
		t.Fatal(err)
	}
	if info.State.Msgs == 0 {
		t.Error("DISCOVER_EVENTS stream holds no asset-change events")
	}
	// Order finalized COMPLETED.
	row, err := rt.st.GetOrder(context.Background(), rt.order.OrderID)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != model.OrderCompleted {
		t.Errorf("order state = %s, want COMPLETED", row.State)
	}
	if row.Progress.Done != 1 || row.Progress.AssetsFound != 3 {
		t.Errorf("progress = %+v", row.Progress)
	}
}

// TestWorkerRefusesR1WithoutToken is the fail-closed path (doc 02 §6.2 +
// §9 matrix): an R1-class task without a Scope Token is refused, dead-lettered,
// and audit-recorded — never executed.
func TestWorkerRefusesR1WithoutToken(t *testing.T) {
	rt := newRoundtrip(t)

	executed := false
	fetch := connectors.FetcherFunc(func(context.Context, *connectors.Request) ([]byte, error) {
		executed = true
		return nil, connectors.ErrNotFound
	})
	keys := connectors.KeyProviderFunc(func(context.Context, string, string) (string, error) { return "k", nil })
	reg := connectors.NewRegistry(keys)
	reg.Register(connectors.NewSecurityTrails(fetch, keys))

	w := worker.New(worker.Deps{
		Lane:     model.LanePassive,
		JS:       rt.js,
		Registry: reg,
		PEP:      &pepclient.Client{Revocations: pep.NewRevocationCache()},
		Store:    rt.st,
		Audit:    auditfwd.NewEmitter(rt.st, "discover-worker-passive-test"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = w.Run(ctx) }()

	task := model.Task{
		TaskID:    uuid.NewString(),
		OrderID:   rt.order.OrderID,
		TenantID:  rt.tenant,
		Technique: model.TechniquePassiveDNS,
		Source:    connectors.SecurityTrailsName,
		Seed:      model.Seed{Type: model.SeedDomain, Value: "example.com"},
		Attempt:   1,
		Deadline:  time.Now().Add(time.Minute).UTC(),
		ROEID:     "roe_rt1",
		RiskClass: "R1", // R1-class task WITHOUT a token ⇒ refuse
	}
	if err := queue.PublishTask(context.Background(), rt.js, task); err != nil {
		t.Fatal(err)
	}

	// The refusal lands on the DLQ.
	dlq, err := rt.js.PullSubscribe(model.SubjectDLQ, "", nats.ManualAck())
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		msgs, err := dlq.Fetch(10, nats.MaxWait(2*time.Second))
		if err != nil && err != nats.ErrTimeout {
			t.Fatal(err)
		}
		found := false
		for _, m := range msgs {
			var rec struct {
				Task   model.Task `json:"task"`
				Reason string     `json:"reason"`
			}
			if json.Unmarshal(m.Data, &rec) == nil && rec.Task.TaskID == task.TaskID {
				found = true
				if rec.Reason == "" {
					t.Error("DLQ record must carry the refusal reason")
				}
				_ = m.Ack()
			} else {
				_ = m.Nak()
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refused task never reached discover.dlq")
		}
	}
	cancel()
	if executed {
		t.Fatal("refused task must never touch a connector")
	}
	// Audit spool carries the worker.refusal (SCOPE_VIOLATION) record.
	deadline = time.Now().Add(5 * time.Second)
	for {
		var n int
		if err := rt.st.Pool().QueryRow(context.Background(),
			`SELECT count(*) FROM audit_spool WHERE action='worker.refusal' AND target=$1`,
			task.TaskID).Scan(&n); err == nil && n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("worker.refusal audit record missing")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
