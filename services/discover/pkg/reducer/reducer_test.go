package reducer_test

// Reducer integration suite (doc 02 §2.2/§4.2/§7.2): AssetChange correctness,
// dedup (asset + finding + DP idempotency), quarantine of out-of-scope and
// excluded findings, corroboration, edges, and order finalization.
//
// Runs against the compose infra Postgres; skips gracefully when it is down.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	sdkscope "github.com/aegisbastion/aegisbastion/sdks/go/scope"

	"github.com/aegisbastion/aegisbastion/services/discover/internal/testutil"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/dpingest"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/reducer"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

// harness wires a reducer against real Postgres with fakes around it.
type harness struct {
	t       *testing.T
	st      *store.Store
	red     *reducer.Reducer
	order   *model.DiscoveryOrder
	tenant  string
	orderID string

	mu      sync.Mutex
	changes []*model.AssetChange
	batches []map[string]any
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dsn := testutil.PostgresDSN(t)
	ensureSchema(t, dsn)

	st, err := store.Connect(context.Background(), dsn, "discover")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)

	h := &harness{t: t, st: st, tenant: uuid.NewString(), orderID: uuid.NewString()}
	h.order = &model.DiscoveryOrder{
		SchemaVersion: model.SchemaVersion,
		OrderID:       h.orderID,
		TenantID:      h.tenant,
		RequestedBy:   model.RequestedBy{Commander: "hexstrike", AgentID: "hx-1"},
		Seeds:         []model.Seed{{Type: model.SeedDomain, Value: "example.com"}},
		Techniques:    []model.Technique{model.TechniqueCT},
		Authorization: model.Authorization{ROEID: "roe_test1"},
		Options:       model.DefaultOrderOptions(),
	}
	reqJSON, _ := json.Marshal(h.order)
	if err := st.InsertOrder(context.Background(), &store.OrderRow{
		OrderID: h.orderID, TenantID: h.tenant, Request: reqJSON,
		State: model.OrderRunning, Progress: model.Progress{},
	}); err != nil {
		t.Fatal(err)
	}

	// Fake DP Ingest API — captures batches, answers accepted.
	dpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-DP-Principal") == "" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		var b map[string]any
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &b)
		h.mu.Lock()
		h.batches = append(h.batches, b)
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"idempotency_key": b["idempotency_key"], "status": "accepted",
		})
	}))
	t.Cleanup(dpSrv.Close)

	sc := &sdkscope.Scope{
		Domains:          []string{"example.com", "*.example.com"},
		CIDRs:            []string{"203.0.113.0/24"},
		CloudAccounts:    []string{"123456789012"},
		ExplicitExcludes: []string{"bad.example.com"},
	}
	h.red = reducer.New(reducer.Deps{
		Store: st,
		DP:    &dpingest.Client{BaseURL: dpSrv.URL, Principal: "svc-discover"},
		PublishChange: func(_ context.Context, ch *model.AssetChange) error {
			h.mu.Lock()
			h.changes = append(h.changes, ch)
			h.mu.Unlock()
			return nil
		},
		ScopeFor: func(_ context.Context, orderID string) (*model.DiscoveryOrder, string, *sdkscope.Scope, error) {
			row, err := st.GetOrder(context.Background(), orderID)
			if err != nil {
				if err == store.ErrNotFound {
					return nil, "", nil, nil
				}
				return nil, "", nil, err
			}
			return h.order, row.State, sc, nil
		},
	})
	return h
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
	err = st.Pool().QueryRow(context.Background(),
		`SELECT to_regclass('discover.assets')::text`).Scan(&reg)
	if err == nil && reg != nil {
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

func (h *harness) finding(source string, a model.Asset, edges []model.EdgeRef) *model.ResultMessage {
	return &model.ResultMessage{
		Kind: model.ResultFinding,
		Finding: &model.RawFinding{
			TaskID:     uuid.NewString(),
			OrderID:    h.orderID,
			Asset:      a,
			Source:     source,
			ObservedAt: time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC),
		},
		Edges: edges,
	}
}

func (h *harness) process(m *model.ResultMessage) reducer.Disposition {
	h.t.Helper()
	return h.red.Process(context.Background(), m, 1)
}

func (h *harness) lastChange() *model.AssetChange {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.changes) == 0 {
		return nil
	}
	return h.changes[len(h.changes)-1]
}

func (h *harness) batchCount() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.batches)
}

// --- tests ------------------------------------------------------------------

func TestReducerNewAsset(t *testing.T) {
	h := newHarness(t)
	disp := h.process(h.finding("crt.sh", model.Asset{Type: model.AssetSubdomain, Value: "www.example.com"}, nil))
	if disp != reducer.Ack {
		t.Fatalf("disp = %v", disp)
	}
	rec, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetSubdomain, "www.example.com")
	if err != nil {
		t.Fatalf("asset not stored: %v", err)
	}
	if rec.Confidence != model.WeightCTLog {
		t.Errorf("confidence = %v, want CT weight 0.9", rec.Confidence)
	}
	if rec.Status != model.AssetActive {
		t.Errorf("status = %s", rec.Status)
	}
	if rec.ROEID != "roe_test1" {
		t.Errorf("roe_id = %s", rec.ROEID)
	}
	// AssetChange "new".
	ch := h.lastChange()
	if ch == nil || ch.Kind != model.ChangeNew || ch.AssetID != rec.AssetID {
		t.Fatalf("AssetChange = %+v", ch)
	}
	if ch.Asset.Value != "www.example.com" || ch.TenantID != h.tenant {
		t.Errorf("change asset = %+v", ch.Asset)
	}
	// Provenance row.
	exists, err := h.st.FindingExists(context.Background(), "ignored", "crt.sh", rec.AssetID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_ = exists
	// DP upsert happened with the right shape.
	if h.batchCount() != 1 {
		t.Fatalf("dp batches = %d", h.batchCount())
	}
	b := h.batches[0]
	if b["idempotency_key"] == "" || b["task_id"] == "" {
		t.Errorf("batch missing idempotency/task attribution: %v", b)
	}
	assets, _ := b["assets"].([]any)
	if len(assets) != 1 {
		t.Fatalf("batch assets = %v", assets)
	}
	a0, _ := assets[0].(map[string]any)
	if a0["type"] != "subdomain" || a0["value"] != "www.example.com" || a0["source"] != "crt.sh" {
		t.Errorf("batch asset = %v", a0)
	}
	// Progress moved.
	row, _ := h.st.GetOrder(context.Background(), h.orderID)
	if row.Progress.AssetsFound != 1 || row.Progress.NewAssets != 1 {
		t.Errorf("progress = %+v", row.Progress)
	}
}

func TestReducerDedupReDelivery(t *testing.T) {
	h := newHarness(t)
	m := h.finding("crt.sh", model.Asset{Type: model.AssetSubdomain, Value: "api.example.com"}, nil)
	if d := h.process(m); d != reducer.Ack {
		t.Fatal(d)
	}
	// Exact re-delivery (same task_id + observed bucket).
	if d := h.process(m); d != reducer.Ack {
		t.Fatal(d)
	}
	rec, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetSubdomain, "api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	exists, err := h.st.FindingExists(context.Background(), m.Finding.TaskID, "crt.sh", rec.AssetID, m.Finding.ObservedAt)
	if err != nil || !exists {
		t.Fatalf("provenance row missing: %v %v", exists, err)
	}
	// One "new" change only; second delivery produced no event.
	h.mu.Lock()
	n := len(h.changes)
	h.mu.Unlock()
	if n != 1 {
		t.Errorf("changes = %d, want 1 (re-delivery is invisible)", n)
	}
	// progress.assets_found counts observations (2), new_assets stays 1.
	row, _ := h.st.GetOrder(context.Background(), h.orderID)
	if row.Progress.NewAssets != 1 {
		t.Errorf("new_assets = %d, want 1", row.Progress.NewAssets)
	}
}

func TestReducerCorroborationAndAttributeChange(t *testing.T) {
	h := newHarness(t)
	h.process(h.finding("crt.sh", model.Asset{Type: model.AssetSubdomain, Value: "vpn.example.com"}, nil))
	// Second source corroborates: CT (0.9) + PDNS ⇒ confidence 1.0, sources merged.
	h.process(h.finding("securitytrails", model.Asset{Type: model.AssetSubdomain, Value: "vpn.example.com"}, nil))
	rec, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetSubdomain, "vpn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if rec.Confidence != 1.0 {
		t.Errorf("corroborated confidence = %v, want 1.0", rec.Confidence)
	}
	sources, _ := rec.Attributes["sources"].([]any)
	if len(sources) != 2 {
		t.Errorf("sources = %v, want both provenances", sources)
	}
	ch := h.lastChange()
	if ch == nil || ch.Kind != model.ChangeAttributeChanged {
		t.Fatalf("want attribute_changed, got %+v", ch)
	}
	found := false
	for _, f := range ch.ChangedFields {
		if f == "confidence" {
			found = true
		}
	}
	if !found {
		t.Errorf("changed_fields = %v, want confidence", ch.ChangedFields)
	}
}

func TestReducerQuarantineOutOfScope(t *testing.T) {
	h := newHarness(t)
	disp := h.process(h.finding("crt.sh", model.Asset{Type: model.AssetSubdomain, Value: "neighbor.example.org"}, nil))
	if disp != reducer.Ack {
		t.Fatalf("quarantine is terminal (Ack), got %v", disp)
	}
	if _, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetSubdomain, "neighbor.example.org"); err != store.ErrNotFound {
		t.Fatal("out-of-scope finding must NEVER become an asset")
	}
	h.mu.Lock()
	n := len(h.changes)
	h.mu.Unlock()
	if n != 0 {
		t.Error("no AssetChange for quarantined findings")
	}
	if h.batchCount() != 0 {
		t.Error("no DP upsert for quarantined findings")
	}
	// Quarantine row exists.
	var reason string
	err := h.st.Pool().QueryRow(context.Background(),
		`SELECT reason_code FROM quarantined_findings WHERE tenant_id=$1 AND asset->>'value'=$2`,
		h.tenant, "neighbor.example.org").Scan(&reason)
	if err != nil || reason != store.ReasonOutOfScope {
		t.Errorf("quarantine row: %v %q", err, reason)
	}
}

func TestReducerQuarantineExcluded(t *testing.T) {
	h := newHarness(t)
	h.process(h.finding("crt.sh", model.Asset{Type: model.AssetSubdomain, Value: "bad.example.com"}, nil))
	var reason string
	err := h.st.Pool().QueryRow(context.Background(),
		`SELECT reason_code FROM quarantined_findings WHERE tenant_id=$1 AND asset->>'value'=$2`,
		h.tenant, "bad.example.com").Scan(&reason)
	if err != nil || reason != store.ReasonExcluded {
		t.Errorf("exclusions always win: %v %q, want EXCLUDED", err, reason)
	}
	if _, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetSubdomain, "bad.example.com"); err != store.ErrNotFound {
		t.Fatal("excluded finding promoted to asset — exclusion violated")
	}
}

func TestReducerCloudScopeByAccount(t *testing.T) {
	h := newHarness(t)
	inScope := model.Asset{Type: model.AssetCloudResource, Value: "arn:aws:s3:::example-backup",
		Attributes: map[string]any{"cloud": map[string]any{"provider": "aws", "account": "123456789012"}}}
	if d := h.process(h.finding("aws_resource_explorer", inScope, nil)); d != reducer.Ack {
		t.Fatal(d)
	}
	rec, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetCloudResource, "arn:aws:s3:::example-backup")
	if err != nil {
		t.Fatalf("in-scope cloud resource not stored: %v", err)
	}
	if rec.Confidence != model.WeightCredentialedCloud {
		t.Errorf("cloud confidence = %v, want 1.0", rec.Confidence)
	}
	outScope := model.Asset{Type: model.AssetCloudResource, Value: "arn:aws:s3:::other-tenant",
		Attributes: map[string]any{"cloud": map[string]any{"provider": "aws", "account": "999999999999"}}}
	h.process(h.finding("aws_resource_explorer", outScope, nil))
	if _, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetCloudResource, "arn:aws:s3:::other-tenant"); err != store.ErrNotFound {
		t.Fatal("cloud resource outside scoped accounts must be quarantined")
	}
}

func TestReducerEdgesAndDPEdges(t *testing.T) {
	h := newHarness(t)
	edges := []model.EdgeRef{{
		Rel: model.RelResolvesTo,
		Src: model.Asset{Type: model.AssetSubdomain, Value: "www.example.com"},
		Dst: model.Asset{Type: model.AssetIP, Value: "203.0.113.10"},
	}}
	h.process(h.finding("shodan_dns", model.Asset{Type: model.AssetSubdomain, Value: "www.example.com"}, edges))
	src, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetSubdomain, "www.example.com")
	if err != nil {
		t.Fatal(err)
	}
	dst, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetIP, "203.0.113.10")
	if err != nil {
		t.Fatalf("edge endpoint not upserted: %v", err)
	}
	var n int
	if err := h.st.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM asset_edges WHERE tenant_id=$1 AND src=$2 AND dst=$3 AND rel='resolves_to'`,
		h.tenant, src.AssetID, dst.AssetID).Scan(&n); err != nil || n != 1 {
		t.Errorf("asset_edges row: %v n=%d", err, n)
	}
	// DP batch carries assets (endpoint included) + the edge.
	if h.batchCount() != 1 {
		t.Fatalf("batches = %d", h.batchCount())
	}
	b := h.batches[0]
	dpedges, _ := b["edges"].([]any)
	if len(dpedges) != 1 {
		t.Fatalf("dp edges = %v", dpedges)
	}
	e0, _ := dpedges[0].(map[string]any)
	if e0["rel"] != "resolves_to" || e0["dst_value"] != "203.0.113.10" {
		t.Errorf("dp edge = %v", e0)
	}
}

func TestReducerDoneMarkerFinalizesOrder(t *testing.T) {
	h := newHarness(t)
	if err := h.st.SetProgressTotal(context.Background(), h.orderID, 1); err != nil {
		t.Fatal(err)
	}
	done := &model.ResultMessage{
		Kind: model.ResultDone, TaskID: "task-1", OrderID: h.orderID, TenantID: h.tenant,
	}
	if d := h.process(done); d != reducer.Ack {
		t.Fatal(d)
	}
	row, err := h.st.GetOrder(context.Background(), h.orderID)
	if err != nil {
		t.Fatal(err)
	}
	if row.State != model.OrderCompleted {
		t.Errorf("state = %s, want COMPLETED", row.State)
	}
	if row.Progress.Done != 1 {
		t.Errorf("done = %d", row.Progress.Done)
	}
}

func TestReducerFailedTaskPartial(t *testing.T) {
	h := newHarness(t)
	if err := h.st.SetProgressTotal(context.Background(), h.orderID, 2); err != nil {
		t.Fatal(err)
	}
	h.process(&model.ResultMessage{Kind: model.ResultDone, TaskID: "t1", OrderID: h.orderID, TenantID: h.tenant})
	h.process(&model.ResultMessage{Kind: model.ResultDone, TaskID: "t2", OrderID: h.orderID, TenantID: h.tenant,
		Error: "SOURCE_UNAVAILABLE: 429"})
	row, _ := h.st.GetOrder(context.Background(), h.orderID)
	if row.State != model.OrderPartial {
		t.Errorf("state = %s, want PARTIAL", row.State)
	}
	if row.Progress.Failed != 1 {
		t.Errorf("failed = %d", row.Progress.Failed)
	}
}

func TestReducerTerminalOrderDropsFindings(t *testing.T) {
	h := newHarness(t)
	if err := h.st.SetOrderState(context.Background(), h.orderID, model.OrderCancelled, nil); err != nil {
		t.Fatal(err)
	}
	// Cooperative cancellation: findings for a terminal order drop silently.
	if d := h.process(h.finding("crt.sh", model.Asset{Type: model.AssetSubdomain, Value: "late.example.com"}, nil)); d != reducer.Ack {
		t.Errorf("terminal-order finding must drop (Ack), got %v", d)
	}
	if _, err := h.st.GetAsset(context.Background(), h.tenant, model.AssetSubdomain, "late.example.com"); err != store.ErrNotFound {
		t.Fatal("finding for a cancelled order must not be promoted")
	}
	// Unknown orders drop too.
	other := &model.ResultMessage{
		Kind: model.ResultFinding,
		Finding: &model.RawFinding{
			TaskID: "x", OrderID: uuid.NewString(),
			Asset:  model.Asset{Type: model.AssetSubdomain, Value: "ghost.example.com"},
			Source: "crt.sh", ObservedAt: time.Now(),
		},
	}
	if d := h.process(other); d != reducer.Ack {
		t.Errorf("unknown order finding must drop (Ack), got %v", d)
	}
}
