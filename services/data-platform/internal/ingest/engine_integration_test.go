package ingest_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/config"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/events"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/httpapi"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/ingest"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/scopeverify"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/testenv"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/tpel"
)

// newEngine builds an ingest engine with token checks disabled (R0 passive
// ingest — doc 09 §8) and a nil-JetStream publisher writing to a temp spill.
func newEngine(t *testing.T, st *store.Store) *ingest.Engine {
	t.Helper()
	pub := events.New(nil, t.TempDir()+"/spill.jsonl", nil)
	return ingest.New(st, nil, pub, nil)
}

func countRows(t *testing.T, st *store.Store, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.Pool.QueryRow(context.Background(), query, args...).Scan(&n); err != nil {
		t.Fatalf("count: %v", err)
	}
	return n
}

func TestIngestIdempotentReplay(t *testing.T) {
	st := testenv.Store(t)
	tenant := testenv.Tenant(t, st, "ingest-idem")
	eng := newEngine(t, st)
	actor := store.Actor{Type: "service", ID: "svc-discover-httprtt"}

	batch := &ingest.Batch{
		IdempotencyKey: "test-idem-1",
		TaskID:         "tsk_test_idem",
		Assets: []ingest.AssetIn{
			{Type: "domain", Value: "Example.COM.", RoeID: "roe_1", Source: "crt.sh", Confidence: fp(0.9)},
			{Type: "subdomain", Value: "*.API.Example.com", RoeID: "roe_1", Source: "crt.sh"},
			{Type: "ip", Value: "203.0.113.10", RoeID: "roe_1"},
		},
		Edges: []ingest.EdgeIn{
			{SrcType: "subdomain", SrcValue: "api.example.com",
				DstType: "domain", DstValue: "example.com", Rel: "resolves_to"},
		},
		Findings: []ingest.FindingIn{
			{AssetType: "subdomain", AssetValue: "api.example.com",
				Module: "phish-catcher", CheckID: "phish-catcher/url-lookalike",
				Title: "Lookalike URL", Severity: "low", Fingerprint: "fp-idem-1"},
		},
	}

	res1, prob := eng.Apply(context.Background(), actor, tenant, batch)
	if prob != nil {
		t.Fatalf("first apply: %s: %s", prob.Reason, prob.Detail)
	}
	if res1.Replay {
		t.Fatal("first apply flagged as replay")
	}
	if res1.Counts.AssetsCreated != 3 || res1.Counts.EdgesUpserted != 1 || res1.Counts.FindingsInserted != 1 {
		t.Fatalf("counts = %+v", res1.Counts)
	}
	// Canonicalization: punycode-lowercase, trailing dot + "*." stripped.
	if got := countRows(t, st,
		`SELECT count(*) FROM dp.assets WHERE tenant_id=$1 AND value='api.example.com'`, tenant); got != 1 {
		t.Fatalf("canonical asset row count = %d", got)
	}

	// Retry with the same key: no-op replay with the recorded outcome
	// (doc 09 §8: duplicate ingest ⇒ idempotency key + deterministic upsert).
	res2, prob := eng.Apply(context.Background(), actor, tenant, batch)
	if prob != nil {
		t.Fatalf("replay apply: %s: %s", prob.Reason, prob.Detail)
	}
	if !res2.Replay {
		t.Fatal("second apply not flagged as replay")
	}
	if res2.Counts != res1.Counts {
		t.Fatalf("replay counts %+v ≠ original %+v", res2.Counts, res1.Counts)
	}
	if got := countRows(t, st, `SELECT count(*) FROM dp.assets WHERE tenant_id=$1`, tenant); got != 3 {
		t.Fatalf("assets after replay = %d, want 3", got)
	}
	if got := countRows(t, st, `SELECT count(*) FROM dp.asset_edges WHERE tenant_id=$1`, tenant); got != 1 {
		t.Fatalf("edges after replay = %d, want 1", got)
	}
	if got := countRows(t, st, `SELECT count(*) FROM dp.findings WHERE tenant_id=$1`, tenant); got != 1 {
		t.Fatalf("findings after replay = %d, want 1", got)
	}

	// Same key under a different tenant never reveals the other tenant's
	// outcome (fail-closed TENANT_MISMATCH).
	other := testenv.Tenant(t, st, "ingest-idem-other")
	if _, prob := eng.Apply(context.Background(), actor, other, batch); prob == nil ||
		prob.Reason != "TENANT_MISMATCH" {
		t.Fatalf("cross-tenant key reuse: prob = %+v", prob)
	}
}

func TestIngestValidationAndTenantBinding(t *testing.T) {
	st := testenv.Store(t)
	tenant := testenv.Tenant(t, st, "ingest-bind")
	eng := newEngine(t, st)
	actor := store.Actor{Type: "service", ID: "svc-monitor"}

	// Payload tenant must never override the credential tenant (doc 09 §2.2).
	other := testenv.Tenant(t, st, "ingest-bind-other")
	b := &ingest.Batch{
		IdempotencyKey: "test-bind-1",
		TenantID:       other,
		Assets:         []ingest.AssetIn{{Type: "domain", Value: "x.example", RoeID: "roe_1"}},
	}
	if _, prob := eng.Apply(context.Background(), actor, tenant, b); prob == nil ||
		prob.Reason != "TENANT_MISMATCH" {
		t.Fatalf("payload tenant override: prob = %+v", prob)
	}

	// Schema validation (SCHEMA_INVALID): unknown asset kind, bad severity.
	bad := &ingest.Batch{
		IdempotencyKey: "test-bind-2",
		Assets:         []ingest.AssetIn{{Type: "server", Value: "x", RoeID: "roe_1"}},
	}
	if _, prob := eng.Apply(context.Background(), actor, tenant, bad); prob == nil ||
		prob.Reason != "SCHEMA_INVALID" {
		t.Fatalf("bad asset kind: prob = %+v", prob)
	}
	bad2 := &ingest.Batch{
		IdempotencyKey: "test-bind-3",
		Assets:         []ingest.AssetIn{{Type: "domain", Value: "ok.example", RoeID: "roe_1"}},
		Findings: []ingest.FindingIn{{
			AssetType: "domain", AssetValue: "ok.example",
			Module: "detect", CheckID: "c", Title: "t", Severity: "apocalyptic",
		}},
	}
	if _, prob := eng.Apply(context.Background(), actor, tenant, bad2); prob == nil ||
		prob.Reason != "SCHEMA_INVALID" {
		t.Fatalf("bad severity: prob = %+v", prob)
	}

	// Rejections are ledgered + audited (doc 09 §2.2/§4.4).
	if got := countRows(t, st,
		`SELECT count(*) FROM dp.ingest_batches WHERE tenant_id=$1 AND status='rejected'`, tenant); got < 2 {
		t.Fatalf("rejected batches ledgered = %d, want ≥ 2", got)
	}
	if got := countRows(t, st,
		`SELECT count(*) FROM dp.audit_outbox WHERE tenant_id=$1 AND action='ingest.rejected'`, tenant); got < 2 {
		t.Fatalf("ingest.rejected audit rows = %d, want ≥ 2", got)
	}
}

func TestIngestScopeTokenEnforcement(t *testing.T) {
	st := testenv.Store(t)
	tenant := testenv.Tenant(t, st, "ingest-token")

	// A verifier whose JWKS is unreachable: every R1+ batch must be rejected
	// fail-closed (doc 09 §8), R0 passive continues without a token.
	verifier := scopeverify.NewWithSources(token.KeySourceFunc(
		func(ctx context.Context) ([]token.JWK, error) { return nil, errors.New("jwks down") }),
		manifest.FetcherFunc(func(ctx context.Context, u string) ([]byte, error) {
			return nil, errors.New("no manifests")
		}))
	eng := ingest.New(st, verifier, events.New(nil, t.TempDir()+"/spill.jsonl", nil), nil)
	actor := store.Actor{Type: "service", ID: "svc-detect"}

	r1 := &ingest.Batch{
		IdempotencyKey: "test-tok-1",
		RiskClass:      "R1",
		TaskID:         "tsk_x",
		Assets:         []ingest.AssetIn{{Type: "domain", Value: "target.example", RoeID: "roe_1"}},
	}
	if _, prob := eng.Apply(context.Background(), actor, tenant, r1); prob == nil ||
		prob.Reason != "AUTHORIZATION_UNVERIFIABLE" {
		t.Fatalf("R1 without token: prob = %+v, want AUTHORIZATION_UNVERIFIABLE", prob)
	}

	// Offensive-module findings force the token requirement even when the
	// batch's risk_class is unset (doc 09 §9.1).
	off := &ingest.Batch{
		IdempotencyKey: "test-tok-2",
		Assets:         []ingest.AssetIn{{Type: "domain", Value: "target2.example", RoeID: "roe_1"}},
		Findings: []ingest.FindingIn{{
			AssetType: "domain", AssetValue: "target2.example",
			Module: "detect", CheckID: "CVE-2024-0001", Title: "t", Severity: "high",
		}},
	}
	if _, prob := eng.Apply(context.Background(), actor, tenant, off); prob == nil ||
		prob.Reason != "AUTHORIZATION_UNVERIFIABLE" {
		t.Fatalf("offensive-module batch without token: prob = %+v", prob)
	}

	// R0 passive ingest proceeds on service creds alone.
	r0 := &ingest.Batch{
		IdempotencyKey: "test-tok-3",
		RiskClass:      "R0",
		Assets:         []ingest.AssetIn{{Type: "domain", Value: "passive.example", RoeID: "roe_1"}},
	}
	if _, prob := eng.Apply(context.Background(), actor, tenant, r0); prob != nil {
		t.Fatalf("R0 ingest rejected: %s: %s", prob.Reason, prob.Detail)
	}
}

// TestIngestHTTPRoundTrip exercises the REST endpoint end-to-end: TPEL
// headers → tenant resolution → engine → ledgered replay.
func TestIngestHTTPRoundTrip(t *testing.T) {
	st := testenv.Store(t)
	tenant := testenv.Tenant(t, st, "ingest-http")
	testenv.Grant(t, st, tenant, "svc-discover-httprtt", "service_discover")
	testenv.Grant(t, st, tenant, "analyst-httprtt", "analyst")

	srv := httpapi.NewServer(&httpapi.Deps{
		Cfg:    &config.Config{},
		Store:  st,
		Engine: newEngine(t, st),
		TPEL:   tpel.NewResolver(st),
	})
	mux := http.NewServeMux()
	srv.Mount(mux, nil)

	body := []byte(`{
	  "idempotency_key": "test-http-1",
	  "task_id": "tsk_http",
	  "assets": [{"type":"domain","value":"http.example","roe_id":"roe_1","source":"crt.sh"}]
	}`)

	do := func(principal string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/ingest/batch", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if principal != "" {
			req.Header.Set("X-DP-Principal", principal)
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec
	}

	// Unknown principal: fail-closed (GRANT_REQUIRED).
	if rec := do("nobody"); rec.Code != http.StatusForbidden {
		t.Fatalf("unknown principal: status %d", rec.Code)
	}
	// Viewer-role principal may not ingest.
	if rec := do("analyst-httprtt"); rec.Code != http.StatusForbidden {
		t.Fatalf("analyst ingest: status %d", rec.Code)
	}
	// Service grant: accepted.
	rec := do("svc-discover-httprtt")
	if rec.Code != http.StatusOK {
		t.Fatalf("ingest: status %d body %s", rec.Code, rec.Body.String())
	}
	// Replay over HTTP: idempotent.
	rec2 := do("svc-discover-httprtt")
	if rec2.Code != http.StatusOK {
		t.Fatalf("replay: status %d", rec2.Code)
	}
	var out struct {
		Replay bool `json:"replay"`
	}
	if err := json.Unmarshal(rec2.Body.Bytes(), &out); err != nil || !out.Replay {
		t.Fatalf("replay body = %s (err %v)", rec2.Body.String(), err)
	}
	if got := countRows(t, st,
		`SELECT count(*) FROM dp.assets WHERE tenant_id=$1 AND value='http.example'`, tenant); got != 1 {
		t.Fatalf("asset rows = %d, want 1", got)
	}
}

func fp(f float64) *float64 { return &f }
