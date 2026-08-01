package queryapi_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/lifecycle"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/queryapi"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/testenv"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/tpel"
)

func advance(from, to string) ([]string, bool) {
	p, ok := lifecycle.Path(lifecycle.State(from), lifecycle.State(to))
	if !ok {
		return nil, false
	}
	out := make([]string, len(p))
	for i, s := range p {
		out[i] = string(s)
	}
	return out, true
}

// fixture seeds two tenants with graph-shaped data and returns the gql
// handler (TPEL middleware in front) plus the ids.
type fixture struct {
	handler   http.Handler
	tenantA   string
	tenantB   string
	assetAID  string // tenant A domain
	assetBID  string // tenant B domain
	findingID string // tenant A finding
}

func setup(t *testing.T) *fixture {
	t.Helper()
	st := testenv.Store(t)
	ctx := context.Background()
	f := &fixture{}

	f.tenantA = testenv.Tenant(t, st, "gql-a")
	f.tenantB = testenv.Tenant(t, st, "gql-b")
	testenv.Grant(t, st, f.tenantA, "gql-analyst-a", "analyst")
	testenv.Grant(t, st, f.tenantA, "gql-viewer-a", "viewer")
	testenv.Grant(t, st, f.tenantB, "gql-analyst-b", "analyst")

	actor := store.Actor{Type: "service", ID: "svc-detect"}
	tx, _ := st.Pool.Begin(ctx)
	dom, err := store.UpsertAssetTx(ctx, tx, f.tenantA, store.AssetUpsert{
		Type: "domain", Value: "gql-a.example", RoeID: "roe_1"})
	if err != nil {
		t.Fatal(err)
	}
	f.assetAID = dom.AssetID
	sub, _ := store.UpsertAssetTx(ctx, tx, f.tenantA, store.AssetUpsert{
		Type: "subdomain", Value: "api.gql-a.example", RoeID: "roe_1"})
	if _, err := store.UpsertEdgeTx(ctx, tx, f.tenantA, store.EdgeUpsert{
		SrcAssetID: sub.AssetID, DstAssetID: dom.AssetID, Rel: "resolves_to"}); err != nil {
		t.Fatal(err)
	}
	fout, err := store.UpsertFindingTx(ctx, tx, f.tenantA, store.FindingUpsert{
		AssetUID: sub.AssetID, Module: store.ModuleDetect, CheckID: "CVE-2024-GQL",
		Title: "gql finding", Severity: "critical", State: "confirmed_open",
		Fingerprint: "gql-fp", EvidenceRef: "s3://evidence/a/blob.enc",
		TaskID: "tsk_gql", Sensitive: true,
	}, actor, advance)
	if err != nil {
		t.Fatal(err)
	}
	f.findingID = fout.FindingID
	tx.Commit(ctx)

	tx, _ = st.Pool.Begin(ctx)
	bdom, _ := store.UpsertAssetTx(ctx, tx, f.tenantB, store.AssetUpsert{
		Type: "domain", Value: "gql-b.example", RoeID: "roe_2"})
	f.assetBID = bdom.AssetID
	tx.Commit(ctx)

	gql := queryapi.NewHandler(queryapi.NewResolver(st, 500, 4, nil))
	f.handler = tpel.NewResolver(st).Middleware(gql)
	return f
}

// gql posts one GraphQL operation as principal and decodes the response.
func (f *fixture) gql(t *testing.T, principal, query string, vars map[string]any) map[string]any {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	req := httptest.NewRequest(http.MethodPost, "/v1/query", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	if principal != "" {
		req.Header.Set("X-DP-Principal", principal)
	}
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("graphql status %d: %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("graphql decode: %v (%s)", err, rec.Body.String())
	}
	return out
}

func data(t *testing.T, resp map[string]any) map[string]any {
	t.Helper()
	if errs, ok := resp["errors"]; ok {
		t.Fatalf("graphql errors: %v", errs)
	}
	d, _ := resp["data"].(map[string]any)
	return d
}

func TestGraphQLAssetsTenantScoped(t *testing.T) {
	f := setup(t)
	d := data(t, f.gql(t, "gql-analyst-a", `
		query { assets { nodes { uid type value } pageInfo { totalCount hasNextPage } } }`, nil))
	conn := d["assets"].(map[string]any)
	if conn["pageInfo"].(map[string]any)["totalCount"].(float64) != 2 {
		t.Fatalf("tenant A totalCount = %v", conn["pageInfo"])
	}
	for _, n := range conn["nodes"].([]any) {
		v := n.(map[string]any)["value"].(string)
		if !strings.HasSuffix(v, "gql-a.example") {
			t.Fatalf("tenant A query returned foreign asset %q", v)
		}
	}

	// Tenant B principal sees only its own asset.
	d = data(t, f.gql(t, "gql-analyst-b", `
		query { assets { nodes { value } pageInfo { totalCount } } }`, nil))
	conn = d["assets"].(map[string]any)
	if conn["pageInfo"].(map[string]any)["totalCount"].(float64) != 1 {
		t.Fatalf("tenant B totalCount = %v", conn["pageInfo"])
	}
}

func TestGraphQLCrossTenantByUID(t *testing.T) {
	f := setup(t)
	// Tenant B asks for tenant A's asset by uid: null, not data.
	d := data(t, f.gql(t, "gql-analyst-b", `
		query ($id: ID!) { asset(uid: $id) { uid value } }`, map[string]any{"id": f.assetAID}))
	if d["asset"] != nil {
		t.Fatalf("cross-tenant asset read returned data: %v", d["asset"])
	}
	d = data(t, f.gql(t, "gql-analyst-b", `
		query ($id: ID!) { finding(id: $id) { findingId } }`, map[string]any{"id": f.findingID}))
	if d["finding"] != nil {
		t.Fatalf("cross-tenant finding read returned data: %v", d["finding"])
	}
}

func TestGraphQLNeighborhood(t *testing.T) {
	f := setup(t)
	d := data(t, f.gql(t, "gql-analyst-a", `
		query ($id: ID!) { assetNeighborhood(uid: $id, depth: 2) {
			root { value } assets { value } edges { rel src dst } } }`,
		map[string]any{"id": f.assetAID}))
	nb := d["assetNeighborhood"].(map[string]any)
	if len(nb["assets"].([]any)) != 2 || len(nb["edges"].([]any)) != 1 {
		t.Fatalf("neighborhood = %v", nb)
	}

	// Depth beyond the cap is rejected (query cost control, doc 09 §5).
	resp := f.gql(t, "gql-analyst-a", `
		query ($id: ID!) { assetNeighborhood(uid: $id, depth: 5) { assets { value } } }`,
		map[string]any{"id": f.assetAID})
	if resp["errors"] == nil {
		t.Fatal("depth 5 accepted — cap is 4")
	}
}

func TestGraphQLFindingsPaginationAndMasking(t *testing.T) {
	f := setup(t)
	d := data(t, f.gql(t, "gql-analyst-a", `
		query { findings(first: 1) {
			nodes { findingId severity state evidenceRef sensitive
			        transitions { fromState toState } }
			pageInfo { totalCount hasNextPage endCursor } } }`, nil))
	conn := d["findings"].(map[string]any)
	pi := conn["pageInfo"].(map[string]any)
	if pi["totalCount"].(float64) != 1 {
		t.Fatalf("totalCount = %v", pi)
	}
	node := conn["nodes"].([]any)[0].(map[string]any)
	if node["state"] != "confirmed_open" || node["severity"] != "critical" {
		t.Fatalf("finding node = %v", node)
	}
	// Analyst (non-viewer) reads the sensitive evidence ref — and is audited.
	if node["evidenceRef"] != "s3://evidence/a/blob.enc" {
		t.Fatalf("analyst evidenceRef = %v", node["evidenceRef"])
	}
	trs := node["transitions"].([]any)
	if len(trs) != 3 {
		t.Fatalf("transitions = %v", trs)
	}

	// Viewer-role: evidence ref on the sensitive finding is masked (doc 09 §9.5).
	d = data(t, f.gql(t, "gql-viewer-a", `
		query { findings { nodes { evidenceRef sensitive } } }`, nil))
	vnode := d["findings"].(map[string]any)["nodes"].([]any)[0].(map[string]any)
	if !strings.HasPrefix(vnode["evidenceRef"].(string), "masked:") {
		t.Fatalf("viewer evidenceRef = %v, want masked", vnode["evidenceRef"])
	}
}

func TestGraphQLTaskRollup(t *testing.T) {
	f := setup(t)
	d := data(t, f.gql(t, "gql-analyst-a", `
		query ($id: ID!) { taskRollup(taskId: $id) {
			taskId findingsProduced findingsBySeverity } }`,
		map[string]any{"id": "tsk_gql"}))
	ru := d["taskRollup"].(map[string]any)
	if ru["findingsProduced"].(float64) != 1 {
		t.Fatalf("rollup = %v", ru)
	}
	// Cross-tenant rollup is null.
	d = data(t, f.gql(t, "gql-analyst-b", `
		query ($id: ID!) { taskRollup(taskId: $id) { taskId } }`,
		map[string]any{"id": "tsk_gql"}))
	if d["taskRollup"] != nil {
		t.Fatal("cross-tenant rollup returned data")
	}
}

func TestGraphQLRequiresIdentity(t *testing.T) {
	f := setup(t)
	// No principal header: TPEL middleware rejects before GraphQL executes.
	body := strings.NewReader(`{"query":"{ assets { nodes { uid } } }"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/query", body)
	rec := httptest.NewRecorder()
	f.handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("unauthenticated query: status %d, want 403", rec.Code)
	}
}
