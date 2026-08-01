package store_test

import (
	"context"
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/lifecycle"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/testenv"
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

var testActor = store.Actor{Type: "service", ID: "svc-detect"}

// seedFinding inserts one finding with its asset via the store upsert path.
func seedFinding(t *testing.T, st *store.Store, tenant, fp, state string) string {
	t.Helper()
	ctx := context.Background()
	tx, err := st.Pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	aout, err := store.UpsertAssetTx(ctx, tx, tenant, store.AssetUpsert{
		Type: "subdomain", Value: "host-" + fp + ".example.com", RoeID: "roe_1",
	})
	if err != nil {
		t.Fatal(err)
	}
	fout, err := store.UpsertFindingTx(ctx, tx, tenant, store.FindingUpsert{
		AssetUID: aout.AssetID, Module: store.ModuleDetect, CheckID: "CVE-2024-TEST",
		Title: "test", Severity: "high", State: state, Fingerprint: fp,
	}, testActor, advance)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	return fout.FindingID
}

func TestLifecycleTransitions(t *testing.T) {
	st := testenv.Store(t)
	tenant := testenv.Tenant(t, st, "lifecycle")
	ctx := context.Background()

	// Ingest proposing confirmed_open advances new→…→confirmed_open, one
	// recorded hop per edge (doc 04 §7.3 persisted by 09).
	fid := seedFinding(t, st, tenant, "lc-1", "confirmed_open")
	f, err := st.GetFinding(ctx, tenant, fid)
	if err != nil || f == nil {
		t.Fatalf("get finding: %v", err)
	}
	if f.State != "confirmed_open" {
		t.Fatalf("state = %q, want confirmed_open", f.State)
	}
	trs, err := st.ListTransitions(ctx, tenant, fid)
	if err != nil {
		t.Fatal(err)
	}
	if len(trs) != 3 { // new→triaged→validating→confirmed_open
		t.Fatalf("transitions = %d, want 3: %+v", len(trs), trs)
	}

	// Legal operator hop: confirmed_open → remediation_claimed.
	tx, _ := st.Pool.Begin(ctx)
	from, changed, ok, err := store.ApplyTransitionTx(ctx, tx, tenant, fid,
		"remediation_claimed", testActor, "tsk_rev", "fix claimed")
	if err != nil || !ok || !changed || from != "confirmed_open" {
		t.Fatalf("legal transition: from=%q changed=%v ok=%v err=%v", from, changed, ok, err)
	}
	tx.Commit(ctx)

	// Illegal hop: remediation_claimed → triaged (not a doc 04 §7.3 edge).
	tx, _ = st.Pool.Begin(ctx)
	_, _, ok, err = store.ApplyTransitionTx(ctx, tx, tenant, fid,
		"triaged", testActor, "", "")
	if err != nil || ok {
		t.Fatalf("illegal transition accepted: ok=%v err=%v", ok, err)
	}
	tx.Rollback(ctx)

	// detect.revalidate drives remediation_claimed → verified_closed.
	tx, _ = st.Pool.Begin(ctx)
	_, changed, ok, err = store.ApplyTransitionTx(ctx, tx, tenant, fid,
		"verified_closed", testActor, "tsk_revalidate", "validator no longer reproduces")
	if err != nil || !ok || !changed {
		t.Fatalf("revalidate close: changed=%v ok=%v err=%v", changed, ok, err)
	}
	tx.Commit(ctx)

	// Terminal states never leave.
	tx, _ = st.Pool.Begin(ctx)
	_, _, ok, _ = store.ApplyTransitionTx(ctx, tx, tenant, fid, "reopened", testActor, "", "")
	if ok {
		t.Fatal("verified_closed → reopened accepted; terminal states must not leave")
	}
	tx.Rollback(ctx)

	trs, _ = st.ListTransitions(ctx, tenant, fid)
	if len(trs) != 5 {
		t.Fatalf("transition history = %d rows, want 5", len(trs))
	}
}

func TestFingerprintDedupMerge(t *testing.T) {
	st := testenv.Store(t)
	tenant := testenv.Tenant(t, st, "dedup")
	ctx := context.Background()

	fid := seedFinding(t, st, tenant, "fp-1", "triaged")

	// Re-scan with the same fingerprint merges (occurrence++) instead of
	// inserting a new row (doc 04 §7.2 cross-run dedup).
	tx, _ := st.Pool.Begin(ctx)
	out, err := store.UpsertFindingTx(ctx, tx, tenant, store.FindingUpsert{
		AssetType: "subdomain", AssetValue: "host-fp-1.example.com",
		Module: store.ModuleDetect, CheckID: "CVE-2024-TEST", Title: "test",
		Severity: "high", State: "confirmed_open", Fingerprint: "fp-1", Occurrence: 2,
	}, testActor, advance)
	if err != nil {
		t.Fatal(err)
	}
	tx.Commit(ctx)
	if out.Created || out.FindingID != fid {
		t.Fatalf("dedup merge: created=%v id=%q, want merge into %q", out.Created, out.FindingID, fid)
	}
	f, _ := st.GetFinding(ctx, tenant, fid)
	if f.Occurrence != 3 { // 1 + 2
		t.Fatalf("occurrence = %d, want 3", f.Occurrence)
	}
	if f.State != "confirmed_open" {
		t.Fatalf("state = %q, want confirmed_open (advanced triaged→…→confirmed_open)", f.State)
	}
	var n int
	st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM dp.findings WHERE tenant_id=$1 AND fingerprint='fp-1'`, tenant).Scan(&n)
	if n != 1 {
		t.Fatalf("rows for fingerprint = %d, want 1", n)
	}
}

func TestTenantIsolation(t *testing.T) {
	st := testenv.Store(t)
	ctx := context.Background()
	tenantA := testenv.Tenant(t, st, "isolation-a")
	tenantB := testenv.Tenant(t, st, "isolation-b")

	// Seed tenant A: two linked assets + one finding; tenant B: same-shaped data.
	tx, _ := st.Pool.Begin(ctx)
	dom, _ := store.UpsertAssetTx(ctx, tx, tenantA, store.AssetUpsert{
		Type: "domain", Value: "a-corp.example", RoeID: "roe_a"})
	sub, _ := store.UpsertAssetTx(ctx, tx, tenantA, store.AssetUpsert{
		Type: "subdomain", Value: "api.a-corp.example", RoeID: "roe_a"})
	store.UpsertEdgeTx(ctx, tx, tenantA, store.EdgeUpsert{
		SrcAssetID: sub.AssetID, DstAssetID: dom.AssetID, Rel: "resolves_to"})
	fout, _ := store.UpsertFindingTx(ctx, tx, tenantA, store.FindingUpsert{
		AssetUID: sub.AssetID, Module: store.ModuleDetect, CheckID: "CVE-A",
		Title: "A finding", Severity: "critical", Fingerprint: "iso-a", TaskID: "tsk_a",
	}, testActor, advance)
	tx.Commit(ctx)

	tx, _ = st.Pool.Begin(ctx)
	store.UpsertAssetTx(ctx, tx, tenantB, store.AssetUpsert{
		Type: "domain", Value: "b-corp.example", RoeID: "roe_b"})
	tx.Commit(ctx)

	// Reads from A: exactly A's data.
	if a, _ := st.GetAsset(ctx, tenantA, dom.AssetID); a == nil || a.Value != "a-corp.example" {
		t.Fatal("tenant A cannot read its own asset")
	}
	assets, total, err := st.ListAssets(ctx, tenantA, store.AssetFilter{}, 100, "", "")
	if err != nil || total != 2 || len(assets) != 2 {
		t.Fatalf("tenant A list: total=%d len=%d err=%v", total, len(assets), err)
	}
	nb, err := st.Neighborhood(ctx, tenantA, dom.AssetID, 4)
	if err != nil || len(nb.Assets) != 2 || len(nb.Edges) != 1 {
		t.Fatalf("tenant A neighborhood: %+v err=%v", nb, err)
	}
	fs, ftotal, _ := st.ListFindings(ctx, tenantA, store.FindingFilter{}, 100, time.Time{}, "")
	if ftotal != 1 || len(fs) != 1 {
		t.Fatalf("tenant A findings: total=%d len=%d", ftotal, len(fs))
	}
	if ru, _ := st.Rollup(ctx, tenantA, "tsk_a"); ru == nil || ru.FindingsProduced != 1 {
		t.Fatalf("tenant A rollup: %+v", ru)
	}

	// Cross-tenant: B sees none of A's rows — invisible, not merely filtered
	// (doc 09 §9.6: structurally impossible).
	if a, _ := st.GetAsset(ctx, tenantB, dom.AssetID); a != nil {
		t.Fatal("tenant B read tenant A's asset by uid")
	}
	if _, total, _ := st.ListAssets(ctx, tenantB, store.AssetFilter{}, 100, "", ""); total != 1 {
		t.Fatalf("tenant B asset total = %d, want 1 (own only)", total)
	}
	if f, _ := st.GetFinding(ctx, tenantB, fout.FindingID); f != nil {
		t.Fatal("tenant B read tenant A's finding")
	}
	if _, total, _ := st.ListFindings(ctx, tenantB, store.FindingFilter{}, 100, time.Time{}, ""); total != 0 {
		t.Fatalf("tenant B findings total = %d, want 0", total)
	}
	if trs, _ := st.ListTransitions(ctx, tenantB, fout.FindingID); len(trs) != 0 {
		t.Fatal("tenant B read tenant A's transition history")
	}
	if ru, _ := st.Rollup(ctx, tenantB, "tsk_a"); ru != nil {
		t.Fatal("tenant B read tenant A's task rollup")
	}
	if nb, _ := st.Neighborhood(ctx, tenantB, dom.AssetID, 4); nb != nil {
		t.Fatal("tenant B walked tenant A's graph")
	}

	// Cross-tenant edge writes fail closed (asset refs resolve in-tenant only).
	tx, _ = st.Pool.Begin(ctx)
	bdom, _ := store.UpsertAssetTx(ctx, tx, tenantB, store.AssetUpsert{
		Type: "subdomain", Value: "x.b-corp.example", RoeID: "roe_b"})
	_, err = store.UpsertEdgeTx(ctx, tx, tenantB, store.EdgeUpsert{
		SrcAssetID: bdom.AssetID, DstAssetID: dom.AssetID /* tenant A asset */, Rel: "resolves_to"})
	if err == nil {
		t.Fatal("cross-tenant edge accepted")
	}
	tx.Rollback(ctx)
}
