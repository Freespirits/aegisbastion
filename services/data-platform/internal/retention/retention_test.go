package retention

import (
	"context"
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/lifecycle"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/testenv"
)

func TestParseDuration(t *testing.T) {
	const day = 24 * time.Hour
	cases := map[string]time.Duration{
		"P90D":   90 * day,
		"P2Y":    730 * day,
		"P7Y":    7 * 365 * day,
		"P1Y90D": 455 * day,
		"P1M":    30 * day,
	}
	for in, want := range cases {
		got, ok := parseDuration(in)
		if !ok || got != want {
			t.Errorf("parseDuration(%q) = %v,%v want %v,true", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "indefinite", "P", "90D", "P1W", "P-1D", "P1.5Y", "P0D"} {
		if _, ok := parseDuration(bad); ok {
			t.Errorf("parseDuration(%q) accepted — fail-safe is never-delete", bad)
		}
	}
}

func TestCutoffFor(t *testing.T) {
	now := time.Date(2026, 7, 31, 0, 0, 0, 0, time.UTC)
	if _, ok := cutoffFor("indefinite", now); ok {
		t.Error("indefinite produced a cutoff (open findings must be kept forever)")
	}
	c, ok := cutoffFor("P90D", now)
	if !ok || !c.Equal(now.Add(-90*24*time.Hour)) {
		t.Errorf("cutoffFor(P90D) = %v,%v", c, ok)
	}
	if _, ok := evidenceCutoff("finding+P90D", now); !ok {
		t.Error("evidenceCutoff(finding+P90D) rejected")
	}
}

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

// TestSweepPurgesResolvedFindings seeds one old terminal finding, one
// legal-hold terminal finding and one open finding; the sweep must purge only
// the first, audit the purge, and freeze the hold subtree (doc 09 §10).
func TestSweepPurgesResolvedFindings(t *testing.T) {
	st := testenv.Store(t)
	tenant := testenv.Tenant(t, st, "retention")
	ctx := context.Background()
	actor := store.Actor{Type: "service", ID: "svc-detect"}

	seed := func(fp string, legalHold bool) string {
		tx, _ := st.Pool.Begin(ctx)
		a, err := store.UpsertAssetTx(ctx, tx, tenant, store.AssetUpsert{
			Type: "domain", Value: fp + ".example", RoeID: "roe_1"})
		if err != nil {
			t.Fatal(err)
		}
		f, err := store.UpsertFindingTx(ctx, tx, tenant, store.FindingUpsert{
			AssetUID: a.AssetID, Module: store.ModuleDetect, CheckID: "CVE-R",
			Title: "t", Severity: "low", State: "verified_closed", Fingerprint: fp,
			LegalHold: legalHold,
		}, actor, advance)
		if err != nil {
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
		return f.FindingID
	}

	oldID := seed("ret-old", false)
	holdID := seed("ret-hold", true)
	openID := func() string {
		tx, _ := st.Pool.Begin(ctx)
		a, _ := store.UpsertAssetTx(ctx, tx, tenant, store.AssetUpsert{
			Type: "domain", Value: "ret-open.example", RoeID: "roe_1"})
		f, err := store.UpsertFindingTx(ctx, tx, tenant, store.FindingUpsert{
			AssetUID: a.AssetID, Module: store.ModuleDetect, CheckID: "CVE-R2",
			Title: "t", Severity: "low", State: "confirmed_open", Fingerprint: "ret-open",
		}, actor, advance)
		if err != nil {
			t.Fatal(err)
		}
		tx.Commit(ctx)
		return f.FindingID
	}()

	// Age the terminal transitions past findings_resolved (P2Y default).
	old := time.Now().Add(-3 * 365 * 24 * time.Hour)
	for _, id := range []string{oldID, holdID} {
		testenv.Exec(t, st,
			`UPDATE dp.finding_state_transitions SET ts = $3
			 WHERE tenant_id = $1 AND finding_id = $2 AND to_state = 'verified_closed'`,
			tenant, id, old)
	}

	// Zero S3 config disables blob deletion; expired evidence refs are still
	// cleared (deleteBlob's MinIO wiring is exercised by the service itself).
	eng := New(st, nil, manifest.S3Config{}, "dp-test", nil)
	if err := eng.Sweep(ctx); err != nil {
		t.Fatalf("sweep: %v", err)
	}

	if f, _ := st.GetFinding(ctx, tenant, oldID); f != nil {
		t.Fatal("old terminal finding survived the sweep")
	}
	if f, _ := st.GetFinding(ctx, tenant, holdID); f == nil {
		t.Fatal("legal-hold finding was purged — hold must freeze the subtree")
	}
	if f, _ := st.GetFinding(ctx, tenant, openID); f == nil {
		t.Fatal("open finding was purged — findings_open is indefinite")
	}

	// The purge was audited (counts + hashes, forwarded to gatekeeper).
	var n int
	if err := st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM dp.audit_outbox
		 WHERE tenant_id = $1 AND action = 'retention.purge'`, tenant).Scan(&n); err != nil || n < 1 {
		t.Fatalf("retention.purge audit rows = %d err=%v", n, err)
	}
}
