package itest

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"
	sdkbus "github.com/aegisbastion/aegisbastion/sdks/go/bus"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/events"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/executor"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/probes"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/rawstore"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/store"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/streamer"
)

// dnsDoc builds a normalized DNS observation for the fixture probe / store.
func dnsDoc(t *testing.T, assetID, mission, snapID string, ts time.Time, aRecords ...string) *snapshot.Document {
	t.Helper()
	doc := &snapshot.Document{
		SnapshotID: snapID,
		AssetID:    assetID,
		MissionID:  mission,
		ProbeType:  snapshot.ProbeDNS,
		ProbeTS:    ts,
		Status:     snapshot.StatusOK,
		Observer:   snapshot.Observer{WorkerID: "mon-w-itest", ResolverSet: "fixture"},
	}
	doc.Data.DNS = &snapshot.DNSData{
		Records: map[string][]string{"A": aRecords},
		Quorum:  snapshot.Quorum{ResolverSet: "fixture", Resolvers: 3, Agreeing: 3},
	}
	if err := doc.ComputeContentHash(); err != nil {
		t.Fatal(err)
	}
	return doc
}

// seedSnapshot persists a SnapshotDocument as latest + history (the "before"
// state the executor diffs against).
func seedSnapshot(t *testing.T, ctx context.Context, st *store.Store, doc *snapshot.Document) {
	t.Helper()
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.WriteSnapshot(ctx, nil, doc.AssetID, doc.ProbeType, doc.SnapshotID,
		doc.ContentHash, doc.ProbeTS, doc.Status, raw, nil); err != nil {
		t.Fatalf("seed snapshot %s/%s: %v", doc.AssetID, doc.ProbeType, err)
	}
}

func scanCtx(assetID, identifier string) events.AssetCtx {
	return events.AssetCtx{
		AssetID: assetID, Kind: "subdomain", Identifier: identifier, Criticality: "medium",
	}
}

// TestExecutorEndToEndChange is doc 03 §15 acceptance 1 at module level: a
// flipped DNS A record produces exactly one dns.records_changed on
// monitor.changes (severity low), with the per-probe authorization invoked
// before any probing (doc 03 §9.2).
func TestExecutorEndToEndChange(t *testing.T) {
	ctx, st, bc, run := env(t)
	now := time.Now().UTC()
	mission := "msn_itest_" + run
	assetID := assetUUID("55555555-2222-3333-4444", run)
	identifier := "api.acme.com"

	if err := st.UpsertWatchAsset(ctx, assetID, mission, identifier, "standard", now); err != nil {
		t.Fatalf("watch asset: %v", err)
	}
	prev := dnsDoc(t, assetID, mission, "snp_prev_"+run, now.Add(-time.Hour), "203.0.113.10")
	seedSnapshot(t, ctx, st, prev)

	fx := probes.NewFixtureProbe(snapshot.ProbeDNS)
	fx.SetFrames(identifier, dnsDoc(t, assetID, mission, "", now, "203.0.113.11"))

	sm := streamer.New(st, streamer.Config{Now: func() time.Time { return now }}, nil)
	exec := executor.New(executor.Config{WorkerID: "mon-w-itest", Now: func() time.Time { return now }},
		st, []probes.Probe{fx}, rawstore.NopUploader{}, sm)

	authorizations := 0
	out, err := exec.ScanAsset(ctx, executor.ScanRequest{
		TaskID: "tsk_itest_" + run, WatchID: "wch_itest",
		MissionID: mission, ROEID: "roe_itest", ROEVersion: 1, OrgID: "org_itest",
		Asset:          scanCtx(assetID, identifier),
		ProbeTypes:     []string{snapshot.ProbeDNS},
		AlertThreshold: "low",
		TokenJTI:       "tok_itest",
		ReportEvents:   true,
		Authorize: func(context.Context, string, string) error {
			authorizations++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	if authorizations != 1 {
		t.Fatalf("per-probe authorizations = %d, want 1 (doc 03 §9.2)", authorizations)
	}
	if out.ProbesRun != 1 || out.EventsEmitted != 1 {
		t.Fatalf("outcome = %+v, want 1 probe / 1 event", out)
	}

	relayed, err := sm.Relay(ctx, rawPublisher{bc}, 10)
	if err != nil || relayed != 1 {
		t.Fatalf("relayed = %d, %v", relayed, err)
	}
	msgs := drainMatching(t, bc, "MONITOR_EVENTS", "monitor.changes",
		func(d []byte) bool { return bytes.Contains(d, []byte(mission)) })
	if len(msgs) != 1 {
		t.Fatalf("monitor.changes messages = %d, want exactly 1", len(msgs))
	}
	envMsg, err := sdkbus.UnmarshalEnvelope(msgs[0])
	if err != nil {
		t.Fatal(err)
	}
	m, err := sdkbus.UnpackPayload(envMsg)
	if err != nil {
		t.Fatal(err)
	}
	mc, ok := m.(*monitorv1.MonitorChange)
	if !ok {
		t.Fatalf("payload = %T", m)
	}
	if mc.GetChangeType() != monitorv1.ChangeType_CHANGE_TYPE_DNS_RECORDS_CHANGED {
		t.Fatalf("change_type = %s, want DNS_RECORDS_CHANGED", mc.GetChangeType())
	}
	if mc.GetSeverity() != monitorv1.Severity_SEVERITY_LOW {
		t.Fatalf("severity = %s, want low (single A-record flip)", mc.GetSeverity())
	}
	if mc.GetSnapshotRefs().GetBefore() != prev.SnapshotID {
		t.Fatalf("snapshot_refs.before = %q, want %q", mc.GetSnapshotRefs().GetBefore(), prev.SnapshotID)
	}
}

// TestExecutorPassiveModeZeroContact is doc 03 §15 acceptance 3 at module
// level (Ruling A.1): passive-only mode performs ZERO target contact while
// rules still evaluate over the cached snapshot set — a cached expired cert
// opens EXP-003 — and the sticky state machine fires exactly once across
// repeated sweeps.
func TestExecutorPassiveModeZeroContact(t *testing.T) {
	ctx, st, _, run := env(t)
	now := time.Now().UTC()
	mission := "msn_itest_" + run
	assetID := assetUUID("66666666-2222-3333-4444", run)
	identifier := "tls.acme.com"

	if err := st.UpsertWatchAsset(ctx, assetID, mission, identifier, "standard", now); err != nil {
		t.Fatalf("watch asset: %v", err)
	}
	// Cached TLS snapshot: certificate expired 3 days ago (EXP-003).
	tlsDoc := &snapshot.Document{
		SnapshotID: "snp_tls_" + run, AssetID: assetID, MissionID: mission,
		ProbeType: snapshot.ProbeTLS, ProbeTS: now.Add(-time.Hour), Status: snapshot.StatusOK,
		Observer: snapshot.Observer{WorkerID: "mon-w-itest"},
	}
	tlsDoc.Data.TLS = &snapshot.TLSData{
		Leaf: snapshot.TLSCert{
			FingerprintSHA256: "ab12", Issuer: "CN=Test CA",
			NotBefore: now.Add(-400 * 24 * time.Hour).Format(time.RFC3339),
			NotAfter:  now.Add(-3 * 24 * time.Hour).Format(time.RFC3339),
		},
		Negotiated:    snapshot.TLSNeg{Version: "1.2", Cipher: "TLS_AES_128_GCM_SHA256"},
		HostnameMatch: true,
		DaysToExpiry:  -3,
	}
	if err := tlsDoc.ComputeContentHash(); err != nil {
		t.Fatal(err)
	}
	seedSnapshot(t, ctx, st, tlsDoc)

	fx := probes.NewFixtureProbe(snapshot.ProbeDNS)
	fx.SetFrames(identifier, dnsDoc(t, assetID, mission, "", now, "203.0.113.12"))

	sm := streamer.New(st, streamer.Config{Now: func() time.Time { return now }}, nil)
	exec := executor.New(executor.Config{WorkerID: "mon-w-itest", Now: func() time.Time { return now }},
		st, []probes.Probe{fx}, rawstore.NopUploader{}, sm)

	passiveReq := func() executor.ScanRequest {
		return executor.ScanRequest{
			TaskID: "tsk_itest_" + run, WatchID: "wch_itest",
			MissionID: mission, ROEID: "roe_itest", ROEVersion: 1, OrgID: "org_itest",
			Asset:        scanCtx(assetID, identifier),
			ProbeTypes:   []string{snapshot.ProbeDNS},
			ReportEvents: true,
			Passive:      true, // Ruling A.1 — R0 mission
			// Authorize deliberately nil: passive mode must never even ask.
		}
	}

	out, err := exec.ScanAsset(ctx, passiveReq())
	if err != nil {
		t.Fatalf("passive scan: %v", err)
	}
	if fx.TotalCalls() != 0 || out.ProbesRun != 0 {
		t.Fatalf("passive mode touched the target: fixture calls=%d probes=%d (want 0/0)",
			fx.TotalCalls(), out.ProbesRun)
	}
	if out.ExposuresOpened == 0 {
		t.Fatal("cached expired cert must open an exposure in passive mode (cached diffing)")
	}
	if out.EventsEmitted == 0 {
		t.Fatal("passive cached diffing must emit change events")
	}

	// Sticky state: a second sweep emits nothing new (transitions only).
	out2, err := exec.ScanAsset(ctx, passiveReq())
	if err != nil {
		t.Fatal(err)
	}
	if out2.EventsEmitted != 0 || out2.ExposuresOpened != 0 {
		t.Fatalf("second passive sweep emitted %d events / %d exposures (sticky state must fire once)",
			out2.EventsEmitted, out2.ExposuresOpened)
	}
}
