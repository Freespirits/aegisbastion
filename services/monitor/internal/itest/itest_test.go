// Package itest runs the monitor module's integration tests against the
// compose infra tier (Postgres 16 + NATS 2.11 + MinIO —
// deploy/docker-compose.yml --profile infra). Env-gated:
//
//	AEGISBASTION_TEST_DATABASE_URL   postgres://aegisbastion:aegisbastion-dev@localhost:5432/aegisbastion?sslmode=disable
//	AEGISBASTION_TEST_NATS_URL       nats://localhost:4222
//
// When unset the tests skip, keeping `go test ./...` hermetic. Every test
// uses ULID-unique mission/asset ids — the infra is shared, nothing is
// truncated.
package itest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"
	sdkbus "github.com/aegisbastion/aegisbastion/sdks/go/bus"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/alertmap"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/events"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/store"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/streamer"
)

func env(t *testing.T) (context.Context, *store.Store, *sdkbus.Client, string) {
	t.Helper()
	dsn := os.Getenv("AEGISBASTION_TEST_DATABASE_URL")
	natsURL := os.Getenv("AEGISBASTION_TEST_NATS_URL")
	if dsn == "" || natsURL == "" {
		t.Skip("integration test needs AEGISBASTION_TEST_DATABASE_URL + AEGISBASTION_TEST_NATS_URL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	t.Cleanup(cancel)
	st, err := store.New(ctx, dsn, "monitor")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(st.Close)
	if err := st.Bootstrap(ctx); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	// Shared dev infra: clear pending outbox rows left by earlier (failed)
	// runs so relay-count assertions stay deterministic. The table is
	// module-owned and no monitor service runs against this database.
	if _, err := st.Pool.Exec(ctx, `DELETE FROM monitor.event_outbox WHERE published_at IS NULL`); err != nil {
		t.Fatalf("outbox cleanup: %v", err)
	}
	bc, err := sdkbus.Connect(natsURL)
	if err != nil {
		t.Fatalf("bus: %v", err)
	}
	t.Cleanup(bc.Close)
	return ctx, st, bc, ulid.Make().String()
}

// seedMissionContext inserts the platform.missions + gatekeeper.roe_records
// rows store.GetMissionContext joins (read-only cross-schema lookups).
func seedMissionContext(t *testing.T, ctx context.Context, st *store.Store, missionID, roeID string) {
	t.Helper()
	scope := []byte(`{"domains":["acme.com","*.acme.com"],"cidrs":["203.0.113.0/24"],"explicit_excludes":["status.acme.com"]}`)
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO gatekeeper.roe_records
		  (roe_id, version, org_id, name, status, created_by, authorized_by, scope, constraints, valid_from, valid_until)
		VALUES ($1, 1, 'org_itest', 'itest roe', 'active', 'itest', '{"identity":"itest"}'::jsonb,
		        $2, '{"max_risk_class":"R1","allowed_capabilities":["monitor.watch","monitor.rescan","monitor.feed.sync","monitor.baseline.set"]}'::jsonb,
		        now() - interval '1 hour', now() + interval '1 day')
		ON CONFLICT (roe_id, version) DO NOTHING`, roeID, scope); err != nil {
		t.Fatalf("seed roe: %v", err)
	}
	if _, err := st.Pool.Exec(ctx, `
		INSERT INTO platform.missions (mission_id, name, owning_commander, objective, roe_id, roe_version, created_by, state)
		VALUES ($1, 'itest mission', 'hexstrike', 'itest', $2, 1, 'itest', 'ACTIVE')
		ON CONFLICT (mission_id) DO NOTHING`, missionID, roeID); err != nil {
		t.Fatalf("seed mission: %v", err)
	}
}

// assetUUID renders a deterministic uuid-shaped asset id from the test run id
// (ULIDs are not hex — hash and take 12 hex chars for the last segment).
func assetUUID(first string, run string) string {
	sum := sha256.Sum256([]byte(run))
	return first + "-" + hex.EncodeToString(sum[:6])
}

// drainMatching fetches messages from a stream subject for up to 5 s and
// returns the payloads where match(data) is true. Fetched messages are acked
// (keeps the shared dev queues moving). On WorkQueue streams NATS forbids a
// second filtered consumer when one already exists (e.g. herald's durable
// herald-ingest on ALERT_INGRESS): fall back to binding to the existing
// consumer and filter by subject client-side — messages for OTHER subjects
// are nak'd back for their real consumer.
func drainMatching(t *testing.T, bc *sdkbus.Client, stream, subject string, match func([]byte) bool) [][]byte {
	t.Helper()
	js := bc.JetStream()
	sub, err := js.PullSubscribe(subject, "itest-"+ulid.Make().String(),
		nats.BindStream(stream))
	bound := false
	if err != nil {
		for name := range js.ConsumerNames(stream) {
			if sub, err = js.PullSubscribe("", "", nats.Bind(stream, name)); err == nil {
				bound = true
				break
			}
		}
		if err != nil {
			t.Fatalf("pull subscribe %s on %s: %v", subject, stream, err)
		}
	}
	defer func() { _ = sub.Unsubscribe() }()
	var out [][]byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		msgs, err := sub.Fetch(10, nats.MaxWait(2*time.Second))
		if err != nil {
			break
		}
		for _, m := range msgs {
			if bound && m.Subject != subject {
				_ = m.Nak() // another module's subject — not ours to consume
				continue
			}
			_ = m.Ack()
			if match == nil || match(m.Data) {
				out = append(out, m.Data)
			}
		}
	}
	return out
}

// changeFixture builds a streamer-ready MonitorChange with a unique
// fingerprint per (mission, diffKey).
func changeFixture(missionID, assetID, diffKey string, ct monitorv1.ChangeType, sev monitorv1.Severity) *monitorv1.MonitorChange {
	return &monitorv1.MonitorChange{
		SchemaVersion: "1.0",
		EventId:       events.NewID("chg"),
		MissionId:     missionID,
		RoeId:         "roe_itest",
		OrgId:         "org_itest",
		Asset: &monitorv1.MonitoredAsset{
			AssetId: assetID, Kind: monitorv1.AssetKind_ASSET_KIND_SUBDOMAIN,
			Identifier: "api.acme.com", Criticality: "high",
		},
		ChangeType:  ct,
		Severity:    sev,
		Confidence:  monitorv1.Confidence_CONFIDENCE_CONFIRMED,
		Summary:     "itest change " + diffKey,
		Fingerprint: events.Fingerprint(missionID, assetID, "tls.cert_expired", diffKey),
		// Realistic detection time (production NewChange always stamps one);
		// the emission cap counts change_events by occurred_at.
		FirstSeenAt: timestamppb.New(time.Now().UTC()),
		OccurredAt:  timestamppb.New(time.Now().UTC()),
		Labels:      map[string]string{"source": "active_probe"},
	}
}

func TestStoreRoundTrip(t *testing.T) {
	ctx, st, _, run := env(t)
	now := time.Now().UTC()
	mission := "msn_itest_" + run
	assetID := assetUUID("11111111-2222-3333-4444", run)

	// Watch assets.
	if err := st.UpsertWatchAsset(ctx, assetID, mission, "api.acme.com", "standard", now); err != nil {
		t.Fatalf("upsert watch asset: %v", err)
	}
	due, err := st.ListDueAssets(ctx, mission, now.Add(time.Minute), 10)
	if err != nil || len(due) != 1 {
		t.Fatalf("due assets = %v, %v", due, err)
	}
	rowUUID := due[0].RowUUID
	if err := st.Reschedule(ctx, rowUUID, now.Add(time.Hour), now); err != nil {
		t.Fatalf("reschedule: %v", err)
	}
	if n, _ := st.CountDueAssets(ctx, mission, now.Add(30*time.Minute)); n != 0 {
		t.Fatalf("due after reschedule = %d", n)
	}

	// Snapshots: latest + history.
	doc := []byte(`{"snapshot_id":"snp_x","probe_type":"dns","status":"ok"}`)
	if err := st.WriteSnapshot(ctx, nil, assetID, "dns", "snp_itest_"+run, "sha256:aa", now, "ok", doc, nil); err != nil {
		t.Fatalf("write snapshot: %v", err)
	}
	latest, err := st.GetLatest(ctx, assetID, "dns")
	if err != nil || latest == nil || latest.ContentHash != "sha256:aa" {
		t.Fatalf("latest = %+v, %v", latest, err)
	}
	raw, err := st.SnapshotData(ctx, "snp_itest_"+run)
	if err != nil || len(raw) == 0 {
		t.Fatalf("snapshot data: %v", err)
	}
	if err := st.TouchLatest(ctx, assetID, "dns", now.Add(time.Minute), "ok"); err != nil {
		t.Fatalf("touch latest: %v", err)
	}

	// Pending changes (2-consecutive confirmation).
	if err := st.PendingUpsert(ctx, assetID, "http", "status", "fp_x", "sha256:bb", []byte(`{"Type":"http.status_changed"}`), now); err != nil {
		t.Fatalf("pending upsert: %v", err)
	}
	pend, err := st.PendingForAsset(ctx, assetID, "http")
	if err != nil || len(pend) != 1 || pend[0].AfterHash != "sha256:bb" {
		t.Fatalf("pending = %+v, %v", pend, err)
	}
	if err := st.PendingDelete(ctx, assetID, "http", "status"); err != nil {
		t.Fatalf("pending delete: %v", err)
	}

	// Dedup window.
	fp := "fp_itest_" + run
	hit, dup, err := st.DedupCheckInsert(ctx, fp, "chg_first", now)
	if err != nil || dup || hit.FirstEventID != "chg_first" {
		t.Fatalf("first dedup insert: %+v dup=%v err=%v", hit, dup, err)
	}
	hit, dup, err = st.DedupCheckInsert(ctx, fp, "chg_second", now.Add(time.Minute))
	if err != nil || !dup || hit.Count != 2 {
		t.Fatalf("dedup repeat: %+v dup=%v err=%v", hit, dup, err)
	}

	// Candidates (metadata-only, idempotent).
	inserted, err := st.InsertCandidate(ctx, mission, "grafana.acme.com", "subdomain", "in_scope", []byte(`{"type":"ct_log"}`))
	if err != nil || !inserted {
		t.Fatalf("candidate insert: %v %v", inserted, err)
	}
	inserted, err = st.InsertCandidate(ctx, mission, "grafana.acme.com", "subdomain", "in_scope", []byte(`{"type":"ct_log"}`))
	if err != nil || inserted {
		t.Fatal("candidate replay must dedup")
	}

	// Baselines (created before drift state — baseline_state references them).
	blRuleID := "bl_itest_" + run + ":" + assetID
	if err := st.UpsertBaselineRule(ctx, store.BaselineRule{
		RuleID: blRuleID, MissionID: mission,
		Name: "bl_itest_" + run, RegoRef: "builtin:captured/v1",
		Config: []byte(`{"id":"x","type":"captured","severity":"medium","expect":{}}`),
	}); err != nil {
		t.Fatalf("baseline upsert: %v", err)
	}
	bl, err := st.BaselineRules(ctx, "bl_itest_"+run)
	if err != nil || len(bl) != 1 {
		t.Fatalf("baseline rules = %d, %v", len(bl), err)
	}

	// Drift / exposure state machines.
	if err := st.SetDriftState(ctx, assetID, blRuleID, "drifted"); err != nil {
		t.Fatalf("set drift: %v", err)
	}
	state, err := st.DriftState(ctx, assetID, blRuleID)
	if err != nil || state != "drifted" {
		t.Fatalf("drift state = %q", state)
	}
	if err := st.SetExposureState(ctx, assetID, "EXP-001", "open"); err != nil {
		t.Fatalf("open exposure: %v", err)
	}
	states, err := st.ExposureStates(ctx, assetID)
	if err != nil || len(states) != 1 || states[0].State != "open" {
		t.Fatalf("exposure states = %+v", states)
	}
	if err := st.SetExposureState(ctx, assetID, "EXP-001", "closed"); err != nil {
		t.Fatalf("close exposure: %v", err)
	}

	// Suppressions + dead jobs.
	supID, err := st.InsertSuppression(ctx, map[string]string{"change_type": "tls.cert_changed"},
		"itest", "op_itest", now.Add(time.Hour))
	if err != nil {
		t.Fatalf("insert suppression: %v", err)
	}
	sup, reason, err := st.IsSuppressed(ctx, mission, assetID, "", "tls.cert_changed", now)
	if err != nil || !sup || reason != "itest" {
		t.Fatalf("suppressed = %v %q", sup, reason)
	}
	sup, _, err = st.IsSuppressed(ctx, mission, assetID, "", "dns.ns_changed", now)
	if err != nil || sup {
		t.Fatal("unrelated change type must not be suppressed")
	}
	if err := st.DeleteSuppression(ctx, supID); err != nil {
		t.Fatalf("delete suppression: %v", err)
	}
	if err := st.InsertDeadJob(ctx, []byte(`{"job_id":"j1"}`), "itest failure", 3); err != nil {
		t.Fatalf("dead job: %v", err)
	}
}

func TestStreamerOutboxRelayRoundTrip(t *testing.T) {
	ctx, st, bc, run := env(t)
	now := time.Now().UTC()
	mission := "msn_itest_" + run
	assetID := assetUUID("22222222-2222-3333-4444", run)

	sm := streamer.New(st, streamer.Config{Now: func() time.Time { return now }}, nil)

	// tls.cert_expired is alertable at high severity → changes + alert rows.
	mc := changeFixture(mission, assetID, "rt1",
		monitorv1.ChangeType_CHANGE_TYPE_TLS_CERT_EXPIRED, monitorv1.Severity_SEVERITY_HIGH)
	out, err := sm.Submit(ctx, streamer.SubmitInput{
		Change: mc,
		Alert:  alertmap.Params{AlertThreshold: "medium", TokenJTI: "tok_itest", ROEID: "roe_itest"},
	})
	if err != nil || out != streamer.OutcomeEmitted {
		t.Fatalf("submit = %v, %v", out, err)
	}

	// Relay publishes both rows.
	relayed, err := sm.Relay(ctx, rawPublisher{bc}, 10)
	if err != nil || relayed != 2 {
		t.Fatalf("relayed = %d, %v", relayed, err)
	}

	// monitor.changes: protobuf envelope carrying MonitorChange.
	changes := drainMatching(t, bc, "MONITOR_EVENTS", "monitor.changes",
		func(d []byte) bool { return bytes.Contains(d, []byte(mc.GetEventId())) })
	if len(changes) != 1 {
		t.Fatalf("changes messages = %d", len(changes))
	}
	env1, err := sdkbus.UnmarshalEnvelope(changes[0])
	if err != nil {
		t.Fatalf("changes envelope: %v", err)
	}
	if env1.GetType() != "aegisbastion.monitor.v1.MonitorChange" {
		t.Fatalf("envelope type = %q", env1.GetType())
	}
	msg, err := sdkbus.UnpackPayload(env1)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := msg.(*monitorv1.MonitorChange)
	if !ok || got.GetEventId() != mc.GetEventId() {
		t.Fatalf("payload = %T %v", msg, msg)
	}

	// monitor.alert: CloudEvents JSON (work queue to the Alert module). When
	// the herald service is live it rightfully consumes monitor.alert
	// mid-test; fall back to the exact outbox bytes (the relay's PubAck
	// already proved ALERT_INGRESS accepted them).
	alerts := drainMatching(t, bc, "ALERT_INGRESS", "monitor.alert",
		func(d []byte) bool { return bytes.Contains(d, []byte(mc.GetEventId())) })
	if len(alerts) == 0 {
		var raw []byte
		if err := st.Pool.QueryRow(ctx, `
			SELECT decode(payload->>'data','base64') FROM monitor.event_outbox
			WHERE subject = 'monitor.alert' AND payload->>'mission_id' = $1`,
			mission).Scan(&raw); err != nil {
			t.Fatalf("alert neither drained (herald consumed it) nor in outbox: %v", err)
		}
		alerts = [][]byte{raw}
	}
	var ce struct {
		SpecVersion string `json:"specversion"`
		Source      string `json:"source"`
		Type        string `json:"type"`
		Data        struct {
			AuthorizationTokenID string `json:"authorization_token_id"`
			Category             string `json:"category"`
			FingerprintHint      string `json:"fingerprint_hint"`
		} `json:"data"`
	}
	if err := json.Unmarshal(alerts[0], &ce); err != nil {
		t.Fatalf("alert cloudevent: %v", err)
	}
	if ce.SpecVersion != "1.0" || ce.Source != "//aegisbastion/monitor" || ce.Type != "com.aegisbastion.alert.v1" {
		t.Fatalf("cloudevent = %+v", ce)
	}
	if ce.Data.AuthorizationTokenID != "tok_itest" || ce.Data.Category != "exposure" {
		t.Fatalf("alert data = %+v", ce.Data)
	}
	if ce.Data.FingerprintHint != mc.GetFingerprint() {
		t.Fatalf("fingerprint_hint = %q", ce.Data.FingerprintHint)
	}

	// Dedup replay: same fingerprint → suppressed, nothing new on the bus.
	mc2 := changeFixture(mission, assetID, "rt1",
		monitorv1.ChangeType_CHANGE_TYPE_TLS_CERT_EXPIRED, monitorv1.Severity_SEVERITY_HIGH)
	out, err = sm.Submit(ctx, streamer.SubmitInput{
		Change: mc2,
		Alert:  alertmap.Params{AlertThreshold: "medium", TokenJTI: "tok_itest"},
	})
	if err != nil || out != streamer.OutcomeSuppressedDedup {
		t.Fatalf("dedup replay = %v, %v", out, err)
	}
	relayed, err = sm.Relay(ctx, rawPublisher{bc}, 10)
	if err != nil || relayed != 0 {
		t.Fatalf("post-dedup relayed = %d", relayed)
	}
	if again := drainMatching(t, bc, "MONITOR_EVENTS", "monitor.changes",
		func(d []byte) bool { return bytes.Contains(d, []byte(mc2.GetEventId())) }); len(again) != 0 {
		t.Fatal("dedup replay must not re-emit (exactly-once per fingerprint)")
	}
}

func TestStreamerSuppressionKeepsHistory(t *testing.T) {
	ctx, st, bc, run := env(t)
	now := time.Now().UTC()
	mission := "msn_itest_" + run
	assetID := assetUUID("33333333-2222-3333-4444", run)

	if _, err := st.InsertSuppression(ctx, map[string]string{"mission_id": mission},
		"operator silence", "op_itest", now.Add(time.Hour)); err != nil {
		t.Fatalf("suppression: %v", err)
	}
	sm := streamer.New(st, streamer.Config{Now: func() time.Time { return now }}, nil)
	mc := changeFixture(mission, assetID, "sup1",
		monitorv1.ChangeType_CHANGE_TYPE_EXPOSURE_OPENED, monitorv1.Severity_SEVERITY_HIGH)
	out, err := sm.Submit(ctx, streamer.SubmitInput{
		Change: mc, Alert: alertmap.Params{AlertThreshold: "info", TokenJTI: "tok_itest"},
	})
	if err != nil || out != streamer.OutcomeSuppressedRule {
		t.Fatalf("submit = %v, %v", out, err)
	}
	// History kept (suppressions gate outbound emission only, doc 03 §8).
	n, err := st.CountRecentEvents(ctx, mission, now.Add(-time.Hour))
	if err != nil || n != 1 {
		t.Fatalf("change_events rows = %d (history must survive suppression)", n)
	}
	// Nothing outboxed.
	relayed, err := sm.Relay(ctx, rawPublisher{bc}, 10)
	if err != nil || relayed != 0 {
		t.Fatalf("relayed under suppression = %d", relayed)
	}
}

func TestStreamerCapAndBurst(t *testing.T) {
	ctx, st, bc, run := env(t)
	now := time.Now().UTC()
	mission := "msn_itest_" + run
	assetID := assetUUID("44444444-2222-3333-4444", run)

	sm := streamer.New(st, streamer.Config{Now: func() time.Time { return now }}, nil)
	var emitted, capped int
	for i := 0; i < 5; i++ {
		mc := changeFixture(mission, assetID, "cap"+string(rune('a'+i)),
			monitorv1.ChangeType_CHANGE_TYPE_HTTP_STATUS_CHANGED, monitorv1.Severity_SEVERITY_LOW)
		out, err := sm.Submit(ctx, streamer.SubmitInput{
			Change: mc, Alert: alertmap.Params{AlertThreshold: "critical"},
			EmissionCapPerHour: 2,
		})
		if err != nil {
			t.Fatal(err)
		}
		switch out {
		case streamer.OutcomeEmitted:
			emitted++
		case streamer.OutcomeSuppressedCap:
			capped++
		}
	}
	if emitted != 2 || capped != 3 {
		t.Fatalf("emitted=%d capped=%d, want 2/3 (cap 2/h)", emitted, capped)
	}
	// Zero event loss in change_events (doc 03 §15.5).
	n, err := st.CountRecentEvents(ctx, mission, now.Add(-time.Hour))
	if err != nil || n != 5 {
		t.Fatalf("change_events rows = %d, want 5 (zero event loss)", n)
	}
	// Burst flush aggregates the overflow into monitor.change_burst.
	if err := sm.FlushBursts(ctx, now.Add(time.Hour), events.ChangeCtx{
		ROEID: "roe_itest", OrgID: "org_itest", WorkerID: "mon-w-itest", WatchID: "wch_itest",
	}); err != nil {
		t.Fatalf("flush bursts: %v", err)
	}
	relayed, err := sm.Relay(ctx, rawPublisher{bc}, 10)
	if err != nil || relayed != 3 { // 2 capped-free changes + 1 burst
		t.Fatalf("relayed = %d, want 3", relayed)
	}
	msgs := drainMatching(t, bc, "MONITOR_EVENTS", "monitor.changes",
		func(d []byte) bool { return bytes.Contains(d, []byte(mission)) })
	if len(msgs) != 3 {
		t.Fatalf("bus messages = %d, want 3", len(msgs))
	}
	var burstFound bool
	for _, raw := range msgs {
		e, err := sdkbus.UnmarshalEnvelope(raw)
		if err != nil {
			continue
		}
		m, err := sdkbus.UnpackPayload(e)
		if err != nil {
			continue
		}
		if mc, ok := m.(*monitorv1.MonitorChange); ok &&
			mc.GetChangeType() == monitorv1.ChangeType_CHANGE_TYPE_MONITOR_CHANGE_BURST {
			burstFound = true
		}
	}
	if !burstFound {
		t.Fatal("monitor.change_burst not emitted after cap overflow")
	}
}

// rawPublisher adapts the bus client to streamer.Publisher.
type rawPublisher struct{ c *sdkbus.Client }

func (r rawPublisher) PublishRaw(ctx context.Context, subject, msgID string, data []byte) error {
	msg := nats.NewMsg(subject)
	msg.Header.Set(nats.MsgIdHdr, msgID)
	msg.Data = data
	return r.c.PublishMsg(ctx, msg)
}
