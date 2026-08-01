// Package itest holds the Detect module's compose-infra integration tests
// (doc 04 §14: the module's bus paths verified against the real JetStream +
// Postgres from `docker compose --profile infra up -d` in deploy/).
//
// Every test skips itself when the infra is unreachable so unit runs stay
// hermetic. Overrides: NATS_URL, DETECT_TEST_DATABASE_URL.
package itest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"
	"google.golang.org/protobuf/types/known/timestamppb"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"

	"github.com/aegisbastion/aegisbastion/sdks/go/bus"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/publish"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/store"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/worker"
)

// defaultNATS matches deploy/docker-compose.yml's published NATS.
const defaultNATS = "nats://localhost:4222"

// defaultDSN matches deploy/docker-compose.yml's published Postgres.
const defaultDSN = "postgres://aegisbastion:aegisbastion-dev@localhost:5432/aegisbastion?sslmode=disable"

// natsBus connects to the compose bus or skips.
func natsBus(t *testing.T) *bus.Client {
	t.Helper()
	url := os.Getenv("NATS_URL")
	if url == "" {
		url = defaultNATS
	}
	bc, err := bus.Connect(url, nats.Timeout(5*time.Second))
	if err != nil {
		t.Skipf("compose NATS unavailable (%v) — docker compose --profile infra up -d", err)
	}
	t.Cleanup(bc.Close)
	return bc
}

// pgStore connects to the compose Postgres (schema detect) or skips.
func pgStore(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("DETECT_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = defaultDSN
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := store.New(ctx, dsn, "detect")
	if err != nil {
		t.Skipf("compose Postgres unavailable (%v) — docker compose --profile infra up -d", err)
	}
	t.Cleanup(st.Close)
	return st
}

// resultCollector subscribes to detect.results and buffers messages for one
// task id (mirrors the Coordinator's aggregation subscription, scan.go).
type resultCollector struct {
	ch chan worker.ResultMessage
}

func subscribeResults(t *testing.T, bc *bus.Client, taskID string) *resultCollector {
	t.Helper()
	c := &resultCollector{ch: make(chan worker.ResultMessage, 64)}
	sub, err := bc.Conn().Subscribe(worker.SubjectResults, func(msg *nats.Msg) {
		var m worker.ResultMessage
		if err := json.Unmarshal(msg.Data, &m); err != nil {
			return
		}
		if m.TaskID != taskID {
			return
		}
		c.ch <- m
	})
	if err != nil {
		t.Fatalf("subscribe %s: %v", worker.SubjectResults, err)
	}
	t.Cleanup(func() { _ = sub.Unsubscribe() })
	return c
}

// waitDone collects results until the job's terminal "done" marker arrives.
func (c *resultCollector) waitDone(t *testing.T, jobID string, timeout time.Duration) (raws []worker.ResultMessage, done worker.ResultMessage) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case m := <-c.ch:
			if m.Kind == "raw" {
				raws = append(raws, m)
				continue
			}
			if m.Kind == "done" && m.JobID == jobID {
				return raws, m
			}
		case <-deadline:
			t.Fatalf("timed out waiting for done marker for job %s (raws so far: %d)", jobID, len(raws))
		}
	}
}

// publishJob puts one ScanJob on detect.jobs.{adapter} exactly the way the
// Coordinator dispatches (JetStream, Nats-Msg-Id = job id).
func publishJob(t *testing.T, bc *bus.Client, job scanner.Job) {
	t.Helper()
	data, err := json.Marshal(job)
	if err != nil {
		t.Fatal(err)
	}
	msg := nats.NewMsg(worker.SubjectJobs(job.Adapter))
	msg.Header.Set(nats.MsgIdHdr, job.JobID)
	msg.Data = data
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := bc.JetStream().PublishMsg(msg, nats.Context(ctx)); err != nil {
		t.Fatalf("dispatch job: %v", err)
	}
}

// TestWorkerBusRoundTrip proves the doc 04 §5.2 internal-queue contract
// against the real JetStream: a ScanJob published on detect.jobs.nuclei is
// consumed by the worker fleet, its RawResults stream back on detect.results,
// and the terminal done marker reports SUCCEEDED. The fixture-mode adapter
// makes zero target contact.
func TestWorkerBusRoundTrip(t *testing.T) {
	bc := natsBus(t)

	reg := scanner.NewRegistry()
	reg.Register(scanner.NewNuclei("", "../scanner/testdata"))
	w, err := worker.New(worker.Config{
		Adapter: "nuclei", Registry: reg, Conn: bc.Conn(),
		Concurrency: 1, AckWait: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("worker.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = w.Run(ctx) }()

	taskID := "tsk_itest_" + ulid.Make().String()
	jobID := "job_itest_" + ulid.Make().String()
	col := subscribeResults(t, bc, taskID)

	publishJob(t, bc, scanner.Job{
		JobID: jobID, TaskID: taskID, Adapter: "nuclei",
		Target: "https://api.acme.test", Capability: "detect.scan.web",
		SafeMode: true, Deadline: time.Now().Add(2 * time.Minute),
	})

	raws, done := col.waitDone(t, jobID, 60*time.Second)
	if done.Status != "SUCCEEDED" {
		t.Fatalf("job status = %s (err %q), want SUCCEEDED", done.Status, done.Error)
	}
	// nuclei-basic.jsonl: 5 valid records, one DoS-class (filtered at the
	// wrapper, doc 04 §10.3) → exactly 4 streamed candidates.
	if len(raws) != 4 {
		t.Fatalf("got %d raw results, want 4 (DoS-class fixture record must be filtered)", len(raws))
	}
	for _, m := range raws {
		if m.Result.CheckID == "dos-slowloris-check" {
			t.Fatal("DoS-class template result escaped the wrapper (doc 04 §10.3 violation)")
		}
		if m.Result.TaskID != taskID || m.Result.JobID != jobID {
			t.Fatalf("raw result binding wrong: %+v", m.Result)
		}
	}
}

// TestWorkerBusRoundTripDoSRefusal proves a job carrying a DoS-class check is
// refused at the adapter wrapper and reported FAILED over the bus — never
// retried into a run (doc 04 §10.3, wrapper refusal independent of params).
func TestWorkerBusRoundTripDoSRefusal(t *testing.T) {
	bc := natsBus(t)

	reg := scanner.NewRegistry()
	reg.Register(scanner.NewNuclei("", "../scanner/testdata"))
	w, err := worker.New(worker.Config{
		Adapter: "nuclei", Registry: reg, Conn: bc.Conn(),
		Concurrency: 1, AckWait: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("worker.New: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = w.Run(ctx) }()

	taskID := "tsk_itest_" + ulid.Make().String()
	jobID := "job_itest_" + ulid.Make().String()
	col := subscribeResults(t, bc, taskID)

	publishJob(t, bc, scanner.Job{
		JobID: jobID, TaskID: taskID, Adapter: "nuclei",
		Target: "https://api.acme.test", Capability: "detect.scan.web",
		Checks: []string{"dos-slowloris-check"}, SafeMode: true,
		Deadline: time.Now().Add(2 * time.Minute),
	})

	raws, done := col.waitDone(t, jobID, 60*time.Second)
	if done.Status != "FAILED" {
		t.Fatalf("DoS job status = %s, want FAILED (wrapper refusal)", done.Status)
	}
	if !strings.Contains(done.Error, "DoS") {
		t.Fatalf("refusal error must name the DoS exclusion, got %q", done.Error)
	}
	if len(raws) != 0 {
		t.Fatalf("DoS job must emit zero results, got %d", len(raws))
	}
}

// sampleFinding is one CONFIRMED P1 report (doc 04 §4.3 shape).
func sampleFinding(taskID, findingID string) *detectv1.FindingReport {
	now := timestamppb.Now()
	return &detectv1.FindingReport{
		FindingId:   findingID,
		Fingerprint: "sha256:itest-" + findingID,
		MissionId:   "msn_itest",
		TaskId:      taskID,
		RoeId:       "roe_itest",
		Target:      "https://api.acme.test/login",
		AssetRef:    "asset:host:api.acme.test",
		Vulnerability: &detectv1.Vulnerability{
			Id:         "CVE-2024-3400",
			Source:     "nuclei",
			TemplateId: "cve-2024-3400",
			Title:      "Palo Alto PAN-OS command injection",
			Cwe:        "CWE-77",
			References: []string{"https://nvd.nist.gov/vuln/detail/CVE-2024-3400"},
		},
		Severity: detectv1.Severity_SEVERITY_CRITICAL,
		Validation: &detectv1.Validation{
			Verdict:          detectv1.ValidationVerdict_VALIDATION_VERDICT_CONFIRMED,
			Method:           "ave.http_replay",
			EvidenceRefs:     []string{"s3://artifacts/msn_itest/" + taskID + "/" + findingID + "/transcript.json"},
			ValidatedAt:      now,
			ValidatorVersion: "ave-0.1.0",
			Confidence:       0.98,
		},
		Risk: &detectv1.RiskScore{
			Score: 96, Tier: "P1", ScorerVersion: "risk-v1",
		},
		Status:      detectv1.FindingStatus_FINDING_STATUS_OPEN,
		FirstSeen:   now,
		LastSeen:    now,
		Occurrences: 1,
	}
}

// TestFindingsAndAlertBusRoundTrip proves the two egress contracts over the
// real bus: detect.findings carries the FindingReport in the doc 01 §8.2
// envelope (dedup-idempotent on finding_id), and the Ruling C8 mapper emits a
// schema-valid AlertEvent v1 CloudEvent on detect.alert with the mandatory
// authorization_token_id (doc 04 §14 acceptance test 4, infra side).
func TestFindingsAndAlertBusRoundTrip(t *testing.T) {
	bc := natsBus(t)

	findingsCh := make(chan *nats.Msg, 4)
	subF, err := bc.Conn().Subscribe(publish.SubjectFindings, func(m *nats.Msg) { findingsCh <- m })
	if err != nil {
		t.Fatal(err)
	}
	defer subF.Unsubscribe()
	alertCh := make(chan *nats.Msg, 4)
	subA, err := bc.Conn().Subscribe(publish.SubjectAlert, func(m *nats.Msg) { alertCh <- m })
	if err != nil {
		t.Fatal(err)
	}
	defer subA.Unsubscribe()

	taskID := "tsk_itest_" + ulid.Make().String()
	findingID := "fnd_itest_" + ulid.Make().String()
	fr := sampleFinding(taskID, findingID)

	// --- detect.findings round-trip -----------------------------------------
	fp := publish.NewFindingsPublisher(bc)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	eventID, err := fp.PublishFinding(ctx, fr, "msn_itest", nil)
	if err != nil {
		t.Fatalf("PublishFinding: %v", err)
	}
	if eventID != "finding-"+findingID {
		t.Fatalf("event id = %s, want finding-%s (idempotency key)", eventID, findingID)
	}
	var got *nats.Msg
	select {
	case got = <-findingsCh:
	case <-time.After(15 * time.Second):
		t.Fatal("no detect.findings message received")
	}
	env, err := bus.UnmarshalEnvelope(got.Data)
	if err != nil {
		t.Fatalf("envelope: %v", err)
	}
	if env.GetType() != "aegisbastion.detect.v1.FindingReport" {
		t.Fatalf("envelope type = %s", env.GetType())
	}
	payload, err := bus.UnpackPayload(env)
	if err != nil {
		t.Fatalf("unpack: %v", err)
	}
	gotFR, ok := payload.(*detectv1.FindingReport)
	if !ok {
		t.Fatalf("payload type %T", payload)
	}
	if gotFR.GetFindingId() != findingID || gotFR.GetRisk().GetTier() != "P1" {
		t.Fatalf("finding round-trip mismatch: %s %s", gotFR.GetFindingId(), gotFR.GetRisk().GetTier())
	}

	// --- detect.alert round-trip (Ruling C8) ---------------------------------
	mapper := publish.NewAlertMapper("org_itest", "P2")
	published, err := mapper.PublishAlert(ctx, bc, fr, "tok_itest_jti")
	if err != nil || !published {
		t.Fatalf("PublishAlert: %v %v", published, err)
	}
	select {
	case got = <-alertCh:
	case <-time.After(15 * time.Second):
		t.Fatal("no detect.alert message received")
	}
	var ce map[string]any
	if err := json.Unmarshal(got.Data, &ce); err != nil {
		t.Fatalf("cloudevent decode: %v", err)
	}
	if ce["source"] != "//aegisbastion/detect" || ce["specversion"] != "1.0" {
		t.Fatalf("bad CloudEvents envelope: %v", ce)
	}
	data, ok := ce["data"].(map[string]any)
	if !ok {
		t.Fatalf("no data: %v", ce)
	}
	if data["authorization_token_id"] != "tok_itest_jti" {
		t.Fatalf("authorization_token_id = %v (mandatory, doc 05 §5.2)", data["authorization_token_id"])
	}
	if err := publish.ValidateAlertEvent(data); err != nil {
		t.Fatalf("alert on the bus must be schema-valid: %v", err)
	}

	// Below-threshold / non-CONFIRMED findings never reach detect.alert
	// (zero-false-positive contract): P3 CONFIRMED must be skipped.
	p3 := sampleFinding(taskID, "fnd_itest_"+ulid.Make().String())
	p3.Risk = &detectv1.RiskScore{Score: 50, Tier: "P3", ScorerVersion: "risk-v1"}
	published, err = mapper.PublishAlert(ctx, bc, p3, "tok_itest_jti")
	if err != nil || published {
		t.Fatalf("P3 below threshold must skip: %v %v", published, err)
	}
}

// TestFallbackStoreRoundTrip proves the MVP fallback path (doc 04 §13)
// against the compose Postgres: findings_fallback upsert + fingerprint
// lookup + lifecycle transition, tenant-scoped, cleaned up after itself.
func TestFallbackStoreRoundTrip(t *testing.T) {
	st := pgStore(t)
	tenantID := "00000000-0000-0000-0000-000000000000"
	ctx := context.Background()

	taskID := "tsk_itest_" + ulid.Make().String()
	findingID := "fnd_itest_" + ulid.Make().String()
	fr := sampleFinding(taskID, findingID)
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = st.Pool.Exec(cctx,
			`DELETE FROM detect.findings_fallback WHERE fingerprint = $1`, fr.GetFingerprint())
	})

	sink := store.NewFallbackSink(st, tenantID)
	if err := sink.StoreFinding(ctx, fr, ""); err != nil {
		t.Fatalf("StoreFinding: %v", err)
	}
	row, err := st.FindingByFingerprint(ctx, tenantID, fr.GetFingerprint())
	if err != nil {
		t.Fatalf("FindingByFingerprint: %v", err)
	}
	if row.CheckID != "cve-2024-3400" || row.State != "confirmed_open" || row.Severity != "critical" {
		t.Fatalf("row mismatch: %+v", row)
	}
	// Redelivery merges (occurrence bump), never duplicates (doc 04 §12).
	if err := sink.StoreFinding(ctx, fr, ""); err != nil {
		t.Fatalf("StoreFinding redelivery: %v", err)
	}
	row2, err := st.FindingByFingerprint(ctx, tenantID, fr.GetFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if row2.Occurrence != row.Occurrence+1 {
		t.Fatalf("redelivery occurrence = %d, want %d", row2.Occurrence, row.Occurrence+1)
	}
	// Lifecycle transition (detect.revalidate persistence path, doc 04 §7.3).
	if err := st.TransitionState(ctx, tenantID, row.FindingID, "verified_closed"); err != nil {
		t.Fatalf("TransitionState: %v", err)
	}
	row3, err := st.FindingByFingerprint(ctx, tenantID, fr.GetFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if row3.State != "verified_closed" {
		t.Fatalf("state = %s, want verified_closed", row3.State)
	}
	// Tenant isolation: another tenant must not see the row.
	if _, err := st.FindingByFingerprint(ctx, "00000000-0000-0000-0000-000000000099", fr.GetFingerprint()); err == nil {
		t.Fatal("cross-tenant fingerprint read must miss")
	}
}

// TestInfraStreamsPresent guards the deploy contract: the detect JetStream
// topology from deploy/jetstream-bootstrap (DETECT_JOBS work queue,
// DETECT_RESULTS durable, findings + alert ingress) exists on the bus.
func TestInfraStreamsPresent(t *testing.T) {
	bc := natsBus(t)
	for _, want := range []string{"DETECT_JOBS", "DETECT_RESULTS"} {
		if _, err := bc.JetStream().StreamInfo(want); err != nil {
			t.Fatalf("stream %s missing — run deploy/jetstream-bootstrap: %v", want, err)
		}
	}
	// Findings + alert subjects must be captured by some stream.
	for _, subject := range []string{publish.SubjectFindings, publish.SubjectAlert} {
		name, err := findStreamForSubject(bc, subject)
		if err != nil {
			t.Fatalf("%s not captured by any stream: %v", subject, err)
		}
		t.Logf("%s ← stream %s", subject, name)
	}
}

func findStreamForSubject(bc *bus.Client, subject string) (string, error) {
	names := bc.JetStream().StreamNames()
	for name := range names {
		si, err := bc.JetStream().StreamInfo(name)
		if err != nil {
			continue
		}
		for _, s := range si.Config.Subjects {
			if s == subject || subjectMatchesWildcard(s, subject) {
				return name, nil
			}
		}
	}
	return "", fmt.Errorf("no stream captures %s", subject)
}

func subjectMatchesWildcard(pattern, subject string) bool {
	if strings.HasSuffix(pattern, ">") {
		return strings.HasPrefix(subject, strings.TrimSuffix(pattern, ">"))
	}
	if strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(subject, strings.TrimSuffix(pattern, "*"))
	}
	return false
}
