package publish

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/types/known/timestamppb"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"
)

func confirmedFinding(tier string, score uint32) *detectv1.FindingReport {
	return &detectv1.FindingReport{
		FindingId:   "fnd_01J9A7TEST",
		Fingerprint: "sha256:8c41abcd",
		MissionId:   "msn_1",
		TaskId:      "tsk_1",
		RoeId:       "roe_1",
		Target:      "https://api.acme.com/login",
		AssetRef:    "asset:host:api.acme.com",
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
			Method:           "evs.poc",
			EvidenceRefs:     []string{"s3://artifacts/msn_1/tsk_1/fnd_1/transcript.http"},
			ValidatedAt:      timestamppb.New(time.Date(2026, 7, 30, 8, 11, 2, 0, time.UTC)),
			ValidatorVersion: "ave-0.1.0",
			Confidence:       0.99,
		},
		Risk: &detectv1.RiskScore{
			Score: score, Tier: tier, ScorerVersion: "risk-v1",
		},
		Status: detectv1.FindingStatus_FINDING_STATUS_OPEN,
	}
}

// TestEmbeddedSchemaMatchesCanonical guards against drift between the
// embedded copy used at runtime and the canonical repo schema
// (schemas/alert/v1/alert-event.schema.json).
func TestEmbeddedSchemaMatchesCanonical(t *testing.T) {
	canonical, err := os.ReadFile("../../../../schemas/alert/v1/alert-event.schema.json")
	if err != nil {
		t.Skipf("canonical schema not reachable from here: %v", err)
	}
	if string(canonical) != string(alertSchemaJSON) {
		t.Fatal("embedded alert-event.schema.json drifted from schemas/alert/v1 — re-copy it")
	}
}

func TestMapProducesSchemaValidAlert(t *testing.T) {
	m := NewAlertMapper("org_aegisbastion", "P2")
	payload, eventID, err := m.Map(confirmedFinding("P1", 96), "tok_01J9ZM8W3F")
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if eventID == "" {
		t.Fatal("no event id")
	}
	var env map[string]any
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	if env["specversion"] != "1.0" || env["source"] != "//aegisbastion/detect" || env["type"] != "com.aegisbastion.alert.v1" {
		t.Fatalf("bad CloudEvents envelope: %v", env)
	}
	data, ok := env["data"].(map[string]any)
	if !ok {
		t.Fatalf("no data in envelope: %v", env)
	}
	// Ruling C8 / doc 04 §4.3 field mapping.
	if data["authorization_token_id"] != "tok_01J9ZM8W3F" {
		t.Errorf("authorization_token_id = %v", data["authorization_token_id"])
	}
	if data["confidence"] != "confirmed" || data["category"] != "vuln" {
		t.Errorf("confidence/category: %v %v", data["confidence"], data["category"])
	}
	if data["severity"] != "critical" {
		t.Errorf("severity = %v", data["severity"])
	}
	if data["fingerprint_hint"] != "sha256:8c41abcd" {
		t.Errorf("fingerprint_hint = %v", data["fingerprint_hint"])
	}
	if data["pii_classification"] != "none" {
		t.Errorf("pii_classification = %v", data["pii_classification"])
	}
	if data["source_module"] != "detect" || data["source_event_id"] != "fnd_01J9A7TEST" {
		t.Errorf("source fields: %v %v", data["source_module"], data["source_event_id"])
	}
	asset := data["asset"].(map[string]any)
	if asset["identifier"] != "api.acme.com" || asset["kind"] != "domain" {
		t.Errorf("asset = %v", asset)
	}
	ev := data["evidence"].(map[string]any)
	if ev["scanner"] != "nuclei" {
		t.Errorf("evidence.scanner = %v", ev["scanner"])
	}
	// The whole document validates against the canonical schema (Map already
	// gates on this; re-validate explicitly for the contract test).
	if err := ValidateAlertEvent(data); err != nil {
		t.Fatalf("mapped event must validate: %v", err)
	}
}

func TestMapRequiresTokenJTI(t *testing.T) {
	m := NewAlertMapper("org_aegisbastion", "P2")
	if _, _, err := m.Map(confirmedFinding("P1", 96), ""); err == nil {
		t.Fatal("missing authorization_token_id must fail the mapping (doc 05 §5.2 mandatory)")
	}
}

func TestSchemaNegativeCases(t *testing.T) {
	m := NewAlertMapper("org_aegisbastion", "P2")
	payload, _, err := m.Map(confirmedFinding("P1", 96), "tok_abc")
	if err != nil {
		t.Fatal(err)
	}
	var env map[string]any
	if err := json.Unmarshal(payload, &env); err != nil {
		t.Fatal(err)
	}
	good := env["data"].(map[string]any)

	mutate := func(fn func(map[string]any)) map[string]any {
		raw, _ := json.Marshal(good)
		var v map[string]any
		_ = json.Unmarshal(raw, &v)
		fn(v)
		return v
	}

	cases := []struct {
		name string
		fn   func(map[string]any)
	}{
		{"missing authorization_token_id", func(v map[string]any) { delete(v, "authorization_token_id") }},
		{"authorization_token_id not tok_", func(v map[string]any) { v["authorization_token_id"] = "jwt_abc" }},
		{"bad severity enum", func(v map[string]any) { v["severity"] = "catastrophic" }},
		{"bad confidence enum", func(v map[string]any) { v["confidence"] = "sure" }},
		{"bad category enum", func(v map[string]any) { v["category"] = "vulnerability" }},
		{"bad source_module enum", func(v map[string]any) { v["source_module"] = "redteam" }},
		{"additional property", func(v map[string]any) { v["surprise"] = true }},
		{"missing org_id", func(v map[string]any) { delete(v, "org_id") }},
		{"missing asset", func(v map[string]any) { delete(v, "asset") }},
		{"bad occurred_at", func(v map[string]any) { v["occurred_at"] = "yesterday" }},
		{"bad asset kind", func(v map[string]any) {
			v["asset"] = map[string]any{"asset_id": "a", "kind": "toaster", "identifier": "x"}
		}},
		{"pii enum", func(v map[string]any) { v["pii_classification"] = "secret" }},
	}
	for _, tc := range cases {
		if err := ValidateAlertEvent(mutate(tc.fn)); err == nil {
			t.Errorf("%s: mutated event must FAIL schema validation", tc.name)
		}
	}

	// A "probable" confidence without a token id is legal (the conditional
	// requirement only binds confirmed vuln/exposure) — documents the rule.
	v := mutate(func(v map[string]any) {
		delete(v, "authorization_token_id")
		v["confidence"] = "probable"
	})
	if err := ValidateAlertEvent(v); err != nil {
		t.Errorf("probable confidence without token id should be schema-valid: %v", err)
	}
}

func TestShouldAlertGating(t *testing.T) {
	if !ShouldAlert(confirmedFinding("P1", 96), "P2") {
		t.Error("CONFIRMED P1 must alert at P2 threshold")
	}
	if !ShouldAlert(confirmedFinding("P2", 70), "P2") {
		t.Error("CONFIRMED P2 must alert at P2 threshold")
	}
	if ShouldAlert(confirmedFinding("P3", 50), "P2") {
		t.Error("CONFIRMED P3 must NOT alert at P2 threshold")
	}
	// INCONCLUSIVE never alerts, any severity/tier (zero-false-positive
	// contract; doc 04 §14 acceptance test 4).
	fr := confirmedFinding("P1", 96)
	fr.Validation.Verdict = detectv1.ValidationVerdict_VALIDATION_VERDICT_INCONCLUSIVE
	if ShouldAlert(fr, "P5") {
		t.Error("INCONCLUSIVE must never alert")
	}
	fr.Validation.Verdict = detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_VALIDATABLE
	if ShouldAlert(fr, "P5") {
		t.Error("NOT_VALIDATABLE must never alert")
	}
	fr.Validation.Verdict = detectv1.ValidationVerdict_VALIDATION_VERDICT_NOT_REPRODUCIBLE
	if ShouldAlert(fr, "P5") {
		t.Error("NOT_REPRODUCIBLE must never alert")
	}
}

type fakeBus struct{ msgs []*nats.Msg }

func (f *fakeBus) PublishMsg(_ context.Context, msg *nats.Msg) error {
	f.msgs = append(f.msgs, msg)
	return nil
}

type failBus struct{}

func (f *failBus) PublishMsg(_ context.Context, msg *nats.Msg) error {
	return errors.New("bus down")
}

func TestPublishAlertRoundTripAndDedupID(t *testing.T) {
	m := NewAlertMapper("org_aegisbastion", "P2")
	fb := &fakeBus{}
	ok, err := m.PublishAlert(context.Background(), fb, confirmedFinding("P1", 96), "tok_x")
	if err != nil || !ok {
		t.Fatalf("publish: %v %v", ok, err)
	}
	if len(fb.msgs) != 1 {
		t.Fatalf("got %d messages", len(fb.msgs))
	}
	msg := fb.msgs[0]
	if msg.Subject != "detect.alert" {
		t.Fatalf("subject = %s", msg.Subject)
	}
	if got := msg.Header.Get(nats.MsgIdHdr); got != "alert-fnd_01J9A7TEST" {
		t.Fatalf("msg id = %s (must be idempotent on finding)", got)
	}

	// Below threshold → nothing published.
	ok, err = m.PublishAlert(context.Background(), fb, confirmedFinding("P4", 20), "tok_x")
	if err != nil || ok {
		t.Fatalf("below-threshold must skip: %v %v", ok, err)
	}
	if len(fb.msgs) != 1 {
		t.Fatal("no extra message expected")
	}

	// Bus failure surfaces as an error (findings stream remains canonical).
	if _, err := m.PublishAlert(context.Background(), &failBus{}, confirmedFinding("P1", 96), "tok_x"); err == nil {
		t.Fatal("bus failure must surface")
	}
}
