package alertmap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"google.golang.org/protobuf/types/known/timestamppb"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"
)

var testNow = time.Date(2026, 7, 30, 7, 0, 11, 0, time.UTC)

func repoSchemas(t *testing.T) (alertEvent, envelope *jsonschema.Schema) {
	t.Helper()
	root := filepath.Join("..", "..", "..", "..", "schemas", "alert", "v1")
	c := jsonschema.NewCompiler()
	for _, name := range []string{"alert-event.schema.json", "cloudevents-alert-envelope.schema.json"} {
		raw, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatalf("read schema %s: %v", name, err)
		}
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(raw)))
		if err != nil {
			t.Fatalf("parse schema %s: %v", name, err)
		}
		if err := c.AddResource("https://aegisbastion.io/schemas/alert/v1/"+name, doc); err != nil {
			t.Fatalf("add resource %s: %v", name, err)
		}
	}
	ae, err := c.Compile("https://aegisbastion.io/schemas/alert/v1/alert-event.schema.json")
	if err != nil {
		t.Fatalf("compile alert-event: %v", err)
	}
	ce, err := c.Compile("https://aegisbastion.io/schemas/alert/v1/cloudevents-alert-envelope.schema.json")
	if err != nil {
		t.Fatalf("compile envelope: %v", err)
	}
	return ae, ce
}

func validateJSON(t *testing.T, schema *jsonschema.Schema, raw []byte) {
	t.Helper()
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if err := schema.Validate(v); err != nil {
		t.Fatalf("schema validation failed: %v\npayload: %s", err, raw)
	}
}

func changeFixture(ct monitorv1.ChangeType, sev monitorv1.Severity, conf monitorv1.Confidence, criticality string) *monitorv1.MonitorChange {
	return &monitorv1.MonitorChange{
		SchemaVersion: "1.0",
		EventId:       "chg_01J9D6T2",
		MissionId:     "msn_01J8ZK",
		RoeId:         "roe_01J8ZM",
		OrgId:         "org_acme",
		Asset: &monitorv1.MonitoredAsset{
			AssetId: "asset_88f3", Kind: monitorv1.AssetKind_ASSET_KIND_SUBDOMAIN,
			Identifier: "api.acme.com", Criticality: criticality,
		},
		ChangeType:   ct,
		Severity:     sev,
		Confidence:   conf,
		Summary:      "TLS certificate has expired",
		Fingerprint:  "fp_9c31e7ab",
		SnapshotRefs: &monitorv1.SnapshotRefs{Before: "snp_01J90", After: "snp_01J9E"},
		OccurredAt:   timestamppb.New(testNow),
		Labels:       map[string]string{"surface": "external"},
	}
}

func TestMap_ActiveExposureConfirmed_SchemaValid(t *testing.T) {
	aeSchema, ceSchema := repoSchemas(t)
	mc := changeFixture(monitorv1.ChangeType_CHANGE_TYPE_TLS_CERT_EXPIRED,
		monitorv1.Severity_SEVERITY_HIGH, monitorv1.Confidence_CONFIDENCE_CONFIRMED, "high")
	raw, eventID, err := Map(mc, Params{
		AlertThreshold: "medium", TokenJTI: "tok_01J92G", ROEID: "roe_01J8ZM",
	}, testNow)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	if eventID == "" {
		t.Fatal("empty event id")
	}
	validateJSON(t, ceSchema, raw)

	var ce struct {
		Source string          `json:"source"`
		Type   string          `json:"type"`
		Data   json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &ce); err != nil {
		t.Fatal(err)
	}
	if ce.Source != "//aegisbastion/monitor" || ce.Type != "com.aegisbastion.alert.v1" {
		t.Fatalf("envelope source/type = %s/%s", ce.Source, ce.Type)
	}
	validateJSON(t, aeSchema, ce.Data)

	var ae AlertEvent
	if err := json.Unmarshal(ce.Data, &ae); err != nil {
		t.Fatal(err)
	}
	if ae.AuthorizationTokenID != "tok_01J92G" {
		// Mandatory for confirmed active-scan exposure alerts (doc 05 §5.2).
		t.Fatalf("authorization_token_id = %q, want tok_01J92G", ae.AuthorizationTokenID)
	}
	if ae.Category != "exposure" || ae.Severity != "high" || ae.Confidence != "confirmed" {
		t.Fatalf("category/severity/confidence = %s/%s/%s", ae.Category, ae.Severity, ae.Confidence)
	}
	if ae.FingerprintHint != "fp_9c31e7ab" || ae.DedupWindowSeconds != 86400 {
		t.Fatalf("dedup mapping wrong: %s %d", ae.FingerprintHint, ae.DedupWindowSeconds)
	}
	if ae.SourceModule != "monitor" || ae.SourceEventID != "chg_01J9D6T2" {
		t.Fatalf("source mapping wrong: %s %s", ae.SourceModule, ae.SourceEventID)
	}
	if ae.Labels["source"] != "active_probe" {
		t.Fatalf("labels.source = %q", ae.Labels["source"])
	}
}

func TestMap_PassiveCarriesROENotToken_SchemaValid(t *testing.T) {
	aeSchema, ceSchema := repoSchemas(t)
	mc := changeFixture(monitorv1.ChangeType_CHANGE_TYPE_ASSET_NEW,
		monitorv1.Severity_SEVERITY_LOW, monitorv1.Confidence_CONFIDENCE_PROBABLE, "high")
	raw, _, err := Map(mc, Params{
		AlertThreshold: "medium", TokenJTI: "tok_should_not_appear",
		ROEID: "roe_01J8ZM", Passive: true,
	}, testNow)
	if err != nil {
		t.Fatalf("Map: %v", err)
	}
	validateJSON(t, ceSchema, raw)
	var ce struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(raw, &ce); err != nil {
		t.Fatal(err)
	}
	validateJSON(t, aeSchema, ce.Data)
	var ae AlertEvent
	if err := json.Unmarshal(ce.Data, &ae); err != nil {
		t.Fatal(err)
	}
	if ae.AuthorizationTokenID != "" {
		t.Fatalf("passive alert must not carry a token id, got %q", ae.AuthorizationTokenID)
	}
	if ae.Labels["roe_id"] != "roe_01J8ZM" || ae.Labels["source"] != "passive_feed" {
		t.Fatalf("passive labels wrong: %v", ae.Labels)
	}
	if ae.Confidence != "probable" {
		t.Fatalf("passive confidence = %q, want probable", ae.Confidence)
	}
	if ae.Category != "new-asset" {
		t.Fatalf("category = %q", ae.Category)
	}
}

func TestMap_PassiveDowngradesConfirmed(t *testing.T) {
	mc := changeFixture(monitorv1.ChangeType_CHANGE_TYPE_EXPOSURE_OPENED,
		monitorv1.Severity_SEVERITY_HIGH, monitorv1.Confidence_CONFIDENCE_CONFIRMED, "high")
	raw, _, err := Map(mc, Params{Passive: true, ROEID: "roe_1"}, testNow)
	if err != nil {
		t.Fatal(err)
	}
	var ce struct {
		Data json.RawMessage `json:"data"`
	}
	_ = json.Unmarshal(raw, &ce)
	var ae AlertEvent
	_ = json.Unmarshal(ce.Data, &ae)
	if ae.Confidence != "probable" {
		t.Fatalf("passive exposure must be probable until probe confirms (doc 03 §5.3): %q", ae.Confidence)
	}
	if ae.AuthorizationTokenID != "" {
		t.Fatal("passive alert must not carry token jti")
	}
}

func TestShouldAlert_Gating(t *testing.T) {
	p := Params{AlertThreshold: "medium", TokenJTI: "tok_x"}
	cases := []struct {
		name string
		mc   *monitorv1.MonitorChange
		want bool
	}{
		{"alertable at threshold", changeFixture(monitorv1.ChangeType_CHANGE_TYPE_EXPOSURE_OPENED,
			monitorv1.Severity_SEVERITY_MEDIUM, monitorv1.Confidence_CONFIDENCE_CONFIRMED, "low"), true},
		{"alertable below threshold", changeFixture(monitorv1.ChangeType_CHANGE_TYPE_EXPOSURE_OPENED,
			monitorv1.Severity_SEVERITY_LOW, monitorv1.Confidence_CONFIDENCE_CONFIRMED, "low"), false},
		{"not in alertable set", changeFixture(monitorv1.ChangeType_CHANGE_TYPE_DNS_NS_CHANGED,
			monitorv1.Severity_SEVERITY_HIGH, monitorv1.Confidence_CONFIDENCE_CONFIRMED, "high"), false},
		{"possible never alerts", changeFixture(monitorv1.ChangeType_CHANGE_TYPE_TLS_CERT_EXPIRED,
			monitorv1.Severity_SEVERITY_HIGH, monitorv1.Confidence_CONFIDENCE_POSSIBLE, "high"), false},
		{"asset.new low criticality", changeFixture(monitorv1.ChangeType_CHANGE_TYPE_ASSET_NEW,
			monitorv1.Severity_SEVERITY_HIGH, monitorv1.Confidence_CONFIDENCE_PROBABLE, "low"), false},
		{"asset.new high criticality", changeFixture(monitorv1.ChangeType_CHANGE_TYPE_ASSET_NEW,
			monitorv1.Severity_SEVERITY_MEDIUM, monitorv1.Confidence_CONFIDENCE_PROBABLE, "high"), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldAlert(tc.mc, p); got != tc.want {
				t.Fatalf("ShouldAlert = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRepoExamplesStayValid re-validates the repo's monitor example so the
// mapping and the fixture never drift apart.
func TestRepoExamplesStayValid(t *testing.T) {
	aeSchema, _ := repoSchemas(t)
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "schemas", "examples",
		"alert-event.monitor-passive.valid.json"))
	if err != nil {
		t.Fatal(err)
	}
	validateJSON(t, aeSchema, raw)
}
