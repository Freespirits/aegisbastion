package ctypes

import (
	"testing"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"
)

// TestV1_EnumCoverage proves the table covers the entire change_type v1 enum
// (doc 03 §5.2: 30 values) bidirectionally.
func TestV1_EnumCoverage(t *testing.T) {
	if len(V1) != 30 {
		t.Fatalf("V1 has %d entries, want 30 (doc 03 §5.2)", len(V1))
	}
	seen := map[string]bool{}
	for i := 1; i <= 30; i++ {
		ct := monitorv1.ChangeType(i)
		e, ok := LookupProto(ct)
		if !ok {
			t.Fatalf("proto value %d (%s) missing from V1", i, ct)
		}
		if int(e.Proto) != i {
			t.Fatalf("entry %s proto = %d, want %d", e.Type, e.Proto, i)
		}
		back, ok := Lookup(e.Type)
		if !ok || back.Proto != ct {
			t.Fatalf("wire string %q does not round-trip", e.Type)
		}
		if e.Group == "" {
			t.Fatalf("entry %s has no group", e.Type)
		}
		seen[e.Type] = true
	}
	// Doc 03 §5.2 exact wire strings.
	want := []string{
		"asset.new", "asset.removed", "asset.reactivated",
		"dns.records_changed", "dns.dangling_cname", "dns.new_records", "dns.ns_changed",
		"tls.cert_changed", "tls.cert_expiring", "tls.cert_expired",
		"tls.protocol_downgrade", "tls.hostname_mismatch",
		"http.status_changed", "http.title_changed", "http.content_changed",
		"http.headers_changed", "http.tech_added", "http.tech_removed",
		"http.redirect_target_changed",
		"port.opened", "port.closed",
		"cloud.config_drift", "cloud.resource_new", "cloud.resource_removed",
		"baseline.drift", "baseline.drift_resolved",
		"exposure.opened", "exposure.closed",
		"monitor.probe_failing", "monitor.change_burst",
	}
	for _, w := range want {
		if !seen[w] {
			t.Fatalf("doc 03 §5.2 value %q missing from V1", w)
		}
	}
}

// TestAlertableSet proves the doc 03 §5.3 alertable set: all exposure.*,
// baseline.drift, dns.dangling_cname, tls.cert_expired,
// tls.hostname_mismatch, tls.protocol_downgrade, asset.new only on
// high-criticality scope.
func TestAlertableSet(t *testing.T) {
	alertable := []string{
		"exposure.opened", "exposure.closed", "baseline.drift",
		"dns.dangling_cname", "tls.cert_expired",
		"tls.hostname_mismatch", "tls.protocol_downgrade",
	}
	for _, ty := range alertable {
		if !AlertableFor(ty, "low") {
			t.Fatalf("%s must be alertable regardless of criticality", ty)
		}
	}
	notAlertable := []string{
		"asset.removed", "asset.reactivated", "dns.records_changed",
		"dns.new_records", "dns.ns_changed", "tls.cert_changed", "tls.cert_expiring",
		"http.status_changed", "http.title_changed", "http.content_changed",
		"http.headers_changed", "http.tech_added", "http.tech_removed",
		"http.redirect_target_changed", "port.opened", "port.closed",
		"baseline.drift_resolved", "monitor.probe_failing", "monitor.change_burst",
	}
	for _, ty := range notAlertable {
		if AlertableFor(ty, "critical") {
			t.Fatalf("%s must NOT be alertable", ty)
		}
	}
	// asset.new is criticality-gated.
	if AlertableFor("asset.new", "low") || AlertableFor("asset.new", "medium") {
		t.Fatal("asset.new on low/medium criticality must not alert")
	}
	if !AlertableFor("asset.new", "high") || !AlertableFor("asset.new", "critical") {
		t.Fatal("asset.new on high/critical criticality must alert")
	}
}

// TestCategoryMapping proves alert categories map per doc 03 §5.3
// (exposure|config-drift|new-asset).
func TestCategoryMapping(t *testing.T) {
	cases := map[string]string{
		"exposure.opened":        "exposure",
		"exposure.closed":        "exposure",
		"dns.dangling_cname":     "exposure",
		"tls.cert_expired":       "exposure",
		"tls.hostname_mismatch":  "exposure",
		"tls.protocol_downgrade": "exposure",
		"baseline.drift":         "config-drift",
		"asset.new":              "new-asset",
	}
	for ty, cat := range cases {
		e, ok := Lookup(ty)
		if !ok || e.Category != cat {
			t.Fatalf("%s category = %q, want %q", ty, e.Category, cat)
		}
	}
}
