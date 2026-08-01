package rules

import (
	"testing"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

func TestExposureV1_RuleCount(t *testing.T) {
	if len(ExposureV1) != 25 {
		t.Fatalf("exposure_rules/v1 has %d rules, want 25 (doc 03 §7.4)", len(ExposureV1))
	}
	seen := map[string]bool{}
	for _, r := range ExposureV1 {
		if seen[r.ID] {
			t.Fatalf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if r.Severity == "" || r.Title == "" {
			t.Fatalf("rule %s missing severity/title", r.ID)
		}
	}
	for _, want := range []string{"EXP-001", "EXP-010", "EXP-025"} {
		if !seen[want] {
			t.Fatalf("%s missing", want)
		}
	}
}

func findFinding(fs []Finding, id string) *Finding {
	for i := range fs {
		if fs[i].RuleID == id {
			return &fs[i]
		}
	}
	return nil
}

func TestExposure_KeyRules(t *testing.T) {
	// EXP-001: dangling takeable CNAME → critical.
	in := &Input{Identifier: "app.acme.com", DNS: &snapshot.DNSData{
		Dangling: &snapshot.DanglingCNAME{Target: "x.azurewebsites.net", TakeableService: "azurewebsites.net"},
	}}
	f := findFinding(EvaluateExposure(in), "EXP-001")
	if f == nil || f.Severity != "critical" {
		t.Fatalf("EXP-001 must fire critical: %+v", f)
	}
	// Non-takeable dangling → EXP-019 (medium), not EXP-001.
	in.DNS.Dangling.TakeableService = ""
	fs := EvaluateExposure(in)
	if findFinding(fs, "EXP-001") != nil {
		t.Fatal("EXP-001 must not fire without takeable service")
	}
	if findFinding(fs, "EXP-019") == nil {
		t.Fatal("EXP-019 must fire on non-takeable dangling")
	}

	// EXP-003: expired cert.
	in = &Input{TLS: &snapshot.TLSData{DaysToExpiry: -3,
		Leaf: snapshot.TLSCert{NotAfter: "2026-07-01T00:00:00Z"}, HostnameMatch: true}}
	if findFinding(EvaluateExposure(in), "EXP-003") == nil {
		t.Fatal("EXP-003 must fire on expired cert")
	}
	// EXP-005: TLS 1.0.
	in = &Input{TLS: &snapshot.TLSData{Negotiated: snapshot.TLSNeg{Version: "1.0"},
		DaysToExpiry: 100, HostnameMatch: true}}
	if findFinding(EvaluateExposure(in), "EXP-005") == nil {
		t.Fatal("EXP-005 must fire on TLS ≤ 1.1")
	}
	// EXP-004: admin port open.
	in = &Input{TCP: &snapshot.TCPData{Ports: []snapshot.PortState{{Port: 3389, State: "open"}}}}
	if findFinding(EvaluateExposure(in), "EXP-004") == nil {
		t.Fatal("EXP-004 must fire on open RDP")
	}
	// EXP-008: EOL php.
	in = &Input{HTTP: &snapshot.HTTPData{Status: 200,
		Tech: []snapshot.Tech{{Name: "php", Version: "7.2.34", Confidence: "sure"}}}}
	if findFinding(EvaluateExposure(in), "EXP-008") == nil {
		t.Fatal("EXP-008 must fire on EOL php")
	}
	// EXP-009: phpmyadmin newly added.
	in = &Input{
		HTTP:     &snapshot.HTTPData{Status: 200, Tech: []snapshot.Tech{{Name: "phpmyadmin", Confidence: "sure"}}},
		PrevHTTP: &snapshot.HTTPData{Status: 200},
	}
	if findFinding(EvaluateExposure(in), "EXP-009") == nil {
		t.Fatal("EXP-009 must fire on newly-added phpmyadmin")
	}
	// EXP-009 requires a previous observation (no fire on first sight).
	in.PrevHTTP = nil
	if findFinding(EvaluateExposure(in), "EXP-009") != nil {
		t.Fatal("EXP-009 must not fire without a previous observation")
	}
	// EXP-010: new high-criticality asset without owner.
	in = &Input{Identifier: "grafana.acme.com", Criticality: "high", NewAsset: true}
	if findFinding(EvaluateExposure(in), "EXP-010") == nil {
		t.Fatal("EXP-010 must fire on untagged high-criticality new asset")
	}
	in.OwnerTag = "team-infra"
	if findFinding(EvaluateExposure(in), "EXP-010") != nil {
		t.Fatal("EXP-010 must not fire when owner tag present")
	}
	// EXP-023: plain HTTP content.
	in = &Input{HTTP: &snapshot.HTTPData{FinalURL: "http://api.acme.com/", Status: 200}}
	if findFinding(EvaluateExposure(in), "EXP-023") == nil {
		t.Fatal("EXP-023 must fire on plain-HTTP content")
	}
	// Clean asset → no findings.
	in = &Input{
		Identifier: "api.acme.com", Criticality: "medium",
		DNS: &snapshot.DNSData{Records: map[string][]string{"A": {"203.0.113.1"}, "NS": {"ns1.x", "ns2.x"}}},
		TLS: &snapshot.TLSData{DaysToExpiry: 100, HostnameMatch: true,
			Leaf:       snapshot.TLSCert{NotAfter: "2026-12-01T00:00:00Z"},
			Negotiated: snapshot.TLSNeg{Version: "1.3", Cipher: "TLS_AES_256_GCM_SHA384"}},
		HTTP: &snapshot.HTTPData{FinalURL: "https://api.acme.com/", Status: 200,
			HeadersCanonical: map[string]string{"server": "nginx"},
			Tech:             []snapshot.Tech{{Name: "nginx", Confidence: "sure"}}},
	}
	if fs := EvaluateExposure(in); len(fs) != 0 {
		t.Fatalf("clean asset must produce no findings, got %+v", fs)
	}
}

func TestBaseline_EvaluateAndCapture(t *testing.T) {
	in := &Input{HTTP: &snapshot.HTTPData{
		FinalURL: "https://api.acme.com/", Status: 200,
		HeadersCanonical: map[string]string{"strict-transport-security": "max-age=63072000"},
		Tech:             []snapshot.Tech{{Name: "nginx", Confidence: "sure"}},
	}}
	// hsts-required passes.
	r := &BaselineRule{ID: "hsts-required", Type: "http_header", Severity: "medium",
		Expect: map[string]any{"header": "strict-transport-security", "present": true}}
	if v := EvaluateBaseline(r, in); v != nil {
		t.Fatalf("compliant HSTS flagged: %+v", v)
	}
	// CSP required → violation.
	r2 := &BaselineRule{ID: "csp-required", Type: "http_header", Severity: "medium",
		Expect: map[string]any{"header": "content-security-policy", "present": true}}
	if v := EvaluateBaseline(r2, in); v == nil {
		t.Fatal("missing CSP must violate")
	}
	// tech allowlist.
	r3 := &BaselineRule{ID: "approved-tech", Type: "tech_allowlist", Severity: "low",
		Expect: map[string]any{"allowed": []any{"nginx", "react"}}}
	if v := EvaluateBaseline(r3, in); v != nil {
		t.Fatalf("allowlisted tech flagged: %+v", v)
	}
	// Capture: HSTS present → captured rule requires it; then regression trips.
	cap := CaptureBaseline("bl_1", "asset_1", "medium", in)
	if cap.Type != "captured" {
		t.Fatalf("captured rule type = %s", cap.Type)
	}
	in.HTTP.HeadersCanonical = map[string]string{}
	if v := EvaluateBaseline(cap, in); v == nil {
		t.Fatal("HSTS regression after capture must violate")
	}
}
