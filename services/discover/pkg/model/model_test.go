package model

import "testing"

func TestCanonicalizeDomain(t *testing.T) {
	cases := []struct {
		raw      string
		want     string
		wildcard bool
		wantErr  bool
	}{
		{"Example.COM", "example.com", false, false},
		{"www.Example.com.", "www.example.com", false, false},
		{"*.example.com", "example.com", true, false},
		{"bücher.de", "xn--bcher-kva.de", false, false},
		{"", "", false, true},
		{"a..b", "", false, true},
	}
	for _, c := range cases {
		got, wc, err := CanonicalizeDomain(c.raw)
		if c.wantErr {
			if err == nil {
				t.Errorf("CanonicalizeDomain(%q): want error, got %q", c.raw, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("CanonicalizeDomain(%q): %v", c.raw, err)
			continue
		}
		if got != c.want || wc != c.wildcard {
			t.Errorf("CanonicalizeDomain(%q) = (%q,%v), want (%q,%v)", c.raw, got, wc, c.want, c.wildcard)
		}
	}
}

func TestCanonicalizeIP(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":        "203.0.113.7",
		"::ffff:203.0.113.7": "203.0.113.7", // 4-in-6 unmapped to canonical v4
		"2001:db8::1":        "2001:db8::1",
		"2001:0DB8:0000::1":  "2001:db8::1",
	}
	for raw, want := range cases {
		got, err := CanonicalizeIP(raw)
		if err != nil {
			t.Errorf("CanonicalizeIP(%q): %v", raw, err)
			continue
		}
		if got != want {
			t.Errorf("CanonicalizeIP(%q) = %q, want %q", raw, got, want)
		}
	}
	if _, err := CanonicalizeIP("999.1.2.3"); err == nil {
		t.Error("CanonicalizeIP(999.1.2.3): want error")
	}
}

func TestCanonicalizeCIDR(t *testing.T) {
	got, err := CanonicalizeCIDR("203.0.113.99/24")
	if err != nil {
		t.Fatal(err)
	}
	if got != "203.0.113.0/24" {
		t.Errorf("masked form = %q, want 203.0.113.0/24", got)
	}
}

func TestCanonicalizeASN(t *testing.T) {
	for raw, want := range map[string]string{"AS64500": "AS64500", "64500": "AS64500", "as64500": "AS64500"} {
		got, err := CanonicalizeASN(raw)
		if err != nil || got != want {
			t.Errorf("CanonicalizeASN(%q) = %q, %v; want %q", raw, got, err, want)
		}
	}
	if _, err := CanonicalizeASN("ASXYZ"); err == nil {
		t.Error("CanonicalizeASN(ASXYZ): want error")
	}
}

func TestClassifyDomainAsset(t *testing.T) {
	if typ, ok := ClassifyDomainAsset("example.com", "example.com"); !ok || typ != AssetDomain {
		t.Errorf("apex classification = %v,%v", typ, ok)
	}
	if typ, ok := ClassifyDomainAsset("www.example.com", "example.com"); !ok || typ != AssetSubdomain {
		t.Errorf("subdomain classification = %v,%v", typ, ok)
	}
	if _, ok := ClassifyDomainAsset("other.org", "example.com"); ok {
		t.Error("out-of-apex host must not classify")
	}
	if IsSubdomainOf("example.com", "example.com") {
		t.Error("apex is not a subdomain of itself")
	}
}

func TestConfidenceScoring(t *testing.T) {
	// Single CT source: 0.9.
	if c := Confidence([]float64{WeightCTLog}); c != 0.9 {
		t.Errorf("single CT = %v, want 0.9", c)
	}
	// CT + passive DNS corroboration: 0.9 + 0.1 = 1.0.
	if c := Confidence([]float64{WeightCTLog, WeightPassiveDNS}); c != 1.0 {
		t.Errorf("CT+PDNS = %v, want 1.0 (capped)", c)
	}
	// Two aggregators: 0.7 + 0.1.
	if c := Confidence([]float64{WeightAggregator, WeightAggregator}); c < 0.799 || c > 0.801 {
		t.Errorf("2 aggregators = %v, want 0.8", c)
	}
	// Below 0.5 ⇒ candidate.
	if StatusForConfidence(0.4) != AssetCandidate {
		t.Error("0.4 must be candidate")
	}
	if StatusForConfidence(0.5) != AssetActive {
		t.Error("0.5 must be active")
	}
}

func TestDiscoveryOrderValidate(t *testing.T) {
	valid := func() *DiscoveryOrder {
		return &DiscoveryOrder{
			TenantID:      "11111111-1111-1111-1111-111111111111",
			RequestedBy:   RequestedBy{Commander: "cai", AgentID: "cai-1", HumanPrincipal: "op@example.com"},
			Seeds:         []Seed{{Type: SeedDomain, Value: "example.com"}},
			Techniques:    []Technique{TechniqueCT},
			Authorization: Authorization{ROEID: "roe_01J9TEST"},
		}
	}
	o := valid()
	if err := o.Validate(); err != nil {
		t.Fatalf("valid order rejected: %v", err)
	}
	if o.SchemaVersion != SchemaVersion {
		t.Errorf("schema_version defaulted to %q, want %s", o.SchemaVersion, SchemaVersion)
	}

	bad := valid()
	bad.Techniques = nil
	if err := bad.Validate(); err == nil {
		t.Error("order without techniques must be rejected")
	}
	bad = valid()
	bad.Authorization.ROEID = ""
	if err := bad.Validate(); err == nil {
		t.Error("order without roe_id must be rejected")
	}
	bad = valid()
	bad.Seeds = append(bad.Seeds, Seed{Type: SeedDomain, Value: "EXAMPLE.com"})
	if err := bad.Validate(); err == nil {
		t.Error("duplicate seeds must be rejected")
	}
	bad = valid()
	bad.TenantID = "not-a-uuid"
	if err := bad.Validate(); err == nil {
		t.Error("non-uuid tenant must be rejected")
	}
	bad = valid()
	bad.SchemaVersion = "0.9"
	if err := bad.Validate(); err == nil {
		t.Error("unsupported schema_version must be rejected")
	}
}

func TestTechniqueMapping(t *testing.T) {
	// Gatekeeper capability registry alignment (services/gatekeeper
	// internal/capreg: discover.passive.* / discover.cloud.* → R0).
	for _, tech := range AllTechniques() {
		cap := tech.Capability()
		if cap == "" {
			t.Errorf("technique %s has no capability mapping", tech)
		}
		if tech.Active() {
			continue // MVP: dropped with ACTIVE_NOT_ALLOWED
		}
		if tech.Lane() == "" {
			t.Errorf("technique %s has no lane", tech)
		}
	}
	if TechniqueSubdomainActive.Lane() != LaneActive {
		t.Error("subdomain_active must map to the reserved active lane")
	}
}
