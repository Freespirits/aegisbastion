package capreg

import (
	"os"
	"path/filepath"
	"testing"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

func TestDefaultLookup(t *testing.T) {
	r := Default()
	cases := []struct {
		capability string
		want       platformv1.RiskClass
		ok         bool
	}{
		{"monitor.watch", platformv1.RiskClass_RISK_CLASS_R1, true},
		{"monitor.rescan", platformv1.RiskClass_RISK_CLASS_R1, true},
		{"monitor.baseline.set", platformv1.RiskClass_RISK_CLASS_R0, true},
		{"stress.http_flood", platformv1.RiskClass_RISK_CLASS_R2, true},
		{"stress.syn_flood", platformv1.RiskClass_RISK_CLASS_R2, true},
		{"ai_redteam.prompt_injection", platformv1.RiskClass_RISK_CLASS_R3, true},
		{"redteam.api_probe", platformv1.RiskClass_RISK_CLASS_R3, true},
		{"recon.subdomain_enum", platformv1.RiskClass_RISK_CLASS_R1, true},
		{"vuln.validate", platformv1.RiskClass_RISK_CLASS_R2, true},
		{"scan.active", platformv1.RiskClass_RISK_CLASS_R1, true},
		{"nonsense.unknown", platformv1.RiskClass_RISK_CLASS_UNSPECIFIED, false},
	}
	for _, c := range cases {
		got, ok := r.Lookup(c.capability)
		if got != c.want || ok != c.ok {
			t.Errorf("Lookup(%q) = %v,%v; want %v,%v", c.capability, got, ok, c.want, c.ok)
		}
	}
}

func TestLoadFileOverride(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "caps.json")
	if err := os.WriteFile(path, []byte(`{"custom.probe": "R2", "monitor.*": "R1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	r := Default()
	if err := r.LoadFile(path); err != nil {
		t.Fatal(err)
	}
	if rc, ok := r.Lookup("custom.probe"); !ok || rc != platformv1.RiskClass_RISK_CLASS_R2 {
		t.Errorf("custom.probe should resolve R2, got %v,%v", rc, ok)
	}
	// Pattern override shadows the exact defaults for monitor.watch? Exact
	// entries still win over patterns.
	if rc, ok := r.Lookup("monitor.watch"); !ok || rc != platformv1.RiskClass_RISK_CLASS_R1 {
		t.Errorf("monitor.watch should stay R1, got %v,%v", rc, ok)
	}
}

func TestRiskClassRoundTrip(t *testing.T) {
	for _, s := range []string{"R0", "R1", "R2", "R3"} {
		rc, err := ParseRiskClass(s)
		if err != nil {
			t.Fatal(err)
		}
		if RiskClassString(rc) != s {
			t.Errorf("round trip %s failed, got %s", s, RiskClassString(rc))
		}
	}
	if _, err := ParseRiskClass("T2"); err == nil {
		t.Error("T2 (deprecated tier) must not parse")
	}
}
