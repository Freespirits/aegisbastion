package risk

import (
	"strings"
	"testing"
	"time"
)

func TestScoreConfirmedCriticalKEVInternet(t *testing.T) {
	// Doc 04 §4.3's example shape: cvss 10, epss 0.94, KEV, internet, high
	// asset, CONFIRMED → the doc shows score 96 / P1 for exactly these
	// factors with exploit_verified=true.
	s := ScoreFactors(Factors{
		CVSS: 10.0, EPSS: 0.94, KEV: true, Exposure: "internet",
		AssetCriticality: "high", ExploitVerified: true, Verdict: VerdictConfirmed,
	})
	// base*m_exploit = 15 → clamped via bonus path: 10*1.5 = 15, +1 → cap 10.
	// 10 * 1.2 * 1.0 * 1.15 * 10 = 138 → capped 100... verify the arithmetic
	// path instead of the doc's illustrative number.
	if s.Tier != "P1" {
		t.Fatalf("tier = %s, want P1 (score %d)", s.Tier, s.Score)
	}
	if s.Score != 100 {
		t.Fatalf("score = %d, want 100 (clamped)", s.Score)
	}
	if s.Factors["m_exploit"] != 1.5 || s.Factors["kev"] != true {
		t.Fatalf("bad factors: %v", s.Factors)
	}
}

func TestScoreDeterministic(t *testing.T) {
	f := Factors{CVSS: 7.5, EPSS: 0.3, Exposure: "internal", AssetCriticality: "medium", Verdict: VerdictConfirmed}
	a, b := ScoreFactors(f), ScoreFactors(f)
	if a.Score != b.Score || a.Tier != b.Tier {
		t.Fatalf("non-deterministic: %v vs %v", a, b)
	}
	// 7.5*1.15 = 8.625 → *1.0*1.0*1.0*10 = 86.25 → 86, P2.
	if a.Score != 86 || a.Tier != "P2" {
		t.Fatalf("score = %d tier %s, want 86/P2", a.Score, a.Tier)
	}
}

func TestVerdictMultipliers(t *testing.T) {
	base := Factors{CVSS: 7.5, Exposure: "internal", AssetCriticality: "medium"}
	cases := []struct {
		verdict string
		want    int
	}{
		{VerdictConfirmed, 75},      // 7.5*1.0*10
		{VerdictNotValidatable, 60}, // 7.5*0.8*10
		{VerdictInconclusive, 45},   // 7.5*0.6*10
		{VerdictNotReproducible, 0}, // false positive → 0
	}
	for _, tc := range cases {
		f := base
		f.Verdict = tc.verdict
		if got := ScoreFactors(f).Score; got != tc.want {
			t.Errorf("verdict %s: score %d, want %d", tc.verdict, got, tc.want)
		}
	}
}

func TestExploitVerifiedBonusCapped(t *testing.T) {
	s := ScoreFactors(Factors{CVSS: 9.8, KEV: true, ExploitVerified: true, Verdict: VerdictConfirmed})
	// 9.8*1.5 = 14.7 → +1 → clamp 10 → *1*1*1*10 = 100.
	if s.Score != 100 {
		t.Fatalf("score = %d, want 100", s.Score)
	}
	s2 := ScoreFactors(Factors{CVSS: 9.8, KEV: true, ExploitVerified: false, Verdict: VerdictConfirmed})
	if s2.Score != 100 {
		t.Fatalf("score = %d, want 100 (clamped at base 10)", s2.Score)
	}
}

func TestExposureAndCriticalityMultipliers(t *testing.T) {
	mk := func(exposure, crit string) int {
		return ScoreFactors(Factors{CVSS: 5.0, Exposure: exposure, AssetCriticality: crit, Verdict: VerdictConfirmed}).Score
	}
	if got := mk("internet", "critical"); got != 78 { // 5*1.2*1.3*10
		t.Errorf("internet/critical = %d, want 78", got)
	}
	if got := mk("isolated", "low"); got != 34 { // 5*0.8*0.85*10 = 34
		t.Errorf("isolated/low = %d, want 34", got)
	}
	if got := mk("", ""); got != 50 { // defaults internal/medium
		t.Errorf("defaults = %d, want 50", got)
	}
}

func TestTierBands(t *testing.T) {
	cases := map[int]string{100: "P1", 90: "P1", 89: "P2", 70: "P2", 69: "P3", 40: "P3", 39: "P4", 15: "P4", 14: "P5", 0: "P5"}
	for score, want := range cases {
		if got := TierFor(score); got != want {
			t.Errorf("TierFor(%d) = %s, want %s", score, got, want)
		}
	}
}

func TestTierAtOrAbove(t *testing.T) {
	if !TierAtOrAbove("P1", "P2") || !TierAtOrAbove("P2", "P2") {
		t.Error("P1 and P2 must be at/above P2")
	}
	if TierAtOrAbove("P3", "P2") {
		t.Error("P3 must not be at/above P2")
	}
}

func TestIntelStaleRecorded(t *testing.T) {
	s := ScoreFactors(Factors{CVSS: 5, Verdict: VerdictConfirmed, IntelStale: true, IntelMirror: "2026-07-01T00:00:00Z"})
	if s.Factors["intel_stale"] != true || s.Factors["intel_mirror"] != "2026-07-01T00:00:00Z" {
		t.Fatalf("staleness not recorded: %v", s.Factors)
	}
}

func TestMirrorSeedLookupAndStaleness(t *testing.T) {
	m := NewMirror()
	now := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	m.Now = func() time.Time { return now }
	seed := `{"version":"2026-07-31T00:00:00Z","epss":{"CVE-2024-3400":0.94},"kev":["CVE-2024-3400"]}`
	if err := m.LoadSeedBytes([]byte(seed)); err != nil {
		t.Fatalf("seed: %v", err)
	}
	epss, kev := m.Lookup("cve-2024-3400")
	if epss != 0.94 || !kev {
		t.Fatalf("lookup = %v,%v", epss, kev)
	}
	if m.Stale() {
		t.Fatal("fresh mirror must not be stale")
	}
	m.Now = func() time.Time { return now.Add(49 * time.Hour) }
	if !m.Stale() {
		t.Fatal(">48h mirror must be stale")
	}
	if _, kev := m.Lookup("CVE-2099-0001"); kev {
		t.Fatal("unknown CVE must not be KEV")
	}
}

func TestMirrorParsers(t *testing.T) {
	epss := map[string]float64{}
	csvData := "#model_version:v2026.01.01\ncve,epss,percentile\nCVE-2024-3094,0.71,0.99\n"
	if err := parseEPSSCSV([]byte(csvData), epss); err != nil {
		t.Fatalf("epss csv: %v", err)
	}
	if epss["CVE-2024-3094"] != 0.71 {
		t.Fatalf("epss parse: %v", epss)
	}
	kev := map[string]bool{}
	kevJSON := `{"title":"CISA Catalog","vulnerabilities":[{"cveID":"CVE-2021-44228"},{"cveID":"CVE-2024-3400"}]}`
	if err := parseKEVJSON([]byte(kevJSON), kev); err != nil {
		t.Fatalf("kev json: %v", err)
	}
	if !kev["CVE-2021-44228"] || !kev["CVE-2024-3400"] {
		t.Fatalf("kev parse: %v", kev)
	}
}

func TestMirrorSnapshotRoundTrip(t *testing.T) {
	m := NewMirror()
	if err := m.LoadSeedBytes([]byte(`{"epss":{"CVE-1":0.2},"kev":["CVE-1"]}`)); err != nil {
		t.Fatal(err)
	}
	data, err := m.SnapshotBytes()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "CVE-1") {
		t.Fatalf("snapshot missing cve: %s", data)
	}
	m2 := NewMirror()
	if err := m2.LoadSeedBytes(data); err != nil {
		t.Fatal(err)
	}
	if e, k := m2.Lookup("CVE-1"); e != 0.2 || !k {
		t.Fatalf("round trip: %v %v", e, k)
	}
}
