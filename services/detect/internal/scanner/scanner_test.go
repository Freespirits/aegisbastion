package scanner

import (
	"context"
	"strings"
	"testing"
)

type collect struct{ results []RawResult }

func (c *collect) Emit(r RawResult) error { c.results = append(c.results, r); return nil }

func unlimitedLimiter() Limiter { return NewBudgetLimiter(0, nil) }

func TestNucleiFixtureParsesFindings(t *testing.T) {
	a := NewNuclei("", "testdata")
	job := Job{
		JobID: "job_1", TaskID: "tsk_1", Target: "https://api.acme.test",
		Adapter: AdapterNuclei, FixtureFile: "nuclei-basic.jsonl", SafeMode: true,
	}
	var out collect
	if err := a.Run(context.Background(), job, unlimitedLimiter(), &out); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// 4 findings in fixture; the dos-tagged template must be dropped by the
	// wrapper (doc 04 §10.3).
	if len(out.results) != 4 {
		t.Fatalf("got %d results, want 4 (DoS-class dropped): %+v", len(out.results), out.results)
	}
	byCheck := map[string]RawResult{}
	for _, r := range out.results {
		byCheck[r.CheckID] = r
	}
	panos, ok := byCheck["cve-2024-3400"]
	if !ok {
		t.Fatalf("cve-2024-3400 missing: %v", byCheck)
	}
	if panos.Severity != "critical" || panos.CVE != "CVE-2024-3400" || panos.CWE != "CWE-77" {
		t.Errorf("bad normalization: %+v", panos)
	}
	if panos.VulnClass != ClassVersionCVE {
		t.Errorf("class = %q, want %q", panos.VulnClass, ClassVersionCVE)
	}
	if panos.MatchedAt != "https://api.acme.test/login" {
		t.Errorf("matched_at = %q", panos.MatchedAt)
	}
	if len(panos.Raw) == 0 {
		t.Error("raw evidence not archived")
	}
	if xss, ok := byCheck["reflected-xss-search"]; !ok || xss.VulnClass != ClassReflectedXSS {
		t.Errorf("xss result wrong: %+v", xss)
	}
	if hdr, ok := byCheck["missing-security-headers"]; !ok || hdr.VulnClass != ClassSecurityHeader || hdr.Severity != "informational" {
		t.Errorf("header result wrong: %+v", hdr)
	}
	if _, banned := byCheck["dos-slowloris-check"]; banned {
		t.Error("DoS-class result leaked through the wrapper")
	}
}

func TestNucleiValidateJobRefusesDoS(t *testing.T) {
	a := NewNuclei("", "testdata")
	err := a.ValidateJob(Job{Checks: []string{"cve-2024-3400", "dos-http-flood"}})
	if err == nil || !strings.Contains(err.Error(), "DoS") {
		t.Fatalf("want DoS refusal, got %v", err)
	}
}

func TestNmapFixtureParsesVulnScripts(t *testing.T) {
	a := NewNmap("", "testdata")
	job := Job{
		JobID: "job_2", TaskID: "tsk_2", Target: "192.0.2.10",
		Adapter: AdapterNmap, FixtureFile: "nmap-basic.xml", SafeMode: true,
	}
	var out collect
	if err := a.Run(context.Background(), job, unlimitedLimiter(), &out); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// heartbleed (VULNERABLE), ssl-dh-params (weak), ms17-010 (VULNERABLE).
	// The closed-port script and the down host contribute nothing.
	if len(out.results) != 3 {
		t.Fatalf("got %d results, want 3: %+v", len(out.results), out.results)
	}
	byCheck := map[string]RawResult{}
	for _, r := range out.results {
		byCheck[r.CheckID] = r
	}
	hb, ok := byCheck["ssl-heartbleed"]
	if !ok {
		t.Fatalf("ssl-heartbleed missing: %v", byCheck)
	}
	if hb.CVE != "CVE-2014-0160" || hb.Severity != "high" || hb.VulnClass != ClassTLSMisconfig {
		t.Errorf("heartbleed normalization wrong: %+v", hb)
	}
	if hb.MatchedAt != "192.0.2.10:443/tcp" {
		t.Errorf("matched_at = %q", hb.MatchedAt)
	}
	ms, ok := byCheck["smb-vuln-ms17-010"]
	if !ok || ms.CVE != "CVE-2017-0143" || ms.Severity != "critical" {
		t.Errorf("ms17-010 normalization wrong: %+v", ms)
	}
	if _, present := byCheck["http-vuln-cve2021-41773"]; present {
		t.Error("closed-port script result must not be reported")
	}
}

func TestNmapValidateJobRefusesDoSCategory(t *testing.T) {
	a := NewNmap("", "testdata")
	for _, checks := range [][]string{{"vuln", "dos"}, {"intrusive"}, {"smb-vuln-ms17-010", "dos-synflood"}} {
		if err := a.ValidateJob(Job{Checks: checks}); err == nil {
			t.Fatalf("checks %v: want DoS refusal", checks)
		}
	}
}

func TestFilterChecks(t *testing.T) {
	kept, dropped := FilterChecks(
		[]string{"cve-2024-3400", "dos-slowloris", "ssl-heartbleed", "flood-udp"},
		[]string{"ssl-*"},
	)
	if len(kept) != 1 || kept[0] != "cve-2024-3400" {
		t.Errorf("kept = %v, want [cve-2024-3400]", kept)
	}
	if len(dropped) != 3 {
		t.Errorf("dropped = %v, want 3 entries", dropped)
	}
}

func TestBudgetLimiter(t *testing.T) {
	l := NewBudgetLimiter(2, nil)
	if !l.TakeRequest() || !l.TakeRequest() {
		t.Fatal("first two takes must succeed")
	}
	if l.TakeRequest() {
		t.Fatal("third take must fail (budget exhausted)")
	}
	u := NewBudgetLimiter(0, nil)
	for i := 0; i < 100; i++ {
		if !u.TakeRequest() {
			t.Fatal("unlimited limiter refused")
		}
	}
}

func TestClassifyNuclei(t *testing.T) {
	cases := []struct {
		id   string
		tags []string
		want string
	}{
		{"cve-2024-3400", []string{"cve", "rce"}, ClassVersionCVE},
		{"reflected-xss", []string{"xss"}, ClassReflectedXSS},
		{"sqli-error", []string{"sqli"}, ClassSQLi},
		{"ssrf-callback", []string{"ssrf"}, ClassSSRF},
		{"xxe-blind", []string{"xxe"}, ClassBlindXXE},
		{"rce-oob", []string{"rce", "oob"}, ClassBlindRCE},
		{"lfi-etc", []string{"lfi"}, ClassPathTraversal},
		{"open-redirect-param", []string{"redirect"}, ClassOpenRedirect},
		{"tomcat-default-login", []string{"default-login"}, ClassDefaultCreds},
		{"ssl-weak-cipher", []string{"ssl"}, ClassTLSMisconfig},
		{"missing-hsts", []string{"header"}, ClassSecurityHeader},
		{"exposed-panel", []string{"exposure"}, ClassExposure},
		{"something-else", []string{"misc"}, ClassUnknown},
	}
	for _, tc := range cases {
		var rec nucleiLine
		rec.TemplateID = tc.id
		rec.Info.Tags = tc.tags
		if got := classifyNuclei(rec); got != tc.want {
			t.Errorf("%s: class = %q, want %q", tc.id, got, tc.want)
		}
	}
}
