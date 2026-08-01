package strixcli

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Mock determinism: identical requests yield byte-identical results, every
// finding clearly marked as canned.
func TestMockDeterminism(t *testing.T) {
	m := NewMockClient()
	req := ScanRequest{
		TaskKey:     "t1",
		Target:      "https://acme.com",
		Instruction: "Autonomous web application penetration test.",
		ScanMode:    "standard",
	}
	r1, err := m.RunScan(context.Background(), req)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	r2, err := m.RunScan(context.Background(), req)
	if err != nil {
		t.Fatalf("RunScan: %v", err)
	}
	b1, _ := json.Marshal(r1)
	b2, _ := json.Marshal(r2)
	if string(b1) != string(b2) {
		t.Errorf("mock must be deterministic:\n%s\n%s", b1, b2)
	}
	if !r1.Success || !r1.Mock {
		t.Errorf("mock result = %+v, want success+mock", r1)
	}
	if len(r1.Findings) != 1 {
		t.Fatalf("findings = %v, want 1 canned finding", r1.Findings)
	}
	f := r1.Findings[0]
	if !strings.HasPrefix(f.ID, "MOCK-") || !strings.Contains(f.Title, "MOCK") {
		t.Errorf("canned finding must be unmistakably marked: %+v", f)
	}
	if f.Target != req.Target {
		t.Errorf("finding target = %q, want %q", f.Target, req.Target)
	}
	if m.Mode() != "mock" {
		t.Errorf("mode = %q", m.Mode())
	}
	if err := m.Health(context.Background()); err != nil {
		t.Errorf("mock health: %v", err)
	}
}

func TestMockRefusals(t *testing.T) {
	m := NewMockClient()
	if _, err := m.RunScan(context.Background(), ScanRequest{TaskKey: "t1"}); err == nil {
		t.Error("empty target must be refused")
	}
	if _, err := m.RunScan(context.Background(), ScanRequest{Target: "x"}); err == nil {
		t.Error("empty task key must be refused")
	}
}

// Live client construction validates the install without running a scan.
func TestCLIClientConstruction(t *testing.T) {
	if _, err := NewCLIClient("", "/tmp/x"); err == nil {
		t.Error("empty binary must be refused")
	}
	if _, err := NewCLIClient("definitely-not-a-real-strix-binary-xyz", "/tmp/x"); err == nil {
		t.Error("unresolvable binary must be refused")
	}
	// A resolvable binary stands in for strix; construction must succeed and
	// health must pass.
	c, err := NewCLIClient("go", t.TempDir())
	if err != nil {
		t.Fatalf("NewCLIClient(go): %v", err)
	}
	if c.Mode() != "live" {
		t.Errorf("mode = %q", c.Mode())
	}
	if err := c.Health(context.Background()); err != nil {
		t.Errorf("health: %v", err)
	}
}

// readFindings parses the strix_runs/<run>/vulnerabilities.json layout the
// real CLI writes (strix/report/writer.py).
func TestReadFindings(t *testing.T) {
	dir := t.TempDir()

	// No runs dir at all: clean scan, zero findings — not an error.
	findings, runDir, err := readFindings(dir)
	if err != nil || findings != nil || runDir != "" {
		t.Errorf("empty dir: got %v %q %v", findings, runDir, err)
	}

	// A run with vulnerabilities.json.
	run := filepath.Join(dir, "strix_runs", "acme-com-20240101-000000")
	if err := os.MkdirAll(run, 0o755); err != nil {
		t.Fatal(err)
	}
	reports := []map[string]any{{
		"id":                "vuln-001",
		"title":             "SQL Injection in login",
		"severity":          "critical",
		"target":            "https://acme.com/login",
		"description":       "…",
		"poc_description":   "curl …",
		"remediation_steps": "parameterize queries",
		"cve":               "",
		"cwe":               "CWE-89",
		"cvss_score":        9.8,
	}}
	raw, _ := json.Marshal(reports)
	if err := os.WriteFile(filepath.Join(run, "vulnerabilities.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	findings, runDir, err = readFindings(dir)
	if err != nil {
		t.Fatalf("readFindings: %v", err)
	}
	if runDir != run {
		t.Errorf("runDir = %q, want %q", runDir, run)
	}
	want := []Finding{{
		ID: "vuln-001", Title: "SQL Injection in login", Severity: "critical",
		Target: "https://acme.com/login", Description: "…", POCDescription: "curl …",
		Remediation: "parameterize queries", CWE: "CWE-89", CVSSScore: 9.8,
	}}
	if !reflect.DeepEqual(findings, want) {
		t.Errorf("findings = %+v, want %+v", findings, want)
	}

	// A run dir without vulnerabilities.json contributes nothing.
	if err := os.MkdirAll(filepath.Join(dir, "strix_runs", "clean-run"), 0o755); err != nil {
		t.Fatal(err)
	}
	findings, _, err = readFindings(dir)
	if err != nil || len(findings) != 1 {
		t.Errorf("with clean run: got %v %v", findings, err)
	}
}

func TestSanitize(t *testing.T) {
	if got := sanitize("https://acme.com:8443/a b"); strings.ContainsAny(got, "/: ") {
		t.Errorf("sanitize left path-unsafe chars: %q", got)
	}
	if got := sanitize(strings.Repeat("x", 200)); len(got) > 64 {
		t.Errorf("sanitize must cap length, got %d", len(got))
	}
	if got := sanitize("///"); got == "" {
		t.Error("sanitize must never return empty")
	}
}
