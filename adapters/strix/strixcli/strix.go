// Package strixcli is the client side of an operator-installed Strix backend
// (usestrix/strix, Apache-2.0): the `strix` CLI runs autonomous AI
// pentest agents against a target and writes results to
// <cwd>/strix_runs/<run-name>/vulnerabilities.json (plus per-finding
// markdown and penetration_test_report.md). There is no headless HTTP API —
// the CLI is the invocation surface.
//
// The adapter runs in two modes (STRIX_MODE):
//
//   - mock (default): a deterministic in-process client that never spawns
//     Strix and never touches the network — the adapter is fully exercisable
//     without a Strix install. Given identical ScanRequests it returns
//     identical results, every finding clearly marked mock.
//   - live: shells out to the `strix` binary (STRIX_BIN), one non-interactive
//     scan per target, and parses the run's vulnerabilities.json. Strix exit
//     codes: 0 = scan completed, no findings; 2 = scan completed,
//     vulnerabilities found; anything else = failure.
package strixcli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ScanRequest is one concrete Strix invocation derived from a TaskSpec by the
// app's translation table.
type ScanRequest struct {
	// TaskKey correlates the scan back to the platform task.
	TaskKey string
	// Target is the single --target value (URL, domain, IP, or repo).
	Target string
	// Instruction is the --instruction steering text from the capability
	// mapping (what class of hunt the agents should perform).
	Instruction string
	// ScanMode is the --scan-mode value: quick | standard | deep.
	ScanMode string
}

// Finding is one vulnerability as Strix reports it in vulnerabilities.json
// (subset of the strix.report fields; PoC-bearing by design).
type Finding struct {
	ID             string  `json:"id"`
	Title          string  `json:"title"`
	Severity       string  `json:"severity"` // critical | high | medium | low | info
	Target         string  `json:"target"`
	Description    string  `json:"description"`
	POCDescription string  `json:"poc_description"`
	Remediation    string  `json:"remediation_steps"`
	CVE            string  `json:"cve"`
	CWE            string  `json:"cwe"`
	CVSSScore      float64 `json:"cvss_score"`
}

// ScanResult is the outcome of one Strix run against one target.
type ScanResult struct {
	// Success is true when the scan ran to completion (with or without
	// findings) — NOT a statement about the target's security.
	Success bool `json:"success"`
	// Mock marks canned results so they can never be mistaken for real
	// target contact.
	Mock bool `json:"mock"`
	// Findings are the validated vulnerabilities Strix reported.
	Findings []Finding `json:"findings"`
	// RunDir is the strix_runs/<run-name> directory the findings were read
	// from (live mode only).
	RunDir string `json:"run_dir,omitempty"`
	// Note carries human-readable provenance (mock marker, exit code).
	Note string `json:"note"`
}

// Client runs Strix scans. Both implementations are safe for concurrent use.
type Client interface {
	// RunScan executes one scan request and returns its parsed result.
	RunScan(ctx context.Context, req ScanRequest) (*ScanResult, error)
	// Health checks the Strix installation is usable (mock: always nil).
	Health(ctx context.Context) error
	// Mode reports "mock" or "live" for logs and health output.
	Mode() string
}

// ---------------------------------------------------------------------------
// Mock
// ---------------------------------------------------------------------------

// MockClient is the default client. Its responses are deterministic: no
// timestamps, no randomness — identical requests yield identical results.
// Every finding is clearly marked as canned so a mock result can never be
// mistaken for real target contact.
type MockClient struct{}

// NewMockClient returns the deterministic mock.
func NewMockClient() *MockClient { return &MockClient{} }

// Mode implements Client.
func (m *MockClient) Mode() string { return "mock" }

// Health implements Client (the mock is always healthy).
func (m *MockClient) Health(context.Context) error { return nil }

// RunScan implements Client.
func (m *MockClient) RunScan(_ context.Context, req ScanRequest) (*ScanResult, error) {
	if strings.TrimSpace(req.Target) == "" {
		return nil, fmt.Errorf("strix mock: empty target")
	}
	if strings.TrimSpace(req.TaskKey) == "" {
		return nil, fmt.Errorf("strix mock: empty task key")
	}
	return &ScanResult{
		Success: true,
		Mock:    true,
		Findings: []Finding{{
			ID:             "MOCK-001",
			Title:          "MOCK finding — canned Strix result, no target contact was made",
			Severity:       "info",
			Target:         req.Target,
			Description:    fmt.Sprintf("MOCK %s scan of %s (task %s): deterministic canned finding.", req.ScanMode, req.Target, req.TaskKey),
			POCDescription: "MOCK proof-of-exploit placeholder — nothing was executed.",
			Remediation:    "MOCK remediation placeholder.",
		}},
		Note: "mock mode: canned findings, Strix was not invoked",
	}, nil
}

// ---------------------------------------------------------------------------
// Live (strix CLI)
// ---------------------------------------------------------------------------

// CLIClient shells out to the `strix` binary. Each scan runs in its own
// working directory (<workDir>/<taskKey>-<i>… is the app's concern; here
// <workDir>/<sanitized taskKey>-<sanitized target>) so the run's strix_runs/
// output is unambiguous.
type CLIClient struct {
	bin     string // path to the strix executable (STRIX_BIN)
	workDir string // parent dir for per-scan working dirs (STRIX_WORK_DIR)
}

// NewCLIClient builds the live client. bin is the strix executable name or
// path; workDir is created lazily per scan.
func NewCLIClient(bin, workDir string) (*CLIClient, error) {
	bin = strings.TrimSpace(bin)
	if bin == "" {
		return nil, fmt.Errorf("strix live: empty strix binary (STRIX_BIN)")
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil, fmt.Errorf("strix live: strix binary %q not found: %v", bin, err)
	}
	workDir = strings.TrimSpace(workDir)
	if workDir == "" {
		return nil, fmt.Errorf("strix live: empty work dir (STRIX_WORK_DIR)")
	}
	return &CLIClient{bin: bin, workDir: workDir}, nil
}

// Mode implements Client.
func (c *CLIClient) Mode() string { return "live" }

// Health implements Client: the strix binary must resolve on PATH.
// (Probing `strix --version` would spawn a Python interpreter per /readyz —
// too heavy for a health check.)
func (c *CLIClient) Health(context.Context) error {
	if _, err := exec.LookPath(c.bin); err != nil {
		return fmt.Errorf("strix live: strix binary %q not found: %v", c.bin, err)
	}
	return nil
}

// RunScan implements Client: one non-interactive strix run per target, then
// parse <scan-dir>/strix_runs/<run-name>/vulnerabilities.json.
func (c *CLIClient) RunScan(ctx context.Context, req ScanRequest) (*ScanResult, error) {
	if strings.TrimSpace(req.Target) == "" {
		return nil, fmt.Errorf("strix live: empty target")
	}
	scanMode := req.ScanMode
	switch scanMode {
	case "quick", "standard", "deep":
	case "":
		scanMode = "standard"
	default:
		return nil, fmt.Errorf("strix live: invalid scan mode %q (want quick|standard|deep)", scanMode)
	}

	dir := filepath.Join(c.workDir, sanitize(req.TaskKey)+"-"+sanitize(req.Target))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("strix live: create work dir: %w", err)
	}

	args := []string{
		"--target", req.Target,
		"--non-interactive",
		"--scan-mode", scanMode,
	}
	if req.Instruction != "" {
		args = append(args, "--instruction", req.Instruction)
	}
	cmd := exec.CommandContext(ctx, c.bin, args...)
	cmd.Dir = dir
	out, runErr := cmd.CombinedOutput()

	// strix exit codes (strix/interface/main.py): 0 = completed, no findings;
	// 2 = completed, vulnerabilities found; anything else is a failure.
	exit := 0
	if runErr != nil {
		ee, ok := runErr.(*exec.ExitError)
		if !ok {
			return nil, fmt.Errorf("strix live: invoke strix: %w (output: %s)", runErr, truncate(string(out), 512))
		}
		exit = ee.ExitCode()
		if exit != 2 {
			return nil, fmt.Errorf("strix live: strix exited %d: %s", exit, truncate(string(out), 512))
		}
	}

	findings, runDir, err := readFindings(dir)
	if err != nil {
		return nil, err
	}
	return &ScanResult{
		Success:  true,
		Mock:     false,
		Findings: findings,
		RunDir:   runDir,
		Note:     fmt.Sprintf("strix exit %d, %d finding(s)", exit, len(findings)),
	}, nil
}

// readFindings locates the single run under <dir>/strix_runs/ and parses its
// vulnerabilities.json. A clean run with no findings may leave no
// vulnerabilities.json — that is success with zero findings, not an error.
func readFindings(dir string) ([]Finding, string, error) {
	runsRoot := filepath.Join(dir, "strix_runs")
	entries, err := os.ReadDir(runsRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, "", nil // scan completed but wrote no runs dir
		}
		return nil, "", fmt.Errorf("strix live: read %s: %w", runsRoot, err)
	}
	var findings []Finding
	var runDir string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		path := filepath.Join(runsRoot, e.Name(), "vulnerabilities.json")
		raw, err := os.ReadFile(path)
		if err != nil {
			continue // run without findings
		}
		var reports []Finding
		if err := json.Unmarshal(raw, &reports); err != nil {
			return nil, "", fmt.Errorf("strix live: parse %s: %w", path, err)
		}
		findings = append(findings, reports...)
		runDir = filepath.Join(runsRoot, e.Name())
	}
	return findings, runDir, nil
}

var unsafeChars = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

// sanitize makes a string safe for a single path segment.
func sanitize(s string) string {
	s = unsafeChars.ReplaceAllString(s, "_")
	if len(s) > 64 {
		s = s[:64]
	}
	if s == "" {
		return "scan"
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
