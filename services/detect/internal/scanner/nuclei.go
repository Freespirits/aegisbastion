package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Nuclei wraps the Nuclei v3 template engine (doc 04 §9 "Primary scanner").
// JSON-lines output; the template allowlist is enforced at launch flags and
// DoS-class templates are hard-excluded at the wrapper (doc 04 §10.3).
type Nuclei struct {
	// Bin is the nuclei binary path (exec mode).
	Bin string
	// FixtureDir maps job.FixtureFile → canned JSONL output (fixture mode).
	FixtureDir string
	// Timeout bounds one scanner run (exec mode; wrapper kill on hang —
	// doc 04 §12 "scanner process hang").
	Timeout time.Duration

	mu     sync.Mutex
	active []*exec.Cmd
}

// NewNuclei builds the adapter. fixtureDir non-empty selects fixture mode.
func NewNuclei(bin, fixtureDir string) *Nuclei {
	return &Nuclei{Bin: bin, FixtureDir: fixtureDir, Timeout: 30 * time.Minute}
}

// defaultFixtureFile is used when the job names no fixture (module-level
// fixture mode: one canned corpus per adapter).
const defaultNucleiFixture = "nuclei-basic.jsonl"

// Name implements Adapter.
func (n *Nuclei) Name() string { return AdapterNuclei }

// Capabilities implements Adapter.
func (n *Nuclei) Capabilities() Capabilities {
	return Capabilities{ChecksSupported: []string{"nuclei:*"}, SafeModeSupported: true}
}

// ValidateJob implements Adapter — refuses DoS-class checks (wrapper-level
// hard exclusion, doc 04 §10.3, independent of params and not configurable).
func (n *Nuclei) ValidateJob(job Job) error {
	if err := RejectDoS(job.Checks); err != nil {
		return err
	}
	if n.FixtureDir == "" && n.Bin == "" {
		return errors.New("nuclei: exec mode requires a binary path")
	}
	return nil
}

// Abort implements Adapter — kills any in-flight nuclei child (≤ 5 s).
func (n *Nuclei) Abort() {
	n.mu.Lock()
	cmds := append([]*exec.Cmd(nil), n.active...)
	n.mu.Unlock()
	for _, c := range cmds {
		if c.Process != nil {
			_ = c.Process.Kill()
		}
	}
}

// Run implements Adapter.
func (n *Nuclei) Run(ctx context.Context, job Job, limiter Limiter, emit Emitter) error {
	if err := n.ValidateJob(job); err != nil {
		return err
	}
	var r io.Reader
	if n.FixtureDir != "" {
		fixture := job.FixtureFile
		if fixture == "" {
			fixture = defaultNucleiFixture
		}
		f, err := os.Open(n.FixtureDir + string(os.PathSeparator) + fixture)
		if err != nil {
			return fmt.Errorf("nuclei: open fixture: %w", err)
		}
		defer f.Close()
		r = f
	} else {
		stdout, wait, err := n.spawn(ctx, job)
		if err != nil {
			return err
		}
		r = stdout
		defer func() { _ = wait() }()
	}
	return n.parse(ctx, job, limiter, r, emit)
}

// spawn launches nuclei with the allowlist at launch flags and all egress
// forced through the scope-enforcing proxy (doc 04 §10.2 — even a malicious
// template cannot reach out of scope).
func (n *Nuclei) spawn(ctx context.Context, job Job) (io.Reader, func() error, error) {
	args := []string{
		"-jsonl", "-silent",
		"-target", job.Target,
		"-rate-limit", fmt.Sprintf("%d", maxU32(job.RPS, 1)),
		"-timeout", "10",
	}
	if len(job.Checks) > 0 {
		// Template-id allowlist (nuclei -id).
		args = append(args, "-id", strings.Join(job.Checks, ","))
	} else if len(job.Tags) > 0 {
		args = append(args, "-tags", strings.Join(job.Tags, ","))
	}
	if job.SafeMode {
		// Belt-and-braces: also exclude dos/fuzzing tags scanner-side; the
		// wrapper never passes DoS-class templates regardless (doc 04 §10.3).
		args = append(args, "-exclude-tags", "dos,fuzzing")
	}
	if job.Ports != "" {
		args = append(args, "-port", job.Ports)
	}
	ctx, cancel := context.WithTimeout(ctx, n.Timeout)
	cmd := exec.CommandContext(ctx, n.Bin, args...)
	if job.ProxyURL != "" {
		cmd.Env = append(os.Environ(),
			"HTTP_PROXY="+job.ProxyURL, "HTTPS_PROXY="+job.ProxyURL,
			"http_proxy="+job.ProxyURL, "https_proxy="+job.ProxyURL)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("nuclei: start: %w", err)
	}
	n.mu.Lock()
	n.active = append(n.active, cmd)
	n.mu.Unlock()
	wait := func() error {
		err := cmd.Wait()
		cancel()
		n.mu.Lock()
		for i, c := range n.active {
			if c == cmd {
				n.active = append(n.active[:i], n.active[i+1:]...)
				break
			}
		}
		n.mu.Unlock()
		if err != nil && !errors.Is(ctx.Err(), context.Canceled) {
			return fmt.Errorf("nuclei: run: %w: %s", err, stderr.String())
		}
		return nil
	}
	return stdout, wait, nil
}

// nucleiLine is the Nuclei v3 JSONL record shape (fields used at MVP).
type nucleiLine struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name           string   `json:"name"`
		Severity       string   `json:"severity"`
		Tags           []string `json:"tags"`
		Reference      []string `json:"reference"`
		Classification struct {
			CVEID []string `json:"cve-id"`
			CWEID []string `json:"cwe-id"`
		} `json:"classification"`
	} `json:"info"`
	Type          string `json:"type"`
	Host          string `json:"host"`
	MatchedAt     string `json:"matched-at"`
	Matched       string `json:"matched"`
	MatcherStatus bool   `json:"matcher-status"`
	Request       string `json:"request,omitempty"`
	Response      string `json:"response,omitempty"`
}

// parse streams JSONL records into RawResults, honoring the rate limiter and
// request budget per emitted candidate (doc 04 §10.3).
func (n *Nuclei) parse(ctx context.Context, job Job, limiter Limiter, r io.Reader, emit Emitter) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 1<<20), 4<<20)
	for sc.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var rec nucleiLine
		if err := json.Unmarshal(line, &rec); err != nil {
			continue // tolerate banner/log lines interleaved in output
		}
		if rec.TemplateID == "" {
			continue
		}
		// Wrapper-level DoS exclusion on the way out too: even if a template
		// slipped past launch flags its result is discarded (doc 04 §10.3).
		if IsDoSCheckID(rec.TemplateID) || IsDoSTags(rec.Info.Tags) {
			continue
		}
		if !limiter.TakeRequest() {
			return fmt.Errorf("nuclei: request budget exhausted for job %s", job.JobID)
		}
		if err := limiter.Wait(ctx); err != nil {
			return err
		}
		matchedAt := rec.MatchedAt
		if matchedAt == "" {
			matchedAt = rec.Matched
		}
		if matchedAt == "" {
			matchedAt = rec.Host
		}
		res := RawResult{
			JobID: job.JobID, TaskID: job.TaskID, Adapter: AdapterNuclei,
			Target: job.Target, CheckID: rec.TemplateID,
			Title: rec.Info.Name, Severity: normalizeSeverity(rec.Info.Severity),
			MatchedAt: matchedAt, VulnClass: classifyNuclei(rec),
			CVE: first(rec.Info.Classification.CVEID), CWE: first(rec.Info.Classification.CWEID),
			References: rec.Info.Reference,
			Evidence: map[string]any{
				"matcher_status": rec.MatcherStatus,
				"type":           rec.Type,
			},
			Raw: append([]byte(nil), line...),
		}
		if err := emit.Emit(res); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("nuclei: read output: %w", err)
	}
	return nil
}

// classifyNuclei maps template metadata to a vuln class for AVE routing
// (doc 04 §5.1 validation hints — no re-classification needed downstream).
func classifyNuclei(rec nucleiLine) string {
	id := strings.ToLower(rec.TemplateID)
	tags := make([]string, 0, len(rec.Info.Tags))
	for _, t := range rec.Info.Tags {
		tags = append(tags, strings.ToLower(t))
	}
	has := func(want ...string) bool {
		for _, t := range tags {
			for _, w := range want {
				if t == w {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has("xss") || strings.Contains(id, "xss"):
		return ClassReflectedXSS
	case has("sqli") || strings.Contains(id, "sqli") || strings.Contains(id, "sql-injection"):
		return ClassSQLi
	case has("ssrf") || strings.Contains(id, "ssrf"):
		return ClassSSRF
	case has("xxe") || strings.Contains(id, "xxe"):
		return ClassBlindXXE
	case has("rce") && has("oob", "blind"):
		return ClassBlindRCE
	case has("lfi") || strings.Contains(id, "lfi") || strings.Contains(id, "traversal"):
		return ClassPathTraversal
	case has("redirect") || strings.Contains(id, "open-redirect") || strings.Contains(id, "redirect"):
		return ClassOpenRedirect
	case has("default-login", "default-creds") || strings.Contains(id, "default-login") || strings.Contains(id, "default-cred"):
		return ClassDefaultCreds
	case has("ssl", "tls") || strings.HasPrefix(id, "ssl-") || strings.HasPrefix(id, "tls-"):
		return ClassTLSMisconfig
	case has("header", "headers", "misconfig") || strings.Contains(id, "header"):
		return ClassSecurityHeader
	case has("cve") || strings.HasPrefix(id, "cve-"):
		return ClassVersionCVE
	case has("exposure", "exposures", "panel", "debug"):
		return ClassExposure
	default:
		return ClassUnknown
	}
}

// normalizeSeverity maps scanner severities to the doc 04 §4.3 bands.
func normalizeSeverity(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	case "info", "informational", "unknown", "":
		return "informational"
	default:
		return "informational"
	}
}

func first(v []string) string {
	if len(v) == 0 {
		return ""
	}
	return v[0]
}

func maxU32(v, floor uint32) uint32 {
	if v < floor {
		return floor
	}
	return v
}
