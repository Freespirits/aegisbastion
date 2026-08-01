// Package scanner is the Detect scanner-adapter layer (doc 04 §5.3, D3): a
// uniform wrapper around third-party scanners (Nuclei, Nmap/NSE at MVP).
//
// Two execution modes (config.ScannerMode):
//
//   - fixture (default): adapters parse canned scanner output from fixture
//     files — deterministic, no target contact; used by tests and local dev.
//   - exec: adapters spawn the real scanner binaries (paths via config) with
//     all target-bound egress forced through the scope-enforcing egress proxy
//     (doc 04 §10.2) and the check allowlist enforced at launch flags.
//
// Hard safety invariants (doc 04 §10.3 — cannot be disabled by configuration):
//
//   - DoS-class checks/templates are excluded at the wrapper, independent of
//     params (Nuclei `dos` tag / dos-* ids, NSE `dos`/`intrusive` categories).
//   - safe_mode (default true) drops state-changing check classes unless the
//     RoE params explicitly permit them.
package scanner

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Adapter names (FindingReport vulnerability.source, doc 04 §4.3).
const (
	AdapterNuclei = "nuclei"
	AdapterNmap   = "nmap"
)

// Vuln classes route candidates to AVE validators (doc 04 §6).
const (
	ClassVersionCVE     = "version_cve"
	ClassReflectedXSS   = "reflected_xss"
	ClassSQLi           = "sqli"
	ClassSSRF           = "ssrf"
	ClassBlindXXE       = "blind_xxe"
	ClassBlindRCE       = "blind_rce"
	ClassPathTraversal  = "path_traversal"
	ClassOpenRedirect   = "open_redirect"
	ClassDefaultCreds   = "default_creds"
	ClassTLSMisconfig   = "tls_misconfig"
	ClassSecurityHeader = "security_header"
	ClassExposure       = "exposure" // no MVP validator — NOT_VALIDATABLE
	ClassUnknown        = "unknown"
)

// RawResult is one scanner-reported candidate finding, pre-normalization.
// Raw keeps the verbatim scanner record: the NormalizedFinding is an
// interpretation; the raw bytes are the proof (doc 04 §5.3).
type RawResult struct {
	JobID      string   `json:"job_id"`
	TaskID     string   `json:"task_id"`
	Adapter    string   `json:"adapter"`
	Target     string   `json:"target"`
	CheckID    string   `json:"check_id"` // template/script id, e.g. "cve-2024-3400"
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`   // informational|low|medium|high|critical
	MatchedAt  string   `json:"matched_at"` // concrete URL/host:port that matched
	VulnClass  string   `json:"vuln_class"`
	CVE        string   `json:"cve,omitempty"`
	CWE        string   `json:"cwe,omitempty"`
	References []string `json:"references,omitempty"`
	// Evidence carries scanner-reported detail (request/response snippets,
	// matched versions, script output) — sanitized before evidence upload.
	Evidence map[string]any `json:"evidence,omitempty"`
	// Raw is the verbatim scanner output record (JSONL line / NSE XML node).
	Raw []byte `json:"raw,omitempty"`
}

// Job is one scanner sub-job (doc 04 §5.2 ScanJob). The Token is the
// narrowed, job-scoped gatekeeper Scope Token obtained via token exchange
// (Ruling C9) — the Coordinator never mints it.
type Job struct {
	JobID         string    `json:"job_id"`
	TaskID        string    `json:"task_id"`
	Target        string    `json:"target"`
	Adapter       string    `json:"adapter"`
	Checks        []string  `json:"checks"`         // explicit allowlist (empty = Tags)
	Tags          []string  `json:"tags,omitempty"` // template-family selection (nuclei -tags)
	Profile       string    `json:"profile"`
	Ports         string    `json:"ports,omitempty"`
	RPS           uint32    `json:"rps"`
	RequestBudget uint32    `json:"request_budget"`
	Deadline      time.Time `json:"deadline"`
	Token         string    `json:"token"`
	SafeMode      bool      `json:"safe_mode"`
	ProxyURL      string    `json:"proxy_url,omitempty"` // egress proxy (exec mode)
	Capability    string    `json:"capability"`
	FixtureFile   string    `json:"fixture_file,omitempty"` // fixture mode only
}

// Emitter streams RawResults and progress out of a running job.
type Emitter interface {
	Emit(RawResult) error
}

// EmitterFunc adapts a function to Emitter.
type EmitterFunc func(RawResult) error

// Emit implements Emitter.
func (f EmitterFunc) Emit(r RawResult) error { return f(r) }

// Capabilities describes what an adapter supports (doc 04 §5.3).
type Capabilities struct {
	ChecksSupported   []string
	SafeModeSupported bool
}

// Adapter is the uniform scanner wrapper interface (doc 04 §5.3).
type Adapter interface {
	// Name is the adapter key ("nuclei", "nmap").
	Name() string
	// ValidateJob rejects jobs this adapter cannot/should not run —
	// including any job whose check list still contains a DoS-class check
	// (wrapper refusal, doc 04 §10.3).
	ValidateJob(Job) error
	// Run executes the job, streaming RawResults. It respects the injected
	// rate limiter, the request budget, and ctx cancellation (≤ 5 s stop).
	Run(ctx context.Context, job Job, limiter Limiter, emit Emitter) error
	// Abort kills any in-flight scanner child process (≤ 5 s, doc 04 §10.3).
	Abort()
	// Capabilities reports supported checks and safe-mode handling.
	Capabilities() Capabilities
}

// Limiter is the per-job rate/budget limiter injected into adapters
// (doc 04 §10.3: per-job limiter mirroring the token's rate caps).
type Limiter interface {
	// Wait blocks until one request may fire (or ctx ends).
	Wait(ctx context.Context) error
	// TakeRequest consumes one unit of the request budget; false = exhausted.
	TakeRequest() bool
}

// ErrDoSClass is returned when a DoS-class check reaches the adapter wrapper
// (planning should have filtered it; the wrapper refuses independently).
var ErrDoSClass = errors.New("scanner: DoS-class check hard-excluded (doc 04 §10.3)")

// ---------------------------------------------------------------------------
// DoS-class and safe-mode classification (shared by both adapters)
// ---------------------------------------------------------------------------

// dosIDPatterns are check-id substrings that mark DoS-class content. NSE
// categories dos/intrusive are blocked at script selection; Nuclei templates
// carry a `dos` tag (checked in the parsed metadata) or a dos-* id.
var dosIDPatterns = []string{
	"dos-", "-dos", "denial", "flood", "slowloris", "stress",
}

// IsDoSCheckID reports whether a check/template/script id is DoS-class.
// The exclusion cannot be disabled by configuration (doc 04 §10.3).
func IsDoSCheckID(id string) bool {
	s := strings.ToLower(id)
	if s == "dos" || strings.HasPrefix(s, "dos-") || strings.HasPrefix(s, "dos_") {
		return true
	}
	for _, p := range dosIDPatterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// IsDoSTags reports whether a scanner tag/category set marks DoS-class
// content (Nuclei `dos` tag; NSE `dos`/`intrusive` categories).
func IsDoSTags(tags []string) bool {
	for _, t := range tags {
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "dos", "intrusive", "exploit-dos", "denial-of-service":
			return true
		}
	}
	return false
}

// FilterChecks returns the job's check allowlist with DoS-class entries
// removed and the removed ids listed (for audit logging). DoS exclusion is
// unconditional (doc 04 §10.3); exclude_check_ids applies on top.
func FilterChecks(checks, exclude []string) (kept, dropped []string) {
	ex := map[string]bool{}
	for _, e := range exclude {
		ex[strings.ToLower(strings.TrimSpace(e))] = true
	}
	for _, c := range checks {
		lc := strings.ToLower(strings.TrimSpace(c))
		if IsDoSCheckID(lc) {
			dropped = append(dropped, c)
			continue
		}
		if ex[lc] || globExcluded(lc, exclude) {
			dropped = append(dropped, c)
			continue
		}
		kept = append(kept, c)
	}
	sort.Strings(kept)
	sort.Strings(dropped)
	return kept, dropped
}

// globExcluded honors simple trailing-* denylist entries ("dos-*").
func globExcluded(id string, exclude []string) bool {
	for _, e := range exclude {
		e = strings.ToLower(strings.TrimSpace(e))
		if strings.HasSuffix(e, "*") && strings.HasPrefix(id, strings.TrimSuffix(e, "*")) {
			return true
		}
	}
	return false
}

// RejectDoS enforces the wrapper-level DoS refusal (doc 04 §10.3): planning
// filters, but a job that still carries DoS-class content is rejected here.
func RejectDoS(checks []string) error {
	for _, c := range checks {
		if IsDoSCheckID(c) {
			return fmt.Errorf("%w: %q", ErrDoSClass, c)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

// Registry holds the adapters keyed by name (doc 04 §5.3 one process per
// adapter type; at MVP the worker pool runs them in-process).
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

// NewRegistry builds an empty registry.
func NewRegistry() *Registry { return &Registry{adapters: map[string]Adapter{}} }

// Register adds an adapter (panics on duplicate — wiring bug).
func (r *Registry) Register(a Adapter) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.adapters[a.Name()]; dup {
		panic("scanner: duplicate adapter " + a.Name())
	}
	r.adapters[a.Name()] = a
}

// Get returns the adapter for name, or nil.
func (r *Registry) Get(name string) Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.adapters[name]
}

// Names lists registered adapter names (sorted).
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.adapters))
	for n := range r.adapters {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// BudgetLimiter is the standard Limiter: token-bucket RPS plus a hard request
// budget (doc 04 §4.2 max_requests, §10.3 per-job limiter).
type BudgetLimiter struct {
	unlimited bool
	remaining int64
	mu        sync.Mutex
	wait      func(ctx context.Context) error
}

// NewBudgetLimiter builds a limiter with budget requests and a wait function
// wired to the job token's rate caps (nil wait = no RPS cap). A zero budget
// means "unlimited" (the planner always sets one in practice; tests may not).
func NewBudgetLimiter(budget uint32, wait func(ctx context.Context) error) *BudgetLimiter {
	return &BudgetLimiter{unlimited: budget == 0, remaining: int64(budget), wait: wait}
}

// Wait implements Limiter.
func (l *BudgetLimiter) Wait(ctx context.Context) error {
	if l.wait == nil {
		return nil
	}
	return l.wait(ctx)
}

// TakeRequest implements Limiter: false once the budget is exhausted.
func (l *BudgetLimiter) TakeRequest() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.unlimited {
		return true
	}
	if l.remaining <= 0 {
		return false
	}
	l.remaining--
	return true
}

// Remaining reports the unconsumed budget (meaningless when unlimited).
func (l *BudgetLimiter) Remaining() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return int(l.remaining)
}
