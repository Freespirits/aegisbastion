// Package ave is the Active Validation Engine (doc 04 §6, D4) — the runtime,
// non-destructive re-verification of every candidate finding against the live
// target that makes "zero false positives" real: a finding is only reportable
// as CONFIRMED when a validator reproduced it with captured evidence.
//
// Validators are versioned, non-destructive plugins behind a common
// interface. Every network action goes through the injected scoped HTTP
// client (per-request scope guard + egress proxy — doc 04 §10.1 layers 3–4).
package ave

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"
)

// Verdict is the validation outcome (doc 04 §4.3).
type Verdict string

// Verdicts (doc 04 §4.3/§6).
const (
	// VerdictConfirmed — reproduced at runtime, evidence attached.
	VerdictConfirmed = "CONFIRMED"
	// VerdictNotReproducible — could not be reproduced (finding becomes
	// false_positive; still logged with evidence for template-quality feedback).
	VerdictNotReproducible = "NOT_REPRODUCIBLE"
	// VerdictInconclusive — target behavior ambiguous.
	VerdictInconclusive = "INCONCLUSIVE"
	// VerdictNotValidatable — no validator for this class (published only at
	// reduced confidence, severity capped at medium until a validator exists).
	VerdictNotValidatable = "NOT_VALIDATABLE"
)

// Version is the AVE build recorded on Validation.validator_version.
const Version = "ave-0.1.0"

// Candidate is one scanner-reported candidate finding to validate.
type Candidate struct {
	Target    string // job target (base)
	MatchedAt string // concrete match (URL / host:port)
	CheckID   string
	VulnClass string
	Title     string
	CVE       string
	Severity  string
	// Evidence carries scanner-reported detail — the matched parameter,
	// request/response snippets, banner strings — validators use it to aim
	// their re-verification probes.
	Evidence map[string]any
}

// Exchange is one sanitized request/response pair in an evidence transcript.
type Exchange struct {
	Label    string `json:"label"` // e.g. "banner", "probe_true", "probe_false"
	Method   string `json:"method"`
	URL      string `json:"url"`
	Status   int    `json:"status"`
	Request  string `json:"request,omitempty"`  // sanitized header block (+ body for GET-ish)
	Response string `json:"response,omitempty"` // sanitized, truncated
	Duration string `json:"duration,omitempty"`
}

// Transcript is the validation evidence (doc 04 §6 evidence contract: every
// CONFIRMED/NOT_REPRODUCIBLE verdict stores one; canary tokens prove the
// interaction was ours).
type Transcript struct {
	Canary    string     `json:"canary,omitempty"`
	Exchanges []Exchange `json:"exchanges"`
	Notes     []string   `json:"notes,omitempty"`
}

// Result is one validator outcome.
type Result struct {
	Verdict    Verdict
	Method     string // "ave.*"
	Confidence float64
	Transcript *Transcript
	Detail     string
}

// OOBInteraction is one recorded callback at the OOB service (doc 04 D7).
type OOBInteraction struct {
	Token     string    `json:"token"`
	At        time.Time `json:"at"`
	Remote    string    `json:"remote"`
	Method    string    `json:"method"`
	Path      string    `json:"path"`
	UserAgent string    `json:"user_agent,omitempty"`
}

// OOBClient is the AVE/EVS view of the OOB interaction service.
type OOBClient interface {
	// NewCanary mints a unique canary (token, callback URL) bound to a
	// purpose string (e.g. the candidate's finding id).
	NewCanary(ctx context.Context, purpose string) (token, url string, err error)
	// Interactions returns recorded callbacks for a canary token.
	Interactions(ctx context.Context, token string) ([]OOBInteraction, error)
}

// TLSProfile is what the independent TLS re-handshake learned.
type TLSProfile struct {
	MinVersionOffered uint16   // lowest protocol version the server accepted
	CipherSuites      []uint16 // accepted cipher suites at that version
	ServerName        string
}

// TLSProber re-handshakes independently of the scanner (ave.tls).
type TLSProber interface {
	// ProbeVersions attempts handshakes at decreasing protocol versions and
	// reports what the server accepted. Non-destructive (handshake only).
	ProbeVersions(ctx context.Context, hostPort string) (*TLSProfile, error)
}

// Tools bundles the scoped network surface validators use.
type Tools struct {
	// HTTP is the scoped client: per-request scope guard + egress proxy +
	// rate limiting are already wired into its transport.
	HTTP *http.Client
	// OOB is the canary callback service (nil → OOB-dependent validators
	// report NOT_VALIDATABLE, doc 04 §12 "OOB service down").
	OOB OOBClient
	// TLS probes handshakes (nil → tls validator uses the default prober).
	TLS TLSProber
	// Now is the clock (tests).
	Now func() time.Time
}

func (t *Tools) now() time.Time {
	if t != nil && t.Now != nil {
		return t.Now()
	}
	return time.Now().UTC()
}

// Validator re-proves one vulnerability class non-destructively.
type Validator interface {
	// Name is the method string recorded on Validation.method ("ave.xss").
	Name() string
	// Classes lists the vuln classes it handles.
	Classes() []string
	// Validate re-verifies cand against the live target. It must be
	// non-destructive (doc 04 §6) and must honor ctx cancellation.
	Validate(ctx context.Context, cand Candidate, tools *Tools) (*Result, error)
}

// Engine routes candidates to validators (doc 04 D4).
type Engine struct {
	byClass map[string]Validator
}

// NewEngine builds an Engine from the MVP validator set.
func NewEngine(validators ...Validator) *Engine {
	e := &Engine{byClass: map[string]Validator{}}
	for _, v := range validators {
		for _, c := range v.Classes() {
			e.byClass[c] = v
		}
	}
	return e
}

// Classes lists the classes with a registered validator (sorted).
func (e *Engine) Classes() []string {
	out := make([]string, 0, len(e.byClass))
	for c := range e.byClass {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// Validate runs the class validator; no validator → NOT_VALIDATABLE
// (doc 04 §6: published only at reduced confidence, severity capped).
func (e *Engine) Validate(ctx context.Context, cand Candidate, tools *Tools) (*Result, error) {
	v, ok := e.byClass[cand.VulnClass]
	if !ok {
		return &Result{
			Verdict:    VerdictNotValidatable,
			Method:     "ave.none",
			Confidence: 0.3,
			Transcript: &Transcript{Notes: []string{"no validator registered for class " + cand.VulnClass}},
			Detail:     "no validator for vuln class " + cand.VulnClass,
		}, nil
	}
	res, err := v.Validate(ctx, cand, tools)
	if err != nil {
		return nil, fmt.Errorf("ave: %s: %w", v.Name(), err)
	}
	if res == nil {
		return nil, fmt.Errorf("ave: %s returned nil result", v.Name())
	}
	if res.Method == "" {
		res.Method = v.Name()
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------------

// errTargetUnreachable marks repeated transport errors (doc 04 §5.2: a target
// returning repeated transport errors is UNREACHABLE for this task, not
// retried into a DoS).
var errTargetUnreachable = errors.New("ave: target unreachable")

// evidenceString reads a string from scanner Evidence.
func evidenceString(ev map[string]any, keys ...string) string {
	for _, k := range keys {
		if v, ok := ev[k]; ok {
			switch s := v.(type) {
			case string:
				if s != "" {
					return s
				}
			case fmt.Stringer:
				if s.String() != "" {
					return s.String()
				}
			}
		}
	}
	return ""
}

// truncate bounds transcript bodies (evidence stays compact; payloads larger
// than this ride to object storage anyway — the transcript is the proof).
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…[truncated]"
}
