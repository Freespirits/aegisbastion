package evs

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
)

// Program is a pack's deterministic verifier script (doc 04 §7.1): an
// ordered list of HTTP/OOB steps plus the confirmation conditions. The proof
// standard: the exploit succeeds only if a canary planted by the verifier is
// observed (echo token in output, OOB callback, temp artifact
// present-then-removed) — never real data access (doc 04 §10.5).
type Program struct {
	Steps   []Step      `json:"steps"`
	Confirm []Condition `json:"confirm"`
}

// Step is one verifier action. Exactly one of HTTP / OOB / SleepMS applies.
type Step struct {
	Name    string    `json:"name"`
	HTTP    *HTTPStep `json:"http,omitempty"`
	OOB     *OOBStep  `json:"oob,omitempty"`
	SleepMS int       `json:"sleep_ms,omitempty"`
}

// HTTPStep fires one request through the scope-enforcing proxy. URL/Body/
// Headers are templates over the run environment ({{target}},
// {{matched_at}}, {{canary_url}}, {{canary_token}}, {{echo_token}},
// {{evidence.<key>}}).
type HTTPStep struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Body    string            `json:"body,omitempty"`
}

// OOBStep waits for canary callbacks at the OOB collector (blind proofs).
type OOBStep struct {
	MinInteractions int `json:"min_interactions"`
	TimeoutMS       int `json:"timeout_ms"`
}

// Condition is one confirmation predicate over a saved step response.
type Condition struct {
	// Var is "<step>.body" or "<step>.status".
	Var string `json:"var"`
	// Contains / NotContains are substring checks (templated).
	Contains    string `json:"contains,omitempty"`
	NotContains string `json:"not_contains,omitempty"`
	// StatusEquals compares the integer status.
	StatusEquals int `json:"status_equals,omitempty"`
}

// ProgramEnv is the sandbox's view of the world: the target, the planted
// canaries, the proxy-forced HTTP client, and the OOB lookup API. Nothing
// else — the program cannot reach the network except through HTTP (proxy)
// and cannot see the platform.
type ProgramEnv struct {
	Target      string
	MatchedAt   string
	CanaryURL   string
	CanaryToken string
	EchoToken   string
	Evidence    map[string]any
	HTTP        *http.Client
	OOB         ave.OOBClient
	Now         func() time.Time
}

// StepRecord is one executed step in the transcript.
type StepRecord struct {
	Name     string `json:"name"`
	Kind     string `json:"kind"`
	Detail   string `json:"detail,omitempty"`
	Status   int    `json:"status,omitempty"`
	Duration string `json:"duration,omitempty"`
	OK       bool   `json:"ok"`
}

// Outcome is the verifier result.
type Outcome struct {
	Confirmed  bool         `json:"confirmed"`
	Proof      string       `json:"proof"`
	Transcript []StepRecord `json:"transcript"`
}

// Render renders the outcome as the evidence-bundle transcript bytes.
func (o *Outcome) Render() []byte {
	b, err := json.MarshalIndent(o, "", "  ")
	if err != nil {
		return []byte(`{"error":"transcript marshal failed"}`)
	}
	return b
}

// NewEchoToken mints a fresh per-run echo canary.
func NewEchoToken() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return "s48echo" + hex.EncodeToString(b)
}

// RunProgram executes a pack program inside the given environment. It never
// fails open: any step error aborts the run with Confirmed=false.
func RunProgram(ctx context.Context, prog Program, env *ProgramEnv) (*Outcome, error) {
	if env.HTTP == nil {
		return nil, fmt.Errorf("evs: program env has no HTTP client (proxy required)")
	}
	out := &Outcome{}
	vars := map[string]*httpObservation{}
	for _, step := range prog.Steps {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		rec := StepRecord{Name: step.Name, OK: true}
		switch {
		case step.HTTP != nil:
			obs, err := runHTTPStep(ctx, step, env, &rec)
			if err != nil {
				rec.OK = false
				rec.Detail = err.Error()
				out.Transcript = append(out.Transcript, rec)
				out.Proof = "step " + step.Name + " failed: " + err.Error()
				return out, nil
			}
			vars[step.Name] = obs
		case step.OOB != nil:
			ok, detail := runOOBStep(ctx, step, env)
			rec.Kind = "oob"
			rec.Detail = detail
			rec.OK = ok
			if !ok {
				out.Transcript = append(out.Transcript, rec)
				out.Proof = "step " + step.Name + ": " + detail
				return out, nil
			}
		case step.SleepMS > 0:
			rec.Kind = "sleep"
			select {
			case <-ctx.Done():
				return out, ctx.Err()
			case <-time.After(time.Duration(step.SleepMS) * time.Millisecond):
			}
		default:
			rec.Kind = "noop"
		}
		out.Transcript = append(out.Transcript, rec)
	}

	// Confirmation: every condition must hold.
	if len(prog.Confirm) == 0 {
		out.Proof = "pack defines no confirmation conditions"
		return out, nil
	}
	for _, c := range prog.Confirm {
		ok, why := evalCondition(c, vars, env)
		if !ok {
			out.Proof = "confirmation failed: " + why
			return out, nil
		}
	}
	out.Confirmed = true
	out.Proof = "canary observed: all confirmation conditions held"
	return out, nil
}

type httpObservation struct {
	status int
	body   string
}

func runHTTPStep(ctx context.Context, step Step, env *ProgramEnv, rec *StepRecord) (*httpObservation, error) {
	rec.Kind = "http"
	h := step.HTTP
	method := h.Method
	if method == "" {
		method = http.MethodGet
	}
	url := renderTemplate(h.URL, env)
	body := renderTemplate(h.Body, env)
	req, err := http.NewRequestWithContext(ctx, method, url, strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for k, v := range h.Headers {
		req.Header.Set(k, renderTemplate(v, env))
	}
	start := time.Now()
	resp, err := env.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request %s %s: %w", method, url, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	rec.Status = resp.StatusCode
	rec.Duration = time.Since(start).Round(time.Millisecond).String()
	rec.Detail = method + " " + url
	return &httpObservation{status: resp.StatusCode, body: string(respBody)}, nil
}

func runOOBStep(ctx context.Context, step Step, env *ProgramEnv) (bool, string) {
	if env.OOB == nil || env.CanaryToken == "" {
		return false, "OOB collector unavailable"
	}
	want := step.OOB.MinInteractions
	if want <= 0 {
		want = 1
	}
	timeout := time.Duration(step.OOB.TimeoutMS) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		hits, err := env.OOB.Interactions(ctx, env.CanaryToken)
		if err == nil && len(hits) >= want {
			return true, fmt.Sprintf("observed %d OOB interaction(s) for canary", len(hits))
		}
		if time.Now().After(deadline) {
			return false, fmt.Sprintf("no OOB interaction within %s", timeout)
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err().Error()
		case <-time.After(250 * time.Millisecond):
		}
	}
}

func evalCondition(c Condition, vars map[string]*httpObservation, env *ProgramEnv) (bool, string) {
	step, field, found := strings.Cut(c.Var, ".")
	if !found {
		return false, "condition var must be <step>.<field>, got " + c.Var
	}
	obs, ok := vars[step]
	if !ok {
		return false, "condition references unknown step " + step
	}
	switch field {
	case "status":
		if c.StatusEquals != 0 && obs.status != c.StatusEquals {
			return false, fmt.Sprintf("%s status %d != %d", c.Var, obs.status, c.StatusEquals)
		}
		return true, ""
	case "body":
		if c.Contains != "" && !strings.Contains(obs.body, renderTemplate(c.Contains, env)) {
			return false, fmt.Sprintf("%s does not contain canary %q", c.Var, renderTemplate(c.Contains, env))
		}
		if c.NotContains != "" && strings.Contains(obs.body, renderTemplate(c.NotContains, env)) {
			return false, fmt.Sprintf("%s unexpectedly contains %q", c.Var, renderTemplate(c.NotContains, env))
		}
		return true, ""
	default:
		return false, "unsupported condition field " + field
	}
}

// renderTemplate interpolates the run environment into a pack template.
func renderTemplate(s string, env *ProgramEnv) string {
	if s == "" {
		return ""
	}
	r := strings.NewReplacer(
		"{{target}}", env.Target,
		"{{matched_at}}", env.MatchedAt,
		"{{canary_url}}", env.CanaryURL,
		"{{canary_token}}", env.CanaryToken,
		"{{echo_token}}", env.EchoToken,
	)
	out := r.Replace(s)
	// {{evidence.<key>}} values from the scanner-reported evidence map.
	for {
		i := strings.Index(out, "{{evidence.")
		if i < 0 {
			break
		}
		j := strings.Index(out[i:], "}}")
		if j < 0 {
			break
		}
		key := out[i+len("{{evidence.") : i+j]
		val := ""
		if env.Evidence != nil {
			if v, ok := env.Evidence[key]; ok {
				val = fmt.Sprint(v)
			}
		}
		out = out[:i] + val + out[i+j+2:]
	}
	return out
}
