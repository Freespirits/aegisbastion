package evs

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
)

// Engine is the EVS orchestrator (doc 04 §7.1, D5): it decides which
// candidates need sandbox verification, runs curated signed packs through
// the runner, and produces AVE-compatible verdicts plus the evidence bundle
// (full session transcript + verdict manifest).
//
// Trigger (doc 04 §7.1): severity ≥ HIGH with INCONCLUSIVE/NOT_VALIDATABLE
// from the AVE, or params.exploit_verify == true. The sandbox pool is
// semaphore-capped with deadline-aware drop — a skipped verification leaves
// the verdict INCONCLUSIVE and never blocks result delivery (doc 04 §11).
type Engine struct {
	runner  Runner
	oob     ave.OOBClient
	packs   []*Pack
	oobBase string

	sem     chan struct{}
	timeout time.Duration
	log     *slog.Logger
}

// EngineConfig wires an Engine.
type EngineConfig struct {
	Runner Runner
	// OOB is the in-process canary client (minting); OOBBaseURL is the lookup
	// API the sandbox child uses.
	OOB        ave.OOBClient
	OOBBaseURL string
	// Packs are the verified, curated PoC packs (signature-checked at load).
	Packs []*Pack
	// MaxConcurrent caps parallel verifications (doc 04 §11: default 8).
	MaxConcurrent int
	// Timeout is the hard cap per verification (doc 04 §7.1: 10 min).
	Timeout time.Duration
	Log     *slog.Logger
}

// NewEngine builds the EVS engine.
func NewEngine(cfg EngineConfig) *Engine {
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	max := cfg.MaxConcurrent
	if max <= 0 {
		max = 8
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Minute
	}
	return &Engine{
		runner:  cfg.Runner,
		oob:     cfg.OOB,
		packs:   cfg.Packs,
		oobBase: cfg.OOBBaseURL,
		sem:     make(chan struct{}, max),
		timeout: cfg.Timeout,
		log:     cfg.Log,
	}
}

// ShouldVerify implements the doc 04 §7.1 trigger.
func ShouldVerify(severity string, verdict ave.Verdict, exploitVerify bool) bool {
	if exploitVerify {
		return true
	}
	sev := strings.ToLower(strings.TrimSpace(severity))
	if sev != "high" && sev != "critical" {
		return false
	}
	return verdict == ave.VerdictInconclusive || verdict == ave.VerdictNotValidatable
}

// HasPack reports whether a curated pack covers a vuln class.
func (e *Engine) HasPack(class string) bool { return ForClass(e.packs, class) != nil }

// Verify runs the sandbox verification for one candidate. It returns an
// AVE-compatible result ("evs.poc" method) and the evidence bundle bytes
// (transcript + verdict manifest). A nil result with nil error means
// "verification skipped" (no pack / pool exhausted) — the caller keeps the
// AVE verdict (never blocks delivery, doc 04 §11).
func (e *Engine) Verify(ctx context.Context, cand ave.Candidate, proxyURL string, safeMode bool) (*ave.Result, []byte, error) {
	pack := ForClass(e.packs, cand.VulnClass)
	if pack == nil {
		return nil, nil, nil // no curated pack for this class — verdict stands
	}
	if err := CheckSafety(pack, safeMode); err != nil {
		return nil, nil, err
	}

	// Deadline-aware pool admission (doc 04 §11): no slot → skip, verdict
	// stays INCONCLUSIVE, delivery is never blocked.
	select {
	case e.sem <- struct{}{}:
		defer func() { <-e.sem }()
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	default:
		e.log.Warn("evs: sandbox pool exhausted — skipping verification", "check", cand.CheckID)
		return nil, nil, nil
	}

	env := EnvSpec{
		Target:     cand.Target,
		MatchedAt:  cand.MatchedAt,
		Evidence:   cand.Evidence,
		ProxyURL:   proxyURL,
		OOBBaseURL: e.oobBase,
		EchoToken:  NewEchoToken(),
	}
	if pack.RequiresOOB {
		if e.oob == nil {
			return &ave.Result{
				Verdict: ave.VerdictNotValidatable, Method: "evs.poc",
				Confidence: 0.3, Detail: "OOB service down — pack requires canary callbacks",
			}, nil, nil
		}
		token, url, err := e.oob.NewCanary(ctx, "evs:"+pack.ID+":"+cand.CheckID)
		if err != nil {
			return nil, nil, fmt.Errorf("evs: mint canary: %w", err)
		}
		env.CanaryToken, env.CanaryURL = token, url
	}

	vctx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	res, err := e.runner.Run(vctx, RunRequest{
		JobID:     "evs-" + cand.CheckID,
		Pack:      pack,
		Env:       env,
		TimeoutMS: int(e.timeout / time.Millisecond),
	})
	if err != nil {
		if ctx.Err() != nil {
			// Kill/timeout mid-proof: halt, partial evidence preserved
			// (doc 04 §10.3).
			if res != nil && res.Outcome != nil {
				return &ave.Result{
					Verdict: ave.VerdictInconclusive, Method: "evs.poc",
					Confidence: 0.4,
					Detail:     "sandbox halted mid-proof: " + err.Error(),
				}, res.Outcome.Render(), ctx.Err()
			}
			return nil, nil, ctx.Err()
		}
		return nil, nil, fmt.Errorf("evs: runner: %w", err)
	}
	if res.Outcome == nil {
		return nil, nil, fmt.Errorf("evs: runner returned no outcome")
	}

	bundle := res.Outcome.Render()
	if res.Outcome.Confirmed {
		return &ave.Result{
			Verdict:    ave.VerdictConfirmed,
			Method:     "evs.poc",
			Confidence: 0.99,
			Transcript: &ave.Transcript{Canary: firstNonEmpty(env.CanaryToken, env.EchoToken)},
			Detail:     fmt.Sprintf("PoC pack %s:%s reproduced via %s sandbox: %s", pack.ID, pack.Version, res.Runner, res.Outcome.Proof),
		}, bundle, nil
	}
	// A clean negative from a deterministic pack: the exploit did NOT
	// reproduce under sandbox conditions.
	return &ave.Result{
		Verdict:    ave.VerdictNotReproducible,
		Method:     "evs.poc",
		Confidence: 0.8,
		Transcript: &ave.Transcript{Canary: firstNonEmpty(env.CanaryToken, env.EchoToken)},
		Detail:     fmt.Sprintf("PoC pack %s:%s could not reproduce: %s", pack.ID, pack.Version, res.Outcome.Proof),
	}, bundle, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
