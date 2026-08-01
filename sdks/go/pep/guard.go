// Package pep is PEP-2 of the canonical enforcement architecture (Ruling
// B.2): the execution-time Policy Enforcement Point merged from doc 01 §9.1's
// agent-SDK guardrails and doc 11's pep-sdk — one library, two names.
//
// The Guard enforces, per intended target contact (all fail-closed):
//  1. revocation state (global / per-RoE / per-capability / per-target,
//     ≤ 5 s halt via tasks.revocations.v1),
//  2. token time validity (agents halt at exp when re-authorization fails),
//  3. per-request target authorization — exact-enumerated manifest
//     membership, or canonicalized scope evaluation with EXCLUSIONS ALWAYS
//     WIN for scope-bound watch tokens (Ruling A, doc 01 §10.1),
//  4. the token's self-contained rate caps (max_rps / max_concurrent),
//
// and emits the audit records that make the gate real: TARGET_TOUCHED per
// authorized probe (doc 03 §9.6) and SCOPE_VIOLATION when the SDK itself
// denies (doc 01 §10.5).
package pep

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/scope"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"
)

// Guardrail denial kinds — every one maps to TaskResult status
// REJECTED_UNAUTHORIZED (doc 01 §5.7).
var (
	// ErrRevoked — a matching revocation is active (halt ≤ 5 s, doc 11 §7).
	ErrRevoked = errors.New("pep: revoked")
	// ErrNoAuthorization — target contact attempted without any authorization
	// (e.g. an R0 task trying to touch a target — zero target contact is the
	// R0 contract, doc 11 §1).
	ErrNoAuthorization = errors.New("pep: no authorization token for this task")
	// ErrTargetNotInManifest — exact-enumerated form: target not listed.
	ErrTargetNotInManifest = errors.New("pep: target not in token manifest")
	// ErrTargetExcluded — scope-bound form: exclusion matched (always wins).
	ErrTargetExcluded = errors.New("pep: target excluded by scope explicit_excludes")
	// ErrTargetOutOfScope — scope-bound form: no include matched.
	ErrTargetOutOfScope = errors.New("pep: target out of scope")
	// ErrTaskBinding — the token is bound to a different task_id (task-bound
	// jti, doc 11 §3.2) or does not permit the assignment's capability.
	ErrTaskBinding = errors.New("pep: token does not authorize this task/capability")
)

// GuardConfig wires a Guard for one task execution.
type GuardConfig struct {
	// Claims — the verified Scope Token claims (from token.Verifier).
	Claims *token.Claims
	// Manifest — the fetched, hash-verified target manifest (manifest.Load).
	Manifest *manifest.Manifest
	// TaskID / Capability — the assignment being executed; the token must be
	// bound to them (task-bound jti).
	TaskID     string
	Capability string
	// Revocations — the agent-wide revocation cache (may be a fresh empty one).
	Revocations *RevocationCache
	// Emitter — audit sink for TARGET_TOUCHED / SCOPE_VIOLATION (nil-safe:
	// denials still refuse, records are dropped).
	Emitter audit.Emitter
	// Audit — actor/subject identity for emitted records.
	Audit audit.Ident
	// ExtraAudit — payload extras merged into TARGET_TOUCHED records
	// (doc 03 §9.6: probe_type, rps observed, …).
	ExtraAudit map[string]any
	// Now — clock injection (tests).
	Now func() time.Time
}

// Guard enforces the PEP-2 guardrails for one task. Safe for concurrent use.
type Guard struct {
	mu          sync.RWMutex
	claims      *token.Claims
	manifest    *manifest.Manifest
	limiter     *RateLimiter
	revocations *RevocationCache
	emitter     audit.Emitter
	auditID     audit.Ident
	extra       map[string]any
	now         func() time.Time

	touched    []string
	touchedSet map[string]struct{}
}

// NewGuard builds a Guard. It fails (refusing all target contact) when the
// token is not bound to this task/capability or the manifest form does not
// match the token's scope_bound claim.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	if cfg.Claims == nil {
		return nil, fmt.Errorf("%w: nil claims", ErrNoAuthorization)
	}
	if cfg.Manifest == nil {
		return nil, fmt.Errorf("%w: nil manifest", ErrNoAuthorization)
	}
	if cfg.Claims.TaskID != cfg.TaskID {
		return nil, fmt.Errorf("%w: token task_id %q, assignment %q",
			ErrTaskBinding, cfg.Claims.TaskID, cfg.TaskID)
	}
	if cfg.Capability != "" && !cfg.Claims.Permits(cfg.Capability) {
		return nil, fmt.Errorf("%w: capability %q not in token capabilities",
			ErrTaskBinding, cfg.Capability)
	}
	if cfg.Claims.ScopeBound != cfg.Manifest.ScopeBound() {
		return nil, fmt.Errorf("%w: scope_bound claim does not match manifest form", ErrTaskBinding)
	}
	rev := cfg.Revocations
	if rev == nil {
		rev = NewRevocationCache()
	}
	emitter := cfg.Emitter
	if emitter == nil {
		emitter = audit.NopEmitter{}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &Guard{
		claims:      cfg.Claims,
		manifest:    cfg.Manifest,
		limiter:     NewRateLimiter(cfg.Claims.RateCaps),
		revocations: rev,
		emitter:     emitter,
		auditID:     cfg.Audit,
		extra:       cfg.ExtraAudit,
		now:         now,
		touchedSet:  map[string]struct{}{},
	}, nil
}

// Claims returns the current claims (swapped on mid-run re-authorization).
func (g *Guard) Claims() *token.Claims {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.claims
}

// Update swaps in the successor token claims + manifest after a mid-run
// RefreshToken re-authorization (doc 01 §5.5, doc 11 §3.2). Rate caps are
// re-read from the new claims; the revocation cache and audit identity carry
// over. The successor must bind the same task.
func (g *Guard) Update(claims *token.Claims, m *manifest.Manifest) error {
	if claims == nil || m == nil {
		return fmt.Errorf("%w: nil successor claims/manifest", ErrNoAuthorization)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if claims.TaskID != g.claims.TaskID {
		return fmt.Errorf("%w: successor token task_id %q, want %q",
			ErrTaskBinding, claims.TaskID, g.claims.TaskID)
	}
	if claims.ScopeBound != m.ScopeBound() {
		return fmt.Errorf("%w: successor scope_bound does not match manifest form", ErrTaskBinding)
	}
	g.claims = claims
	g.manifest = m
	g.limiter = NewRateLimiter(claims.RateCaps)
	return nil
}

// AuthorizeTarget is the per-request gate: the SDK calls it before EVERY
// network action against target (doc 01 §5.5 "re-check every target string
// against the manifest before each network action"; §9 item 4). On success
// the contact is rate-limited into budget, the target is recorded as touched
// and a per-probe TARGET_TOUCHED audit record is emitted. On any failure the
// target MUST NOT be contacted — and the denial is audit-logged
// (SCOPE_VIOLATION, fail-closed per doc 03 §9.2).
func (g *Guard) AuthorizeTarget(ctx context.Context, target string) error {
	if err := g.check(ctx, target); err != nil {
		g.denyAudit(target, err)
		return err
	}
	g.recordTouch(target)
	return nil
}

// check runs revocation → token-time → target-form → rate-cap checks without
// recording anything.
func (g *Guard) check(ctx context.Context, target string) error {
	g.mu.RLock()
	claims := g.claims
	man := g.manifest
	limiter := g.limiter
	g.mu.RUnlock()

	// 1. Revocation (global / RoE / capability / target) — ≤ 5 s halt.
	if revoked, reason := g.revocations.Revoked(claims.ROEID, firstCapability(claims), target); revoked {
		return fmt.Errorf("%w: %s", ErrRevoked, reason)
	}

	// 2. Token time validity — halts work when re-authorization failed and
	// the token expired (doc 11 §7).
	if err := claims.ValidAt(g.now()); err != nil {
		return err
	}

	// 3. Per-request target authorization.
	if claims.ScopeBound {
		dec := man.EvaluateScope(target)
		if !dec.Allowed {
			if dec.Excluded {
				return fmt.Errorf("%w: %s", ErrTargetExcluded, dec.Reason)
			}
			return fmt.Errorf("%w: %s", ErrTargetOutOfScope, dec.Reason)
		}
	} else if !man.Contains(target) {
		return fmt.Errorf("%w: %q", ErrTargetNotInManifest, target)
	}

	// 4. Rate caps (self-contained; no PDP call, doc 11 §3.2).
	if err := limiter.Wait(ctx); err != nil {
		return err
	}
	return nil
}

// Acquire takes a max_concurrent slot for one in-flight probe batch.
func (g *Guard) Acquire(ctx context.Context) error {
	g.mu.RLock()
	limiter := g.limiter
	g.mu.RUnlock()
	return limiter.Acquire(ctx)
}

// Release returns a max_concurrent slot.
func (g *Guard) Release() {
	g.mu.RLock()
	limiter := g.limiter
	g.mu.RUnlock()
	limiter.Release()
}

// Touched returns the concrete targets authorized so far (canonical form,
// deduplicated, in first-touch order) — the honest targets_touched of
// doc 01 §9 item 6.
func (g *Guard) Touched() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]string, len(g.touched))
	copy(out, g.touched)
	return out
}

// TargetsTouchedMetric renders the TaskResult metrics.targets_touched form:
// for scope-bound watch tokens the checkpoint form ["scope:sha256:<hash>"]
// (accepted ONLY alongside the per-probe TARGET_TOUCHED records, Ruling A.4);
// for exact-enumerated tokens the concrete touched list.
func (g *Guard) TargetsTouchedMetric() []string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if g.claims.ScopeBound {
		return audit.CheckpointTargetsTouched(g.manifest.SHA256Hex)
	}
	out := make([]string, len(g.touched))
	copy(out, g.touched)
	return out
}

// ScopeAuditValue returns the "scope:sha256:<hash>" audit value of the
// current manifest (empty for exact-enumerated tokens).
func (g *Guard) ScopeAuditValue() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.manifest.ScopeAuditValue()
}

func (g *Guard) recordTouch(target string) {
	// Canonicalize for the audit record when possible; the raw string is
	// recorded verbatim otherwise (the check already passed on it).
	canonical := target
	if t, err := scope.Canonicalize(target); err == nil {
		canonical = t.Canonical
	}
	g.mu.Lock()
	if _, seen := g.touchedSet[canonical]; !seen {
		g.touchedSet[canonical] = struct{}{}
		g.touched = append(g.touched, canonical)
	}
	g.mu.Unlock()

	evt, err := audit.TargetTouchedEvent(g.auditID, canonical, g.Claims().ID, g.extra)
	if err == nil {
		// Audit emission is best-effort on the hot path; the audit-service
		// hash chain and the result-level targets_touched remain the
		// cross-check (fail-closed audit gating lives at dispatch, doc 11 §2.2).
		_ = g.emitter.Emit(context.Background(), evt)
	}
}

// denyAudit emits the SCOPE_VIOLATION record for an SDK-side denial
// (doc 01 §10.5; "dead-lettered and audit-logged", doc 03 §9.2). Revocations
// and token expiry are not violations — gatekeeper already audited them.
func (g *Guard) denyAudit(target string, cause error) {
	if errors.Is(cause, ErrRevoked) || errors.Is(cause, token.ErrExpired) ||
		errors.Is(cause, token.ErrNotYetValid) || errors.Is(cause, context.Canceled) ||
		errors.Is(cause, context.DeadlineExceeded) || errors.Is(cause, ErrRateLimited) {
		return
	}
	evt, err := audit.ScopeViolationEvent(g.auditID, target, g.Claims().ID, cause.Error())
	if err == nil {
		_ = g.emitter.Emit(context.Background(), evt)
	}
}

func firstCapability(c *token.Claims) string {
	if len(c.Capabilities) > 0 {
		return c.Capabilities[0]
	}
	return ""
}
