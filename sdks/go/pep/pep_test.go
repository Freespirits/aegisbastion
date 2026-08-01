package pep

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/scope"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"
)

var testNow = time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

func exactManifest(targets ...string) *manifest.Manifest {
	m := &manifest.Manifest{SHA256Hex: "ab"}
	for _, t := range targets {
		ct, err := scope.Canonicalize(t)
		if err != nil {
			panic(err)
		}
		m.ExactTargets = append(m.ExactTargets, ct.Canonical)
	}
	return m
}

func scopeManifest() *manifest.Manifest {
	return &manifest.Manifest{
		SHA256Hex: "7d3e",
		ScopeManifest: &manifest.ScopeManifest{
			ROEID:      "roe_1",
			ROEVersion: 1,
			Scope: scope.Scope{
				Domains:          []string{"acme.com", "*.acme.com"},
				CIDRs:            []string{"203.0.113.0/24"},
				ExplicitExcludes: []string{"status.acme.com"},
			},
		},
	}
}

func claimsFor(mut func(*token.Claims)) *token.Claims {
	c := &token.Claims{
		Issuer:       token.Issuer,
		Audience:     token.Audience,
		ID:           "tok_1",
		Subject:      "agent_1",
		TaskID:       "tsk_1",
		ROEID:        "roe_1",
		ROEVersion:   1,
		RiskClass:    "R2",
		Capabilities: []string{"detect.scan"},
		NotBefore:    testNow.Add(-time.Minute).Unix(),
		ExpiresAt:    testNow.Add(14 * time.Minute).Unix(),
	}
	if mut != nil {
		mut(c)
	}
	return c
}

type recordedEvents struct {
	mu     sync.Mutex
	events []*platformv1.AuditEvent
}

func (r *recordedEvents) emitter() audit.Emitter {
	return audit.EmitterFunc(func(_ context.Context, evt *platformv1.AuditEvent) error {
		r.mu.Lock()
		r.events = append(r.events, evt)
		r.mu.Unlock()
		return nil
	})
}

func (r *recordedEvents) byType(t platformv1.AuditEventType) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, e := range r.events {
		if e.GetType() == t {
			n++
		}
	}
	return n
}

func newTestGuard(t *testing.T, claims *token.Claims, man *manifest.Manifest, rev *RevocationCache, rec *recordedEvents) *Guard {
	t.Helper()
	if rev == nil {
		rev = NewRevocationCache(WithRevocationClock(func() time.Time { return testNow }))
	}
	if rec == nil {
		rec = &recordedEvents{}
	}
	g, err := NewGuard(GuardConfig{
		Claims:      claims,
		Manifest:    man,
		TaskID:      claims.TaskID,
		Capability:  claims.Capabilities[0],
		Revocations: rev,
		Emitter:     rec.emitter(),
		Audit:       audit.Ident{AgentID: "agent_1", MissionID: "msn_1", TaskID: claims.TaskID, ROEID: claims.ROEID},
		Now:         func() time.Time { return testNow },
	})
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	return g
}

// TestGuard_AuthorizeTarget is the doc 01 §15 acceptance-test-2 table: every
// guardrail failure refuses target contact and the denial is audit-logged.
func TestGuard_AuthorizeTarget(t *testing.T) {
	clock := func() time.Time { return testNow }

	revokedROE := NewRevocationCache(WithRevocationClock(clock))
	revokedROE.Apply(&gatekeeperv1.Revocation{
		RevocationId: "rev_1",
		Scope:        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE,
		Key:          "roe_1",
	})
	revokedTarget := NewRevocationCache(WithRevocationClock(clock))
	revokedTarget.Apply(&gatekeeperv1.Revocation{
		RevocationId: "rev_2",
		Scope:        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_TARGET,
		Key:          "https://api.acme.com:443/graphql", // canonicalizes to the manifest form
	})
	revokedCapability := NewRevocationCache(WithRevocationClock(clock))
	revokedCapability.Apply(&gatekeeperv1.Revocation{
		RevocationId: "rev_3",
		Scope:        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_CAPABILITY,
		Key:          "detect.scan",
	})
	revokedGlobal := NewRevocationCache(WithRevocationClock(clock))
	revokedGlobal.Apply(&gatekeeperv1.Revocation{
		RevocationId: "rev_4",
		Scope:        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL,
	})

	cases := []struct {
		name          string
		claims        *token.Claims
		man           *manifest.Manifest
		rev           *RevocationCache
		target        string
		wantErr       error
		wantViolation bool // SCOPE_VIOLATION audit record expected
		wantTouch     bool // TARGET_TOUCHED audit record expected
	}{
		{
			name:      "exact manifest member allowed",
			claims:    claimsFor(nil),
			man:       exactManifest("https://api.acme.com/graphql"),
			target:    "https://api.acme.com:443/graphql", // canonicalizes to the manifest entry
			wantTouch: true,
		},
		{
			name:          "target not in manifest refused",
			claims:        claimsFor(nil),
			man:           exactManifest("https://api.acme.com/graphql"),
			target:        "https://evil.example.com/",
			wantErr:       ErrTargetNotInManifest,
			wantViolation: true,
		},
		{
			name: "scope-bound in-scope allowed",
			claims: claimsFor(func(c *token.Claims) {
				c.ScopeBound = true
				c.RiskClass = "R1"
				c.Capabilities = []string{"monitor.watch"}
			}),
			man:       scopeManifest(),
			target:    "api.acme.com",
			wantTouch: true,
		},
		{
			name: "scope-bound excluded refused (exclusions always win)",
			claims: claimsFor(func(c *token.Claims) {
				c.ScopeBound = true
				c.RiskClass = "R1"
				c.Capabilities = []string{"monitor.watch"}
			}),
			man:           scopeManifest(),
			target:        "status.acme.com",
			wantErr:       ErrTargetExcluded,
			wantViolation: true,
		},
		{
			name: "scope-bound out-of-scope refused (fail-closed)",
			claims: claimsFor(func(c *token.Claims) {
				c.ScopeBound = true
				c.RiskClass = "R1"
				c.Capabilities = []string{"monitor.watch"}
			}),
			man:           scopeManifest(),
			target:        "other-corp.example",
			wantErr:       ErrTargetOutOfScope,
			wantViolation: true,
		},
		{
			name:    "RoE revoked halts (≤ 5 s, doc 11 §7)",
			claims:  claimsFor(nil),
			man:     exactManifest("https://api.acme.com/graphql"),
			rev:     revokedROE,
			target:  "https://api.acme.com/graphql",
			wantErr: ErrRevoked,
		},
		{
			name:    "target revoked halts (canonical match both sides)",
			claims:  claimsFor(nil),
			man:     exactManifest("https://api.acme.com/graphql"),
			rev:     revokedTarget,
			target:  "https://api.acme.com/graphql",
			wantErr: ErrRevoked,
		},
		{
			name:    "capability revoked halts",
			claims:  claimsFor(nil),
			man:     exactManifest("https://api.acme.com/graphql"),
			rev:     revokedCapability,
			target:  "https://api.acme.com/graphql",
			wantErr: ErrRevoked,
		},
		{
			name:    "global revocation halts everything",
			claims:  claimsFor(nil),
			man:     exactManifest("https://api.acme.com/graphql"),
			rev:     revokedGlobal,
			target:  "https://api.acme.com/graphql",
			wantErr: ErrRevoked,
		},
		{
			name: "expired mid-run token halts target contact",
			claims: claimsFor(func(c *token.Claims) {
				c.ExpiresAt = testNow.Add(-2 * time.Minute).Unix()
				c.NotBefore = testNow.Add(-16 * time.Minute).Unix()
			}),
			man:     exactManifest("https://api.acme.com/graphql"),
			target:  "https://api.acme.com/graphql",
			wantErr: token.ErrExpired,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := &recordedEvents{}
			capability := tc.claims.Capabilities[0]
			g, err := NewGuard(GuardConfig{
				Claims:      tc.claims,
				Manifest:    tc.man,
				TaskID:      tc.claims.TaskID,
				Capability:  capability,
				Revocations: tc.rev,
				Emitter:     rec.emitter(),
				Audit:       audit.Ident{AgentID: "agent_1", MissionID: "msn_1", TaskID: tc.claims.TaskID, ROEID: tc.claims.ROEID},
				Now:         func() time.Time { return testNow },
			})
			if err != nil {
				t.Fatalf("NewGuard: %v", err)
			}
			err = g.AuthorizeTarget(context.Background(), tc.target)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("AuthorizeTarget(%q) = %v, want nil", tc.target, err)
				}
			} else {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("AuthorizeTarget(%q) = %v, want %v", tc.target, err, tc.wantErr)
				}
			}
			if got := rec.byType(platformv1.AuditEventType_AUDIT_EVENT_TYPE_TARGET_TOUCHED) > 0; got != tc.wantTouch {
				t.Errorf("TARGET_TOUCHED emitted = %v, want %v", got, tc.wantTouch)
			}
			if got := rec.byType(platformv1.AuditEventType_AUDIT_EVENT_TYPE_SCOPE_VIOLATION) > 0; got != tc.wantViolation {
				t.Errorf("SCOPE_VIOLATION emitted = %v, want %v", got, tc.wantViolation)
			}
		})
	}
}

func TestGuard_TaskBinding(t *testing.T) {
	man := exactManifest("acme.com")
	// Token bound to another task.
	if _, err := NewGuard(GuardConfig{
		Claims:   claimsFor(func(c *token.Claims) { c.TaskID = "tsk_OTHER" }),
		Manifest: man, TaskID: "tsk_1", Capability: "detect.scan",
	}); !errors.Is(err, ErrTaskBinding) {
		t.Fatalf("wrong-task token: err = %v, want ErrTaskBinding", err)
	}
	// Token missing the capability.
	if _, err := NewGuard(GuardConfig{
		Claims:   claimsFor(nil),
		Manifest: man, TaskID: "tsk_1", Capability: "redteam.api_probe",
	}); !errors.Is(err, ErrTaskBinding) {
		t.Fatalf("wrong-capability token: err = %v, want ErrTaskBinding", err)
	}
	// scope_bound claim vs manifest form mismatch.
	if _, err := NewGuard(GuardConfig{
		Claims:   claimsFor(func(c *token.Claims) { c.ScopeBound = true }),
		Manifest: man, TaskID: "tsk_1", Capability: "detect.scan",
	}); !errors.Is(err, ErrTaskBinding) {
		t.Fatalf("form mismatch: err = %v, want ErrTaskBinding", err)
	}
}

func TestGuard_TouchedAndCheckpointMetric(t *testing.T) {
	rec := &recordedEvents{}
	// Exact form: concrete touched list, deduped.
	g := newTestGuard(t, claimsFor(nil), exactManifest("a.acme.com", "b.acme.com"), nil, rec)
	for _, tgt := range []string{"a.acme.com", "a.acme.com", "b.acme.com"} {
		if err := g.AuthorizeTarget(context.Background(), tgt); err != nil {
			t.Fatal(err)
		}
	}
	if got := g.Touched(); len(got) != 2 || got[0] != "a.acme.com" || got[1] != "b.acme.com" {
		t.Fatalf("Touched = %v", got)
	}
	if got := g.TargetsTouchedMetric(); len(got) != 2 {
		t.Fatalf("TargetsTouchedMetric = %v, want concrete list", got)
	}

	// Scope-bound form: ["scope:sha256:<hash>"] checkpoint (Ruling A.4) —
	// valid only alongside the per-probe TARGET_TOUCHED records.
	gs := newTestGuard(t,
		claimsFor(func(c *token.Claims) {
			c.ScopeBound = true
			c.RiskClass = "R1"
			c.Capabilities = []string{"monitor.watch"}
		}),
		scopeManifest(), nil, rec)
	if err := gs.AuthorizeTarget(context.Background(), "api.acme.com"); err != nil {
		t.Fatal(err)
	}
	metric := gs.TargetsTouchedMetric()
	if len(metric) != 1 || metric[0] != "scope:sha256:7d3e" {
		t.Fatalf("scope-bound metric = %v", metric)
	}
	// Per-probe TARGET_TOUCHED records are emitted per authorize call (4
	// probe authorizations above: 3 exact + 1 scope-bound); the metric list
	// is the deduped one.
	if rec.byType(platformv1.AuditEventType_AUDIT_EVENT_TYPE_TARGET_TOUCHED) != 4 {
		t.Fatalf("TARGET_TOUCHED count = %d, want 4", rec.byType(platformv1.AuditEventType_AUDIT_EVENT_TYPE_TARGET_TOUCHED))
	}
}

func TestRateLimiter(t *testing.T) {
	l := NewRateLimiter(&token.RateCaps{MaxRPS: 2, MaxConcurrent: 1})
	if !l.Allow() || !l.Allow() {
		t.Fatalf("burst of 2 at max_rps=2 must pass")
	}
	if l.Allow() {
		t.Fatalf("third immediate request must be denied at max_rps=2")
	}
	// Wait denies when the delay exceeds the burst-tolerance bound.
	slow := NewRateLimiter(&token.RateCaps{MaxRPS: 1})
	slow.Allow()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := slow.Wait(ctx); err == nil {
		t.Fatalf("Wait must fail when over budget (ctx timeout)")
	}
	// Concurrency slots.
	if !l.TryAcquire() {
		t.Fatalf("first Acquire must succeed")
	}
	if l.TryAcquire() {
		t.Fatalf("second concurrent Acquire must fail at max_concurrent=1")
	}
	l.Release()
	if !l.TryAcquire() {
		t.Fatalf("Acquire after Release must succeed")
	}
	// Nil caps = unlimited.
	open := NewRateLimiter(nil)
	for i := 0; i < 100; i++ {
		if !open.Allow() || !open.TryAcquire() {
			t.Fatalf("uncapped limiter denied at %d", i)
		}
	}
}

func TestRevocationCache(t *testing.T) {
	now := testNow
	c := NewRevocationCache(WithRevocationClock(func() time.Time { return now }))

	// Expired temporary revocation is a no-op.
	c.Apply(&gatekeeperv1.Revocation{
		RevocationId: "rev_old",
		Scope:        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL,
		ExpiresAt:    timestamppb.New(now.Add(-time.Minute)),
	})
	if halted, _ := c.Halted(); halted {
		t.Fatalf("expired revocation halted the cache")
	}

	// Event application: ROE revocation hits matching RoE only.
	c.ApplyEvent(&gatekeeperv1.RevocationEvent{Revocation: &gatekeeperv1.Revocation{
		RevocationId: "rev_roe",
		Scope:        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE,
		Key:          "roe_1",
		Reason:       "RoE revoked by operator",
	}})
	if ok, _ := c.Revoked("roe_1", "detect.scan", "acme.com"); !ok {
		t.Fatalf("roe_1 revocation not applied")
	}
	if ok, _ := c.Revoked("roe_2", "detect.scan", "acme.com"); ok {
		t.Fatalf("roe_2 falsely revoked")
	}

	// Replace lifts cleared revocations (≤ 30 s reconciliation).
	c.Replace(nil)
	if ok, _ := c.Revoked("roe_1", "", ""); ok {
		t.Fatalf("Replace(nil) did not lift the revocation")
	}

	// Target revocation canonicalizes both sides.
	c.Apply(&gatekeeperv1.Revocation{
		RevocationId: "rev_t",
		Scope:        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_TARGET,
		Key:          "HTTPS://API.Acme.COM:443/x",
	})
	if ok, _ := c.Revoked("", "", "https://api.acme.com/x"); !ok {
		t.Fatalf("canonical target revocation missed")
	}
}

func TestKillDecision(t *testing.T) {
	mkEnv := func(t *testing.T, rev *gatekeeperv1.Revocation, missionID string) *platformv1.Envelope {
		t.Helper()
		if rev == nil {
			return &platformv1.Envelope{MissionId: missionID}
		}
		any, err := anypb.New(&gatekeeperv1.RevocationEvent{Revocation: rev})
		if err != nil {
			t.Fatal(err)
		}
		return &platformv1.Envelope{
			Type:      "aegisbastion.gatekeeper.v1.RevocationEvent",
			MissionId: missionID,
			Payload:   any,
		}
	}

	cases := []struct {
		name       string
		rev        *gatekeeperv1.Revocation
		envMission string
		ourMission string
		wantKill   bool
	}{
		{name: "global kill halts", rev: &gatekeeperv1.Revocation{Scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL, Reason: "DISARM-ALL"}, wantKill: true},
		{name: "RoE kill is a check signal", rev: &gatekeeperv1.Revocation{Scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE, Key: "roe_1"}, wantKill: true},
		{name: "capability kill is a check signal", rev: &gatekeeperv1.Revocation{Scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_CAPABILITY, Key: "detect.scan"}, wantKill: true},
		{name: "mission kill matches ours", rev: nil, envMission: "msn_1", ourMission: "msn_1", wantKill: true},
		{name: "mission kill ignores others", rev: nil, envMission: "msn_2", ourMission: "msn_1", wantKill: false},
		{name: "empty envelope does not kill", rev: nil, wantKill: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kill, _ := KillDecision(mkEnv(t, tc.rev, tc.envMission), tc.ourMission)
			if kill != tc.wantKill {
				t.Fatalf("KillDecision = %v, want %v", kill, tc.wantKill)
			}
		})
	}
}

func TestGuard_UpdateSuccessor(t *testing.T) {
	g := newTestGuard(t, claimsFor(nil), exactManifest("a.acme.com"), nil, nil)
	// Successor for the same task with new rate caps + manifest.
	succ := claimsFor(func(c *token.Claims) {
		c.ID = "tok_2"
		c.IssuedAt = testNow.Unix()
		c.NotBefore = testNow.Unix()
		c.ExpiresAt = testNow.Add(15 * time.Minute).Unix()
		c.RateCaps = &token.RateCaps{MaxRPS: 1}
	})
	if err := g.Update(succ, exactManifest("b.acme.com")); err != nil {
		t.Fatalf("Update: %v", err)
	}
	if err := g.AuthorizeTarget(context.Background(), "b.acme.com"); err != nil {
		t.Fatalf("successor manifest not in force: %v", err)
	}
	if err := g.AuthorizeTarget(context.Background(), "a.acme.com"); !errors.Is(err, ErrTargetNotInManifest) {
		t.Fatalf("old manifest target still allowed: %v", err)
	}
	// Successor bound to another task is refused.
	if err := g.Update(claimsFor(func(c *token.Claims) { c.TaskID = "tsk_OTHER" }), exactManifest("a.acme.com")); !errors.Is(err, ErrTaskBinding) {
		t.Fatalf("cross-task successor accepted: %v", err)
	}
}
