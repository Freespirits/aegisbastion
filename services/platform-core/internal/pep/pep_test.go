package pep

import (
	"context"
	"errors"
	"testing"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

type stubPDP struct {
	decision *gatekeeperv1.DecisionEvent
	err      error
	calls    int
	lastReq  *gatekeeperv1.AuthorizationRequest
}

func (s *stubPDP) Authorize(_ context.Context, req *gatekeeperv1.AuthorizationRequest) (*gatekeeperv1.DecisionEvent, error) {
	s.calls++
	s.lastReq = req
	return s.decision, s.err
}

type stubMinter struct {
	resp  *gatekeeperv1.MintTokenResponse
	err   error
	calls int
	last  *gatekeeperv1.MintTokenRequest
}

func (s *stubMinter) MintToken(_ context.Context, req *gatekeeperv1.MintTokenRequest) (*gatekeeperv1.MintTokenResponse, error) {
	s.calls++
	s.last = req
	return s.resp, s.err
}

func fixtures(risk, capability string) (*store.Task, *store.Mission, *store.Agent) {
	t := &store.Task{
		TaskID: "tsk_1", PlanID: "pln_1", MissionID: "msn_1",
		Capability: capability, RiskClass: risk, Targets: []string{"api.acme.com"},
	}
	m := &store.Mission{MissionID: "msn_1", RoeID: "roe_1", RoeVersion: 3, OwningCommander: "hexstrike"}
	a := &store.Agent{AgentID: "agent_1", Region: "eastus"}
	return t, m, a
}

// Doc 01 §15 acceptance behavior: gatekeeper unreachable → the PEP outcome
// is fail-closed (Unavailable, never Allowed).
func TestPEPUnreachableFailsClosed(t *testing.T) {
	pdp := &stubPDP{err: errors.New("connection refused")}
	p := New(pdp, &stubMinter{}, "test-instance")
	task, mission, agent := fixtures(store.RiskR1, "detect.scan")
	out := p.AuthorizeDispatch(context.Background(), task, mission, agent, "hexstrike")
	if !out.Unavailable {
		t.Fatal("expected Unavailable when PDP errors")
	}
	if out.Allowed() {
		t.Fatal("MUST NOT be Allowed when PDP is unreachable (fail-closed)")
	}
	if out.Err == nil {
		t.Fatal("expected error detail")
	}
}

// A nil PDP/minter (misconfiguration) is also fail-closed.
func TestPEPNilClientFailsClosed(t *testing.T) {
	p := New(nil, nil, "test-instance")
	task, mission, agent := fixtures(store.RiskR2, "detect.scan")
	out := p.AuthorizeDispatch(context.Background(), task, mission, agent, "hexstrike")
	if !out.Unavailable || out.Allowed() {
		t.Fatal("nil gatekeeper client must fail closed")
	}
}

// R0 never calls the PDP (no per-target token, doc 11 §1).
func TestPEPR0SkipsPDP(t *testing.T) {
	pdp := &stubPDP{err: errors.New("must not be called")}
	minter := &stubMinter{}
	p := New(pdp, minter, "test-instance")
	task, mission, agent := fixtures(store.RiskR0, "monitor.feed.sync")
	out := p.AuthorizeDispatch(context.Background(), task, mission, agent, "cai")
	if pdp.calls != 0 || minter.calls != 0 {
		t.Fatalf("R0 must not touch gatekeeper (pdp=%d minter=%d)", pdp.calls, minter.calls)
	}
	if out.Unavailable || out.Denied() {
		t.Fatal("R0 outcome must be neutral")
	}
}

func TestPEPDeny(t *testing.T) {
	pdp := &stubPDP{decision: &gatekeeperv1.DecisionEvent{
		DecisionId: "dec_1",
		Decision:   gatekeeperv1.Decision_DECISION_DENY,
		Reasons: []*gatekeeperv1.Reason{{
			Code:   gatekeeperv1.DenyReason_DENY_REASON_TARGET_EXCLUDED,
			Detail: "status.acme.com excluded",
		}},
	}}
	minter := &stubMinter{}
	p := New(pdp, minter, "test-instance")
	task, mission, agent := fixtures(store.RiskR1, "monitor.rescan")
	out := p.AuthorizeDispatch(context.Background(), task, mission, agent, "hexstrike")
	if !out.Denied() {
		t.Fatal("expected DENY")
	}
	if minter.calls != 0 {
		t.Fatal("DENY must never reach token-service")
	}
}

func TestPEPAllowMintsToken(t *testing.T) {
	pdp := &stubPDP{decision: &gatekeeperv1.DecisionEvent{
		DecisionId: "dec_9", Decision: gatekeeperv1.Decision_DECISION_ALLOW,
	}}
	minter := &stubMinter{resp: &gatekeeperv1.MintTokenResponse{
		Token:  "eyJ.fake",
		Claims: &gatekeeperv1.ScopeTokenClaims{Jti: "tok_1"},
	}}
	p := New(pdp, minter, "test-instance")
	task, mission, agent := fixtures(store.RiskR2, "detect.scan")
	out := p.AuthorizeDispatch(context.Background(), task, mission, agent, "hexstrike")
	if !out.Allowed() {
		t.Fatal("expected ALLOW")
	}
	if out.Token.GetToken() != "eyJ.fake" {
		t.Fatal("token not carried through")
	}
	if minter.last.GetDecisionId() != "dec_9" {
		t.Fatal("mint must reference the ALLOW decision id (doc 11 §2.2 invariant)")
	}
	if minter.last.GetScopeBound() {
		t.Fatal("R2 detect.scan must use the exact-enumerated manifest, not scope-bound")
	}
	if minter.last.GetSubject() != "agent_1" {
		t.Fatal("token sub must be the executing agent")
	}
}

// Ruling A: scope-bound form ONLY for R1 monitor.watch / monitor.rescan.
func TestPEPScopeBoundOnlyForWatch(t *testing.T) {
	pdp := &stubPDP{decision: &gatekeeperv1.DecisionEvent{
		DecisionId: "dec_1", Decision: gatekeeperv1.Decision_DECISION_ALLOW,
	}}
	minter := &stubMinter{resp: &gatekeeperv1.MintTokenResponse{Token: "t", Claims: &gatekeeperv1.ScopeTokenClaims{}}}
	p := New(pdp, minter, "test-instance")

	cases := []struct {
		capability, risk string
		wantScopeBound   bool
	}{
		{"monitor.watch", store.RiskR1, true},
		{"monitor.rescan", store.RiskR1, true},
		{"monitor.watch", store.RiskR2, false}, // wrong class — never scope-bound
		{"monitor.baseline.set", store.RiskR1, false},
		{"detect.scan", store.RiskR1, false},
	}
	for _, c := range cases {
		task, mission, agent := fixtures(c.risk, c.capability)
		minter.calls = 0
		out := p.AuthorizeDispatch(context.Background(), task, mission, agent, "cai")
		if !out.Allowed() {
			t.Fatalf("%s/%s: expected ALLOW", c.capability, c.risk)
		}
		if minter.last.GetScopeBound() != c.wantScopeBound {
			t.Errorf("%s/%s: scope_bound=%v, want %v",
				c.capability, c.risk, minter.last.GetScopeBound(), c.wantScopeBound)
		}
	}
}

// Mint failure after ALLOW is fail-closed (deferred, not dispatched).
func TestPEPMintFailureFailsClosed(t *testing.T) {
	pdp := &stubPDP{decision: &gatekeeperv1.DecisionEvent{
		DecisionId: "dec_1", Decision: gatekeeperv1.Decision_DECISION_ALLOW,
	}}
	minter := &stubMinter{err: errors.New("token-service down")}
	p := New(pdp, minter, "test-instance")
	task, mission, agent := fixtures(store.RiskR1, "monitor.rescan")
	out := p.AuthorizeDispatch(context.Background(), task, mission, agent, "cai")
	if !out.Unavailable || out.Allowed() {
		t.Fatal("mint failure must be Unavailable (fail-closed), never Allowed")
	}
}
