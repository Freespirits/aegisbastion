// Package pep is the dispatch Policy Enforcement Point (doc 01 C5, re-scoped
// per Ruling B): a thin adapter between the Orchestrator and the gatekeeper
// PDP. It holds NO RoE/token/audit stores of its own. The non-negotiable
// invariant (doc 01 §1): no task with risk class ≥ R1 is dispatched unless a
// gatekeeper authorization decision record exists and is linked in the audit
// log — every call here is fail-closed.
package pep

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/gatekeeper"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// Outcome is the result of one dispatch authorization attempt.
type Outcome struct {
	// Decision is the gatekeeper DecisionEvent (nil when the PDP was not
	// reached — R0 task — or unreachable).
	Decision *gatekeeperv1.DecisionEvent
	// Token is the minted Scope Token (nil for R0 and on any failure).
	Token *gatekeeperv1.MintTokenResponse
	// Unavailable is true when the PDP could not be evaluated (unreachable,
	// timeout, internal error): the dispatch MUST be deferred, never allowed.
	Unavailable bool
	// Err carries the underlying error when Unavailable is set.
	Err error
}

// Denied reports whether the PDP explicitly denied the request.
func (o *Outcome) Denied() bool {
	return o.Decision != nil && o.Decision.GetDecision() == gatekeeperv1.Decision_DECISION_DENY
}

// Allowed reports whether the PDP allowed AND a Scope Token was minted
// against the decision. An ALLOW without a token (mint failure) is NOT
// dispatchable — it is Unavailable (fail-closed).
func (o *Outcome) Allowed() bool {
	return o.Decision != nil &&
		o.Decision.GetDecision() == gatekeeperv1.Decision_DECISION_ALLOW &&
		o.Token != nil
}

// PEP is the dispatch PEP adapter.
type PEP struct {
	pdp        gatekeeper.PDP
	minter     gatekeeper.TokenMinter
	instanceID string
}

// New builds a PEP. pdp and minter may be nil only when the deployment
// dispatches R0 tasks exclusively — any R1+ attempt with a nil PDP is
// fail-closed by construction.
func New(pdp gatekeeper.PDP, minter gatekeeper.TokenMinter, instanceID string) *PEP {
	return &PEP{pdp: pdp, minter: minter, instanceID: instanceID}
}

// scopeBoundWatch reports whether the Ruling A scope-bound watch-token form
// applies: R1 monitor.watch / monitor.rescan ONLY.
func scopeBoundWatch(capability, riskClass string) bool {
	return riskClass == store.RiskR1 &&
		(capability == "monitor.watch" || capability == "monitor.rescan")
}

// AuthorizeDispatch evaluates one task dispatch (doc 01 §6.3). R0 tasks skip
// the PDP (no per-target token required, doc 11 §1). R1+ tasks are
// authorized fail-closed: any error or non-ALLOW outcome means "do not
// dispatch", and the caller must record the attempt in the audit chain
// (AUTHZ_DECISION) — that is acceptance test 1 of doc 01 §15.
func (p *PEP) AuthorizeDispatch(ctx context.Context, task *store.Task, mission *store.Mission, agent *store.Agent, commander string) *Outcome {
	// R0: no PDP call, no token (authorization_token stays empty, doc 01 §5.6).
	if task.RiskClass == store.RiskR0 {
		return &Outcome{}
	}
	if p.pdp == nil || p.minter == nil {
		return &Outcome{Unavailable: true, Err: fmt.Errorf("gatekeeper client not configured — fail-closed")}
	}

	req := &gatekeeperv1.AuthorizationRequest{
		RequestId: ids.New("req"),
		Principal: &gatekeeperv1.Principal{
			Kind:     "service",
			Id:       p.instanceID,
			SpiffeId: "spiffe://aegisbastion/platform-core/orchestrator",
		},
		Task: &gatekeeperv1.TaskContext{
			TaskId:       task.TaskID,
			ParentPlanId: task.PlanID,
			Commander:    commander,
		},
		Capability:  task.Capability,
		Targets:     task.Targets,
		RoeId:       mission.RoeID,
		RoeVersion:  uint64(mission.RoeVersion),
		RequestedAt: timestamppb.Now(),
		Context: &gatekeeperv1.EvaluationContext{
			SourceRegion: agent.Region,
		},
	}
	decision, err := p.pdp.Authorize(ctx, req)
	if err != nil {
		return &Outcome{Unavailable: true, Err: fmt.Errorf("policy-service.Authorize: %w", err)}
	}
	out := &Outcome{Decision: decision}
	if decision.GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
		return out // explicit DENY (or malformed outcome) — no mint attempted
	}

	// ALLOW → mint the Scope Token bound to this task/agent (doc 01 §6.3).
	mint, err := p.minter.MintToken(ctx, &gatekeeperv1.MintTokenRequest{
		DecisionId: decision.GetDecisionId(),
		TaskId:     task.TaskID,
		Subject:    agent.AgentID,
		Targets:    task.Targets,
		ScopeBound: scopeBoundWatch(task.Capability, task.RiskClass),
	})
	if err != nil {
		return &Outcome{Decision: decision, Unavailable: true,
			Err: fmt.Errorf("token-service.MintToken: %w", err)}
	}
	out.Token = mint
	return out
}

// RiskToProto maps store risk strings to the proto enum.
func RiskToProto(r string) platformv1.RiskClass {
	switch r {
	case store.RiskR0:
		return platformv1.RiskClass_RISK_CLASS_R0
	case store.RiskR1:
		return platformv1.RiskClass_RISK_CLASS_R1
	case store.RiskR2:
		return platformv1.RiskClass_RISK_CLASS_R2
	case store.RiskR3:
		return platformv1.RiskClass_RISK_CLASS_R3
	}
	return platformv1.RiskClass_RISK_CLASS_UNSPECIFIED
}

// RiskFromProto maps the proto enum to store risk strings.
func RiskFromProto(r platformv1.RiskClass) string {
	switch r {
	case platformv1.RiskClass_RISK_CLASS_R0:
		return store.RiskR0
	case platformv1.RiskClass_RISK_CLASS_R1:
		return store.RiskR1
	case platformv1.RiskClass_RISK_CLASS_R2:
		return store.RiskR2
	case platformv1.RiskClass_RISK_CLASS_R3:
		return store.RiskR3
	}
	return ""
}

// DenyReasons flattens a DecisionEvent's reasons for audit payloads.
func DenyReasons(d *gatekeeperv1.DecisionEvent) []map[string]any {
	var out []map[string]any
	for _, r := range d.GetReasons() {
		out = append(out, map[string]any{
			"code":   r.GetCode().String(),
			"detail": r.GetDetail(),
		})
	}
	return out
}

// Deadline computes the hard execution deadline for a task (lease TTL equals
// this, doc 01 §6.4).
func Deadline(timeoutS int) time.Time {
	if timeoutS <= 0 {
		timeoutS = 900
	}
	return time.Now().UTC().Add(time.Duration(timeoutS) * time.Second)
}
