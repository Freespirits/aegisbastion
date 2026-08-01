package orchestrator

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/pep"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// dispatchOutcome describes what dispatchOne decided (for tests + logging).
type dispatchOutcome string

const (
	outcomeDispatched dispatchOutcome = "DISPATCHED"
	outcomeDeferred   dispatchOutcome = "DEFERRED"
	outcomeDenied     dispatchOutcome = "DENIED"
	outcomeTerminal   dispatchOutcome = "TERMINAL"
)

// dispatchOne runs the doc 01 §6.3 gated dispatch flow for one QUEUED task:
//
//	mission/kill/dependency gates → capability match → R2/R3 leases → rate
//	buckets → PEP Authorize (fail-closed) → token mint → AUTHZ_DECISION +
//	TASK_DISPATCHED audit → publish task.assign.{agent_id}
//
// The §1 invariant: an R1+ task leaves QUEUED only with a gatekeeper
// decision record linked in the audit chain.
func (o *Orchestrator) dispatchOne(ctx context.Context, t *store.Task) (dispatchOutcome, error) {
	mission, err := o.store.GetMission(ctx, t.MissionID)
	if err != nil {
		return outcomeDeferred, fmt.Errorf("load mission: %w", err)
	}

	// --- mission gate -------------------------------------------------------
	switch mission.State {
	case store.MissionActive:
	case store.MissionKilled, store.MissionCompleted:
		if err := o.transition(ctx, t, []string{store.TaskQueued}, store.TaskKilled, "mission "+mission.State); err != nil {
			return outcomeTerminal, err
		}
		return outcomeTerminal, nil
	default: // DRAFT / PAUSED / PLANNER_DEGRADED — wait
		return outcomeDeferred, nil
	}

	// --- kill-switch flags (DB side of the kill switch, doc 01 §10.5) -------
	kills, err := o.store.KillSwitchesEngaged(ctx)
	if err != nil {
		return outcomeDeferred, fmt.Errorf("kill switches: %w", err)
	}
	if kills[store.KillScopeGlobal+"/"] || kills[store.KillScopeMission+"/"+t.MissionID] {
		if err := o.transition(ctx, t, []string{store.TaskQueued}, store.TaskKilled, "kill switch engaged"); err != nil {
			return outcomeTerminal, err
		}
		o.EmitMissionEvent(ctx, t.MissionID, "TASK_KILLED", t.TaskID, map[string]any{"reason": "kill switch engaged"})
		return outcomeTerminal, nil
	}

	// --- queue TTL ----------------------------------------------------------
	if time.Since(t.CreatedAt) > o.cfg.QueueTTL {
		if err := o.transition(ctx, t, []string{store.TaskQueued}, store.TaskExpired, "missed dispatch window"); err != nil {
			return outcomeTerminal, err
		}
		return outcomeTerminal, nil
	}

	// --- dependency failure -------------------------------------------------
	if failed, key, err := o.store.HasFailedDependency(ctx, t); err != nil {
		return outcomeDeferred, err
	} else if failed {
		if err := o.transition(ctx, t, []string{store.TaskQueued}, store.TaskCancelled,
			"dependency "+key+" failed"); err != nil {
			return outcomeTerminal, err
		}
		return outcomeTerminal, nil
	}

	// --- capability match (registry, doc 01 §8.3) ---------------------------
	agents, err := o.store.ListCapable(ctx, t.Capability, store.RiskRank(t.RiskClass))
	if err != nil {
		return outcomeDeferred, fmt.Errorf("registry: %w", err)
	}
	var agent *store.Agent
	for _, a := range agents {
		// R3 requires sandboxed execution (doc 01 §5.3).
		if t.RiskClass == store.RiskR3 && !a.Sandboxed {
			continue
		}
		agent = a
		break
	}
	if agent == nil {
		return outcomeDeferred, nil // no capable agent online — wait
	}

	// --- per-target intrusive leases (R2/R3, doc 01 §6.4) -------------------
	leaseTTL := pep.Deadline(t.TimeoutS).Sub(time.Now())
	acquired := []string{}
	if t.RiskClass == store.RiskR2 || t.RiskClass == store.RiskR3 {
		if o.leases == nil {
			// Intrusive serialization impossible → fail-safe defer.
			o.log.Warn("lease store unavailable; deferring intrusive dispatch", "task", t.TaskID)
			return outcomeDeferred, nil
		}
		for _, target := range t.Targets {
			ok, err := o.leases.Acquire(ctx, target, t.TaskID, leaseTTL)
			if err != nil {
				o.releaseLeases(ctx, t, acquired)
				return outcomeDeferred, fmt.Errorf("lease acquire: %w", err)
			}
			if !ok {
				o.releaseLeases(ctx, t, acquired)
				return outcomeDeferred, nil // target busy — serialize
			}
			acquired = append(acquired, target)
		}
	}
	// From here any early return MUST release acquired leases.
	release := func() { o.releaseLeases(ctx, t, acquired) }

	// --- per-RoE intrusive concurrency bucket (doc 01 §6.4) ------------------
	if t.RiskClass == store.RiskR2 || t.RiskClass == store.RiskR3 {
		cap := o.cfg.DefaultMaxConcurrentIntrusive
		if roe, err := o.ROE(ctx, mission); err == nil && roe.MaxConcurrent > 0 {
			cap = roe.MaxConcurrent
		}
		inFlight, err := o.store.CountIntrusiveInFlightByROE(ctx, mission.RoeID)
		if err != nil {
			release()
			return outcomeDeferred, fmt.Errorf("rate bucket: %w", err)
		}
		if inFlight >= cap {
			release()
			return outcomeDeferred, nil
		}
	}

	// --- dispatch PEP (fail-closed, doc 01 §6.3/C5) --------------------------
	commander := mission.OwningCommander
	outcome := o.pep.AuthorizeDispatch(ctx, t, mission, agent, commander)
	subj := audit.Subject{MissionID: t.MissionID, TaskID: t.TaskID, RoeID: mission.RoeID}

	switch {
	case outcome.Unavailable:
		// PDP/token-service unreachable or mint failed: NEVER dispatch; audit
		// the attempt (doc 01 §15 acceptance test 1).
		if err := o.AuditLog(ctx, audit.AuthzDecision, subj, map[string]any{
			"decision":   "UNAVAILABLE",
			"policy":     "gatekeeper.policy-service/v1",
			"error":      outcome.Err.Error(),
			"capability": t.Capability,
			"risk_class": t.RiskClass,
			"targets":    anySlice(t.Targets),
		}); err != nil {
			release()
			return outcomeDeferred, fmt.Errorf("audit AUTHZ_DECISION: %w", err)
		}
		release()
		return outcomeDeferred, nil

	case outcome.Denied():
		d := outcome.Decision
		reason := firstDenyReason(d)
		if err := o.AuditLog(ctx, audit.AuthzDecision, subj, map[string]any{
			"decision":    "DENY",
			"decision_id": d.GetDecisionId(),
			"policy":      "gatekeeper.policy-service/v1",
			"reasons":     denyReasonMaps(d),
			"capability":  t.Capability,
			"risk_class":  t.RiskClass,
			"targets":     anySlice(t.Targets),
		}); err != nil {
			release()
			return outcomeDeferred, fmt.Errorf("audit AUTHZ_DECISION: %w", err)
		}
		release()
		if err := o.transition(ctx, t, []string{store.TaskQueued}, store.TaskRejectedUnauthorized, reason,
			store.TaskField{Column: "rejection_reason", Value: reason}); err != nil {
			return outcomeDenied, err
		}
		o.EmitMissionEvent(ctx, t.MissionID, "TASK_REJECTED_UNAUTHORIZED", t.TaskID,
			map[string]any{"reason": reason, "decision_id": d.GetDecisionId()})
		return outcomeDenied, nil
	}

	// ALLOW (R1+, decision + token present) or R0 (no decision needed).
	// Anything else for an R1+ task is a malformed PDP outcome — fail closed.
	if t.RiskClass != store.RiskR0 && !outcome.Allowed() {
		if err := o.AuditLog(ctx, audit.AuthzDecision, subj, map[string]any{
			"decision":   "UNAVAILABLE",
			"policy":     "gatekeeper.policy-service/v1",
			"error":      "malformed PDP outcome: neither ALLOW+token nor DENY",
			"capability": t.Capability,
			"risk_class": t.RiskClass,
			"targets":    anySlice(t.Targets),
		}); err != nil {
			release()
			return outcomeDeferred, fmt.Errorf("audit AUTHZ_DECISION: %w", err)
		}
		release()
		return outcomeDeferred, nil
	}

	token := ""
	decisionID := ""
	jti := ""
	if outcome.Allowed() {
		decisionID = outcome.Decision.GetDecisionId()
		token = outcome.Token.GetToken()
		jti = outcome.Token.GetClaims().GetJti()
		if err := o.AuditLog(ctx, audit.AuthzDecision, subj, map[string]any{
			"decision":    "ALLOW",
			"decision_id": decisionID,
			"token_jti":   jti,
			"policy":      "gatekeeper.policy-service/v1",
			"capability":  t.Capability,
			"risk_class":  t.RiskClass,
			"targets":     anySlice(t.Targets),
			"scope_bound": outcome.Token.GetClaims().GetScopeBound(),
		}); err != nil {
			release()
			return outcomeDeferred, fmt.Errorf("audit AUTHZ_DECISION: %w", err)
		}
	}

	// --- state transition + outbox (one tx) ----------------------------------
	deadline := pep.Deadline(t.TimeoutS)
	assignment := buildAssignment(t, agent, token, deadline, o.cfg.ArtifactBucket)
	env, err := bus.NewEnvelope(t.MissionID, assignment)
	if err != nil {
		release()
		return outcomeDeferred, err
	}
	env.TraceContext = assignment.TraceContext
	data, err := bus.MarshalEnvelope(env)
	if err != nil {
		release()
		return outcomeDeferred, err
	}

	tx, err := o.store.Pool.Begin(ctx)
	if err != nil {
		release()
		return outcomeDeferred, err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback(ctx)
		}
	}()

	// Transition inline (same tx as the outbox row so state + publish are
	// atomic; task_state_transitions logged here too).
	tag, err := tx.Exec(ctx, `
		UPDATE platform.tasks SET
		    state = 'DISPATCHED', assigned_agent_id = $2,
		    authorization_token_jti = NULLIF($3,''), decision_id = NULLIF($4,''),
		    deadline = $5, dispatched_at = now(), updated_at = now()
		WHERE task_id = $1 AND state = 'QUEUED'`,
		t.TaskID, agent.AgentID, jti, decisionID, deadline)
	if err != nil {
		release()
		return outcomeDeferred, err
	}
	if tag.RowsAffected() == 0 {
		release()
		_ = tx.Rollback(ctx)
		committed = true            // nothing to roll back anymore
		return outcomeDeferred, nil // another replica won the race
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO platform.task_state_transitions (task_id, from_state, to_state, actor, reason)
		VALUES ($1, 'QUEUED', 'DISPATCHED', $2, $3)`, t.TaskID, o.cfg.InstanceID, "dispatch PEP allowed"); err != nil {
		release()
		return outcomeDeferred, err
	}
	outboxID, err := store.OutboxAdd(ctx, tx, env.EventId, bus.SubjectTaskAssignPrefix+agent.AgentID, data, assignment.TraceContext.GetTraceparent())
	if err != nil {
		release()
		return outcomeDeferred, err
	}
	if err := tx.Commit(ctx); err != nil {
		release()
		return outcomeDeferred, err
	}
	committed = true

	// --- TASK_DISPATCHED audit (critical path, doc 01 §13) --------------------
	if err := o.AuditLog(ctx, audit.TaskDispatched, subj, map[string]any{
		"agent_id":    agent.AgentID,
		"decision_id": decisionID,
		"token_jti":   jti,
		"deadline":    deadline.Format(time.RFC3339Nano),
	}); err != nil {
		// Audit failed hard (no spill): roll back the publish + state so the
		// invariant "dispatch implies audit" holds, then defer.
		_ = o.store.OutboxDrop(ctx, outboxID)
		_ = o.transition(ctx, t, []string{store.TaskDispatched}, store.TaskQueued, "audit write failure — dispatch rolled back")
		release()
		return outcomeDeferred, fmt.Errorf("audit TASK_DISPATCHED: %w", err)
	}

	// In-process fan-out (StreamTasks) + relay wake for the bus path.
	o.assignments.publish(agent.AgentID, assignment)
	o.wakeRelay()
	return outcomeDispatched, nil
}

// releaseLeases drops held leases for targets still owned by the task.
func (o *Orchestrator) releaseLeases(ctx context.Context, t *store.Task, targets []string) {
	if o.leases == nil {
		return
	}
	for _, target := range targets {
		if err := o.leases.Release(ctx, target, t.TaskID); err != nil {
			o.log.Warn("lease release", "task", t.TaskID, "target", target, "err", err)
		}
	}
}

// releaseAllTargetLeases drops leases for every task target (result/kill
// paths).
func (o *Orchestrator) releaseAllTargetLeases(ctx context.Context, t *store.Task) {
	if t.RiskClass == store.RiskR2 || t.RiskClass == store.RiskR3 {
		o.releaseLeases(ctx, t, t.Targets)
	}
}

// transition applies the state machine guard around store.Transition.
func (o *Orchestrator) transition(ctx context.Context, t *store.Task, from []string, to, reason string, fields ...store.TaskField) error {
	for _, f := range from {
		if !CanTransition(f, to) {
			return fmt.Errorf("state machine: %s → %s not allowed", f, to)
		}
	}
	if err := o.store.Transition(ctx, t.TaskID, from, to, o.cfg.InstanceID, reason, fields...); err != nil {
		return err
	}
	t.State = to
	return nil
}

// buildAssignment assembles the doc 01 §5.6 TaskAssignment.
func buildAssignment(t *store.Task, agent *store.Agent, token string, deadline time.Time, artifactBucket string) *platformv1.TaskAssignment {
	var params = "{}"
	if len(t.Params) > 0 {
		params = string(t.Params)
	}
	return &platformv1.TaskAssignment{
		TaskId:             t.TaskID,
		MissionId:          t.MissionID,
		PlanId:             t.PlanID,
		Capability:         t.Capability,
		RiskClass:          pep.RiskToProto(t.RiskClass),
		Targets:            t.Targets,
		Params:             structFromJSON(params),
		TimeoutS:           uint32(t.TimeoutS),
		Deadline:           timestamppb.New(deadline),
		AuthorizationToken: token, // empty for R0 (doc 01 §5.6)
		ArtifactUpload: &platformv1.ArtifactUpload{
			Bucket: artifactBucket,
			Prefix: fmt.Sprintf("%s/%s/", t.MissionID, t.TaskID),
		},
		TraceContext: &platformv1.TraceContext{Traceparent: newTraceparent()},
	}
}

func newTraceparent() string {
	var traceID, spanID [16]byte
	_, _ = rand.Read(traceID[:])
	_, _ = rand.Read(spanID[:8])
	return fmt.Sprintf("00-%s-%s-01", hex.EncodeToString(traceID[:]), hex.EncodeToString(spanID[:8]))
}

func structFromJSON(s string) *structpb.Struct {
	m := map[string]any{}
	_ = json.Unmarshal([]byte(s), &m)
	st, err := structpb.NewStruct(m)
	if err != nil {
		return &structpb.Struct{}
	}
	return st
}

func anySlice(ss []string) []any {
	out := make([]any, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

func firstDenyReason(d *gatekeeperv1.DecisionEvent) string {
	if rs := d.GetReasons(); len(rs) > 0 {
		code := rs[0].GetCode().String()
		if rs[0].GetDetail() != "" {
			return code + ": " + rs[0].GetDetail()
		}
		return code
	}
	return "DENIED"
}

func denyReasonMaps(d *gatekeeperv1.DecisionEvent) []any {
	out := []any{}
	for _, r := range d.GetReasons() {
		out = append(out, map[string]any{"code": r.GetCode().String(), "detail": r.GetDetail()})
	}
	return out
}
