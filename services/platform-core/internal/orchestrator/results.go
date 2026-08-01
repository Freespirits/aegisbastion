package orchestrator

import (
	"context"
	"fmt"
	"strings"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
	"github.com/aegisbastion/aegisbastion/services/platform-core/pkg/scope"
)

// HandleResult processes a terminal TaskResult from an agent (doc 01 §5.7,
// §6.3 tail). Idempotent on task_id — duplicate deliveries are ACKed and
// dropped (doc 01 §8.2).
func (o *Orchestrator) HandleResult(ctx context.Context, res *platformv1.TaskResult) error {
	t, err := o.store.GetTask(ctx, res.GetTaskId())
	if err == store.ErrNotFound {
		return fmt.Errorf("unknown task %s", res.GetTaskId())
	}
	if err != nil {
		return err
	}
	if store.TerminalStates[t.State] {
		return nil // duplicate delivery — idempotent no-op
	}
	if t.AssignedAgentID != res.GetAgentId() {
		return fmt.Errorf("result for task %s from wrong agent %s (assigned %s)",
			t.TaskID, res.GetAgentId(), t.AssignedAgentID)
	}

	subj := audit.Subject{MissionID: t.MissionID, TaskID: t.TaskID}
	summaryJSON := []byte(`{}`)
	if res.GetSummary() != nil {
		if b, err := res.GetSummary().MarshalJSON(); err == nil {
			summaryJSON = b
		}
	}
	fin := res.GetFinishedAt().AsTime()

	fields := []store.TaskField{
		{Column: "result_status", Value: resultStatusName(res.GetStatus())},
		{Column: "result_summary", Value: summaryJSON},
		{Column: "artifact_refs", Value: res.GetArtifactRefs()},
		{Column: "targets_touched", Value: res.GetMetrics().GetTargetsTouched()},
		{Column: "finished_at", Value: fin},
	}
	if res.GetError() != "" {
		fields = append(fields, store.TaskField{Column: "error", Value: res.GetError()})
	}

	// REPORTED, then route by status.
	var to string
	fromStates := []string{store.TaskRunning, store.TaskDispatched}
	switch res.GetStatus() {
	case platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED:
		to = store.TaskReported
	case platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED,
		platformv1.TaskResultStatus_TASK_RESULT_STATUS_TIMEOUT:
		to = store.TaskFailed
	case platformv1.TaskResultStatus_TASK_RESULT_STATUS_KILLED:
		to = store.TaskKilled
	case platformv1.TaskResultStatus_TASK_RESULT_STATUS_REJECTED_UNAUTHORIZED:
		to = store.TaskRejectedUnauthorized
	default:
		return fmt.Errorf("result with unspecified status")
	}
	// FAILED/KILLED/REJECTED are reachable from REPORTED; walk through it.
	if err := o.transition(ctx, t, fromStates, store.TaskReported, "result received", fields...); err != nil {
		return err
	}
	o.releaseAllTargetLeases(ctx, t)

	if err := o.AuditLog(ctx, audit.TaskResult, subj, map[string]any{
		"status":          resultStatusName(res.GetStatus()),
		"agent_id":        res.GetAgentId(),
		"targets_touched": anySlice(res.GetMetrics().GetTargetsTouched()),
		"requests_sent":   res.GetMetrics().GetRequestsSent(),
	}); err != nil {
		o.log.Error("audit TASK_RESULT", "task", t.TaskID, "err", err)
	}

	// --- targets_touched cross-check (doc 01 §10.5) --------------------------
	if violation := o.checkTargetsTouched(t, res); violation != "" {
		return o.handleScopeViolation(ctx, t, res, violation)
	}

	switch to {
	case store.TaskReported: // success path → VALIDATED → COMPLETED
		if err := o.transition(ctx, t, []string{store.TaskReported}, store.TaskValidated, "result validated"); err != nil {
			return err
		}
		if err := o.transition(ctx, t, []string{store.TaskValidated}, store.TaskCompleted, "task complete"); err != nil {
			return err
		}
		o.EmitMissionEvent(ctx, t.MissionID, "TASK_COMPLETED", t.TaskID, map[string]any{
			"agent_id": res.GetAgentId(),
		})
		o.maybeRenewWatch(ctx, t, res)
	case store.TaskFailed:
		return o.handleFailure(ctx, t, res.GetError())
	case store.TaskKilled:
		if err := o.transition(ctx, t, []string{store.TaskReported}, store.TaskKilled, "agent reported KILLED"); err != nil {
			return err
		}
		o.EmitMissionEvent(ctx, t.MissionID, "TASK_KILLED", t.TaskID, map[string]any{"agent_id": res.GetAgentId()})
	case store.TaskRejectedUnauthorized:
		if err := o.transition(ctx, t, []string{store.TaskReported}, store.TaskRejectedUnauthorized,
			"SDK guardrail refused: "+res.GetError(),
			store.TaskField{Column: "rejection_reason", Value: res.GetError()}); err != nil {
			return err
		}
		o.EmitMissionEvent(ctx, t.MissionID, "TASK_REJECTED_UNAUTHORIZED", t.TaskID, map[string]any{
			"reason": res.GetError(),
		})
	}
	return nil
}

// handleFailure retries up to max_retries, then DEAD (doc 01 §6.2).
func (o *Orchestrator) handleFailure(ctx context.Context, t *store.Task, cause string) error {
	if t.Attempt < t.MaxRetries {
		if err := o.transition(ctx, t, []string{store.TaskFailed}, store.TaskQueued,
			"retry after failure: "+cause,
			store.TaskField{Column: "attempt", Value: t.Attempt + 1}); err != nil {
			return err
		}
		o.EmitMissionEvent(ctx, t.MissionID, "TASK_RETRY", t.TaskID, map[string]any{
			"attempt": t.Attempt + 1, "max_retries": t.MaxRetries,
		})
		return nil
	}
	if err := o.transition(ctx, t, []string{store.TaskFailed}, store.TaskDead,
		"retries exhausted: "+cause); err != nil {
		return err
	}
	o.EmitMissionEvent(ctx, t.MissionID, "TASK_DEAD", t.TaskID, map[string]any{"error": cause})
	return nil
}

// checkTargetsTouched cross-checks reported touches against the authorized
// target set (doc 01 §10.5). For scope-bound watch tokens the
// "scope:sha256:…" checkpoint form is accepted (Ruling A.4 — the per-probe
// TARGET_TOUCHED records on audit.events remain the authoritative
// cross-check); all other entries are compared to the exact-authorized set.
// Returns "" when clean, else a violation description.
func (o *Orchestrator) checkTargetsTouched(t *store.Task, res *platformv1.TaskResult) string {
	touched := res.GetMetrics().GetTargetsTouched()
	if len(touched) == 0 {
		return ""
	}
	scopeBoundWatch := t.RiskClass == store.RiskR1 &&
		(t.Capability == "monitor.watch" || t.Capability == "monitor.rescan")
	authorized := map[string]bool{}
	for _, target := range t.Targets {
		authorized[scope.Canonicalize(target)] = true
	}
	for _, x := range touched {
		if scopeBoundWatch && strings.HasPrefix(x, "scope:sha256:") {
			continue // checkpoint form (Ruling A.4)
		}
		if !authorized[scope.Canonicalize(x)] {
			return fmt.Sprintf("target %q touched outside authorized set", x)
		}
	}
	return ""
}

// handleScopeViolation applies doc 01 §10.5: SCOPE_VIOLATION audit, agent
// quarantined, mission paused, commander halt signal. Commanders cannot
// override.
func (o *Orchestrator) handleScopeViolation(ctx context.Context, t *store.Task, res *platformv1.TaskResult, violation string) error {
	subj := audit.Subject{MissionID: t.MissionID, TaskID: t.TaskID}
	if err := o.AuditLog(ctx, audit.ScopeViolation, subj, map[string]any{
		"violation":       violation,
		"agent_id":        res.GetAgentId(),
		"targets_touched": anySlice(res.GetMetrics().GetTargetsTouched()),
	}); err != nil {
		o.log.Error("audit SCOPE_VIOLATION", "err", err)
	}
	if err := o.store.SetAgentStatus(ctx, res.GetAgentId(), store.AgentQuarantined); err != nil {
		o.log.Error("quarantine agent", "agent", res.GetAgentId(), "err", err)
	}
	// Mission paused — new dispatches halt (scheduler mission gate).
	if err := o.store.SetMissionState(ctx, t.MissionID, store.MissionPaused,
		store.MissionActive, store.MissionPlannerDegraded); err != nil && err != store.ErrInvalidTransition {
		o.log.Error("pause mission on scope violation", "mission", t.MissionID, "err", err)
	}
	// The violating task is terminal — never retried.
	if !store.TerminalStates[t.State] && t.State == store.TaskReported {
		if err := o.transition(ctx, t, []string{store.TaskReported}, store.TaskKilled, "scope violation"); err != nil {
			o.log.Error("kill violating task", "task", t.TaskID, "err", err)
		}
	}
	o.EmitMissionEvent(ctx, t.MissionID, "SCOPE_VIOLATION", t.TaskID, map[string]any{
		"violation": violation,
		"agent_id":  res.GetAgentId(),
	})
	return nil
}

// maybeRenewWatch enqueues the standing-watch continuation (doc 01 C3 "cron
// for Monitor cadence"; doc 03 §4.3 renewal_requested). The renewal is a new
// task that re-runs the full gated dispatch path (fresh PDP decision +
// fresh scope-bound token).
func (o *Orchestrator) maybeRenewWatch(ctx context.Context, t *store.Task, res *platformv1.TaskResult) {
	if t.Capability != "monitor.watch" || res.GetSummary() == nil {
		return
	}
	if !res.GetSummary().GetFields()["renewal_requested"].GetBoolValue() {
		return
	}
	mission, err := o.store.GetMission(ctx, t.MissionID)
	if err != nil || mission.State != store.MissionActive {
		return
	}
	renewal := &store.Task{
		TaskID:     ids.New("tsk"),
		PlanID:     t.PlanID,
		MissionID:  t.MissionID,
		TaskKey:    t.TaskKey + "#renewal-" + ids.New(""),
		Capability: t.Capability,
		RiskClass:  t.RiskClass,
		Targets:    t.Targets,
		Params:     t.Params,
		DependsOn:  []string{},
		TimeoutS:   t.TimeoutS,
		MaxRetries: t.MaxRetries,
		State:      store.TaskPending,
	}
	if err := o.store.InsertTask(ctx, renewal); err != nil {
		o.log.Error("watch renewal insert", "task", t.TaskID, "err", err)
		return
	}
	if err := o.transition(ctx, renewal, []string{store.TaskPending}, store.TaskValidating, "watch renewal"); err != nil {
		o.log.Error("watch renewal transition", "err", err)
		return
	}
	if err := o.transition(ctx, renewal, []string{store.TaskValidating}, store.TaskQueued, "watch renewal"); err != nil {
		o.log.Error("watch renewal queue", "err", err)
		return
	}
	o.EmitMissionEvent(ctx, t.MissionID, "WATCH_RENEWED", renewal.TaskID, map[string]any{
		"previous_task_id": t.TaskID,
	})
}

func resultStatusName(s platformv1.TaskResultStatus) string {
	switch s {
	case platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED:
		return "SUCCEEDED"
	case platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED:
		return "FAILED"
	case platformv1.TaskResultStatus_TASK_RESULT_STATUS_REJECTED_UNAUTHORIZED:
		return "REJECTED_UNAUTHORIZED"
	case platformv1.TaskResultStatus_TASK_RESULT_STATUS_KILLED:
		return "KILLED"
	case platformv1.TaskResultStatus_TASK_RESULT_STATUS_TIMEOUT:
		return "TIMEOUT"
	}
	return ""
}
