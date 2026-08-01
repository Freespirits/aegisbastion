// Package app is the HexStrike MCP adapter core: it fronts the local
// HexStrike AI installation as a platform commander (doc 01 §4.1, §7.1).
//
// The adapter is a PLANNER, NOT AN AUTHORIZER. It submits TaskPlans to the
// Orchestrator's PlannerService and may only translate a task into a
// HexStrike tool call after the Orchestrator's PlanVerdict accepted that
// task. Accepted tasks live in the Ledger; execute_approved_task consults
// nothing else. Authorization for real dispatch stays with the Orchestrator
// dispatch PEP and the gatekeeper PDP (Ruling B) — this adapter never sees,
// mints, or verifies a Scope Token.
package app

import (
	"sync"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// Ledger records, per submitted plan, which tasks the Orchestrator accepted.
// It is the adapter's only "authorization" input: an entry exists only for
// tasks the PlannerService verdict marked accepted.
//
// MVP note: the ledger is in-memory. Doc 01 §4.3 makes commanders stateless
// planners; the ledger is a correlation cache, not state of record — a
// restart simply means execute_approved_task must be preceded by a fresh
// submit_task_plan, which is the normal flow anyway.
type Ledger struct {
	mu    sync.Mutex
	plans map[string]*planEntry // plan_id → entry
}

type planEntry struct {
	decision platformv1.PlanDecision
	tasks    map[string]*taskEntry // task_key → entry
}

type taskEntry struct {
	spec     *platformv1.TaskSpec
	accepted bool
	reason   string
}

// NewLedger returns an empty ledger.
func NewLedger() *Ledger {
	return &Ledger{plans: map[string]*planEntry{}}
}

// Record stores the verdict for one submitted plan.
func (l *Ledger) Record(plan *platformv1.TaskPlan, resp *platformv1.SubmitTaskPlanResponse) {
	entry := &planEntry{decision: resp.GetDecision(), tasks: map[string]*taskEntry{}}
	specs := map[string]*platformv1.TaskSpec{}
	for _, t := range plan.GetTasks() {
		specs[t.GetTaskKey()] = t
	}
	for _, v := range resp.GetTaskVerdicts() {
		spec := specs[v.GetTaskKey()]
		if spec == nil {
			continue // verdict for an unknown task_key: ignore defensively
		}
		entry.tasks[v.GetTaskKey()] = &taskEntry{
			spec:     spec,
			accepted: v.GetAccepted(),
			reason:   v.GetReason(),
		}
	}
	l.mu.Lock()
	l.plans[plan.GetPlanId()] = entry
	l.mu.Unlock()
}

// Approved returns the TaskSpec for planID/taskKey only when the Orchestrator
// accepted it. The second return value explains the refusal otherwise.
func (l *Ledger) Approved(planID, taskKey string) (*platformv1.TaskSpec, string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	plan, ok := l.plans[planID]
	if !ok {
		return nil, "unknown plan_id (submit the plan first; the adapter ledger is in-memory)", false
	}
	task, ok := plan.tasks[taskKey]
	if !ok {
		return nil, "unknown task_key in plan " + planID, false
	}
	if !task.accepted {
		reason := task.reason
		if reason == "" {
			reason = "no reason given"
		}
		return nil, "task was NOT accepted by the Orchestrator (" + reason +
			"); the adapter is a planner, not an authorizer — refusing to execute", false
	}
	return task.spec, "", true
}
