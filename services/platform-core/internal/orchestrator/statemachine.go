// Package orchestrator is the single authority for task state (doc 01 §3.1):
// plan intake + validation, the task state machine (§6.2), the gated dispatch
// path (§6.3), concurrency controls (§6.4), and the kill switch (§10.5).
package orchestrator

import "github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"

// legalTransitions is the doc 01 §6.2 task state machine:
//
//	PENDING → VALIDATING → QUEUED → DISPATCHED → RUNNING → REPORTED → VALIDATED → COMPLETED
//	   │          │           │          │          │          │
//	   │          ▼           │          ▼          ▼          ▼
//	   │     REJECTED_        │       EXPIRED    FAILED ──▶ (retry≤max) ──▶ DEAD
//	   │     UNAUTHORIZED     │          │          │
//	   │                      │          │          └──▶ KILLED (kill switch / RoE revoke / timeout)
//	   └──── CANCELLED (operator) ◀──────┘
//
// DISPATCHED → QUEUED is the ack-timeout redelivery; RUNNING → QUEUED is the
// agent-crash redelivery (§13); FAILED → QUEUED is the bounded retry.
var legalTransitions = map[string][]string{
	store.TaskPending:    {store.TaskValidating, store.TaskCancelled, store.TaskKilled},
	store.TaskValidating: {store.TaskQueued, store.TaskRejectedUnauthorized, store.TaskCancelled, store.TaskKilled},
	store.TaskQueued:     {store.TaskDispatched, store.TaskRejectedUnauthorized, store.TaskCancelled, store.TaskExpired, store.TaskKilled},
	store.TaskDispatched: {store.TaskRunning, store.TaskQueued, store.TaskReported, store.TaskKilled, store.TaskCancelled},
	store.TaskRunning:    {store.TaskReported, store.TaskQueued, store.TaskFailed, store.TaskKilled},
	store.TaskReported:   {store.TaskValidated, store.TaskFailed, store.TaskRejectedUnauthorized, store.TaskKilled},
	store.TaskValidated:  {store.TaskCompleted, store.TaskKilled},
	store.TaskFailed:     {store.TaskQueued, store.TaskDead, store.TaskKilled},
	// Terminal states have no outgoing transitions.
	store.TaskCompleted:            {},
	store.TaskRejectedUnauthorized: {},
	store.TaskExpired:              {},
	store.TaskDead:                 {},
	store.TaskKilled:               {},
	store.TaskCancelled:            {},
}

// CanTransition reports whether from→to is legal in the state machine.
func CanTransition(from, to string) bool {
	for _, t := range legalTransitions[from] {
		if t == to {
			return true
		}
	}
	return false
}
