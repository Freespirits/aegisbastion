package orchestrator

import (
	"testing"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// The doc 01 §6.2 happy path and every documented redelivery/failure edge.
func TestStateMachineLegalTransitions(t *testing.T) {
	legal := [][2]string{
		{store.TaskPending, store.TaskValidating},
		{store.TaskValidating, store.TaskQueued},
		{store.TaskValidating, store.TaskRejectedUnauthorized},
		{store.TaskQueued, store.TaskDispatched},
		{store.TaskQueued, store.TaskRejectedUnauthorized}, // dispatch PEP DENY
		{store.TaskQueued, store.TaskExpired},
		{store.TaskQueued, store.TaskCancelled},
		{store.TaskQueued, store.TaskKilled},
		{store.TaskDispatched, store.TaskRunning}, // ACK
		{store.TaskDispatched, store.TaskQueued},  // ack-timeout redelivery
		{store.TaskDispatched, store.TaskKilled},
		{store.TaskRunning, store.TaskReported},
		{store.TaskRunning, store.TaskQueued}, // agent crash redelivery
		{store.TaskRunning, store.TaskFailed},
		{store.TaskRunning, store.TaskKilled}, // kill / timeout
		{store.TaskReported, store.TaskValidated},
		{store.TaskReported, store.TaskFailed},
		{store.TaskReported, store.TaskRejectedUnauthorized}, // SDK guardrail refusal
		{store.TaskReported, store.TaskKilled},               // scope violation
		{store.TaskValidated, store.TaskCompleted},
		{store.TaskFailed, store.TaskQueued}, // retry ≤ max_retries
		{store.TaskFailed, store.TaskDead},
	}
	for _, tr := range legal {
		if !CanTransition(tr[0], tr[1]) {
			t.Errorf("expected %s → %s to be legal", tr[0], tr[1])
		}
	}
}

func TestStateMachineIllegalTransitions(t *testing.T) {
	illegal := [][2]string{
		{store.TaskPending, store.TaskDispatched}, // skipping validation+queue
		{store.TaskPending, store.TaskRunning},
		{store.TaskQueued, store.TaskRunning}, // must dispatch first
		{store.TaskValidating, store.TaskDispatched},
		{store.TaskCompleted, store.TaskQueued},            // terminal
		{store.TaskDead, store.TaskQueued},                 // terminal
		{store.TaskKilled, store.TaskQueued},               // terminal
		{store.TaskCancelled, store.TaskQueued},            // terminal
		{store.TaskRejectedUnauthorized, store.TaskQueued}, // terminal — commander replans instead
		{store.TaskExpired, store.TaskQueued},              // terminal
		{store.TaskDispatched, store.TaskCompleted},        // must ACK + report first
		{store.TaskRunning, store.TaskCompleted},           // must report first
	}
	for _, tr := range illegal {
		if CanTransition(tr[0], tr[1]) {
			t.Errorf("expected %s → %s to be ILLEGAL", tr[0], tr[1])
		}
	}
}

// Terminal states have no outgoing edges at all.
func TestTerminalStatesClosed(t *testing.T) {
	all := []string{
		store.TaskPending, store.TaskValidating, store.TaskQueued, store.TaskDispatched,
		store.TaskRunning, store.TaskReported, store.TaskValidated, store.TaskCompleted,
		store.TaskRejectedUnauthorized, store.TaskExpired, store.TaskFailed, store.TaskDead,
		store.TaskKilled, store.TaskCancelled,
	}
	for terminal := range store.TerminalStates {
		for _, to := range all {
			if CanTransition(terminal, to) {
				t.Errorf("terminal %s must not transition to %s", terminal, to)
			}
		}
	}
}
