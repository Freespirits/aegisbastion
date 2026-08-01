// Package lifecycle implements the findings lifecycle state machine of
// doc 04 §7.3 — the dp.findings.state enum of record (Ruling C4: states are
// proposed by Detect in FindingReport.status but PERSISTED by the data
// platform, module 09):
//
//	new ──▶ triaged ──▶ validating ──▶ confirmed_open ──▶ remediation_claimed ──▶ verified_closed
//	                      │                 │                        │
//	                      ▼                 ▼                        ▼
//	                false_positive     accepted_risk            reopened ──▶ confirmed_open
//
// Every persisted state change is validated against these edges and recorded
// in dp.finding_state_transitions.
package lifecycle

import "fmt"

// State is a findings lifecycle state (doc 04 §7.3; matches the CHECK
// constraint on dp.findings.state in db/migrations/000003).
type State string

const (
	New                State = "new"
	Triaged            State = "triaged"
	Validating         State = "validating"
	ConfirmedOpen      State = "confirmed_open"
	RemediationClaimed State = "remediation_claimed"
	VerifiedClosed     State = "verified_closed"
	FalsePositive      State = "false_positive"
	AcceptedRisk       State = "accepted_risk"
	Reopened           State = "reopened"
)

// All lists every valid state (used for payload validation).
var All = []State{
	New, Triaged, Validating, ConfirmedOpen, RemediationClaimed,
	VerifiedClosed, FalsePositive, AcceptedRisk, Reopened,
}

// edges is the doc 04 §7.3 transition graph (directed).
var edges = map[State][]State{
	New:                {Triaged},
	Triaged:            {Validating, FalsePositive},
	Validating:         {ConfirmedOpen, AcceptedRisk},
	ConfirmedOpen:      {RemediationClaimed},
	RemediationClaimed: {VerifiedClosed, Reopened},
	Reopened:           {ConfirmedOpen},
	// Terminal states have no outgoing edges.
	VerifiedClosed: {},
	FalsePositive:  {},
	AcceptedRisk:   {},
}

// Parse validates a raw state string.
func Parse(s string) (State, error) {
	st := State(s)
	for _, v := range All {
		if st == v {
			return st, nil
		}
	}
	return "", fmt.Errorf("lifecycle: unknown state %q (want one of new|triaged|validating|confirmed_open|remediation_claimed|verified_closed|false_positive|accepted_risk|reopened)", s)
}

// Legal reports whether from→to is a direct edge of the state machine.
// A self-transition (from == to) is NOT an edge; callers treat it as a no-op.
func Legal(from, to State) bool {
	for _, n := range edges[from] {
		if n == to {
			return true
		}
	}
	return false
}

// Terminal reports whether s is a state the machine never leaves
// (retention's "resolved findings" class, doc 09 §10).
func Terminal(s State) bool {
	switch s {
	case VerifiedClosed, FalsePositive, AcceptedRisk:
		return true
	}
	return false
}

// Path finds the shortest legal hop sequence from→to (BFS), exclusive of
// from, inclusive of to. ok=false when no path exists.
func Path(from, to State) ([]State, bool) {
	if from == to {
		return nil, true
	}
	type node struct {
		s    State
		path []State
	}
	queue := []node{{from, nil}}
	seen := map[State]bool{from: true}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		for _, next := range edges[cur.s] {
			if seen[next] {
				continue
			}
			p := append(append([]State{}, cur.path...), next)
			if next == to {
				return p, true
			}
			seen[next] = true
			queue = append(queue, node{next, p})
		}
	}
	return nil, false
}
