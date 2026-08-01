package orchestrator

import (
	"sync"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// assignmentBroker fans dispatched assignments out to in-process
// AgentService.StreamTasks subscribers (doc 01 §8.3: same TaskAssignment
// payload over bus or stream; the Orchestrator abstracts the transport).
// The durable path is the bus (outbox → task.assign.{agent}); the broker is
// the low-latency in-process path.
type assignmentBroker struct {
	mu   sync.Mutex
	subs map[string]map[chan *platformv1.TaskAssignment]struct{}
}

func newAssignmentBroker() *assignmentBroker {
	return &assignmentBroker{subs: map[string]map[chan *platformv1.TaskAssignment]struct{}{}}
}

// subscribe registers a buffered channel for an agent; call the returned
// function to unsubscribe.
func (b *assignmentBroker) subscribe(agentID string) (<-chan *platformv1.TaskAssignment, func()) {
	ch := make(chan *platformv1.TaskAssignment, 64)
	b.mu.Lock()
	if b.subs[agentID] == nil {
		b.subs[agentID] = map[chan *platformv1.TaskAssignment]struct{}{}
	}
	b.subs[agentID][ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs[agentID], ch)
		if len(b.subs[agentID]) == 0 {
			delete(b.subs, agentID)
		}
		b.mu.Unlock()
		close(ch)
	}
}

// publish delivers to all current subscribers (non-blocking; slow consumers
// still get the assignment via the durable bus path).
func (b *assignmentBroker) publish(agentID string, a *platformv1.TaskAssignment) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[agentID] {
		select {
		case ch <- a:
		default:
		}
	}
}

// missionEventBroker fans mission events out to PlannerService
// .StreamMissionEvents subscribers and in-process consumers (echo planner).
type missionEventBroker struct {
	mu   sync.Mutex
	subs map[string]map[chan *platformv1.MissionEvent]struct{}
}

func newMissionEventBroker() *missionEventBroker {
	return &missionEventBroker{subs: map[string]map[chan *platformv1.MissionEvent]struct{}{}}
}

func (b *missionEventBroker) subscribe(missionID string) (<-chan *platformv1.MissionEvent, func()) {
	ch := make(chan *platformv1.MissionEvent, 128)
	b.mu.Lock()
	if b.subs[missionID] == nil {
		b.subs[missionID] = map[chan *platformv1.MissionEvent]struct{}{}
	}
	b.subs[missionID][ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs[missionID], ch)
		if len(b.subs[missionID]) == 0 {
			delete(b.subs, missionID)
		}
		b.mu.Unlock()
		close(ch)
	}
}

func (b *missionEventBroker) publish(missionID string, ev *platformv1.MissionEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for ch := range b.subs[missionID] {
		select {
		case ch <- ev:
		default:
		}
	}
}
