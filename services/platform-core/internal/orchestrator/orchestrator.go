package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/config"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/gatekeeper"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/leases"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/pep"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// Orchestrator wires the dispatch path together (doc 01 C2/C3).
type Orchestrator struct {
	cfg    *config.Config
	store  *store.Store
	pep    *pep.PEP
	roes   gatekeeper.ROEStore
	leases leases.Store // nil → R2/R3 dispatches defer (fail-safe)
	bus    *bus.Bus     // nil tolerated (publishes buffer in the outbox)
	audit  *audit.Logger
	log    *slog.Logger

	assignments *assignmentBroker
	events      *missionEventBroker

	roeMu     sync.Mutex
	roeCache  map[string]*roeEntry
	relayWake chan struct{}
}

type roeEntry struct {
	roe       *roeRecord
	fetchedAt time.Time
}

// New builds the Orchestrator.
func New(cfg *config.Config, st *store.Store, p *pep.PEP, roes gatekeeper.ROEStore, ls leases.Store, b *bus.Bus, al *audit.Logger, log *slog.Logger) *Orchestrator {
	if log == nil {
		log = slog.Default()
	}
	return &Orchestrator{
		cfg:         cfg,
		store:       st,
		pep:         p,
		roes:        roes,
		leases:      ls,
		bus:         b,
		audit:       al,
		log:         log,
		assignments: newAssignmentBroker(),
		events:      newMissionEventBroker(),
		roeCache:    map[string]*roeEntry{},
		relayWake:   make(chan struct{}, 1),
	}
}

// actor is the audit actor for orchestrator-driven events.
func (o *Orchestrator) actor() audit.Actor {
	return audit.Actor{Kind: "service", ID: o.cfg.InstanceID}
}

// AuditLog appends to the chain, tolerating the configured spill behavior
// (doc 01 §13). Returns nil when the event is durable (chained OR spilled).
func (o *Orchestrator) AuditLog(ctx context.Context, typ audit.EventType, subj audit.Subject, payload map[string]any) error {
	err := o.audit.Log(ctx, typ, o.actor(), subj, payload)
	if err == nil {
		return nil
	}
	var spilled *audit.SpilledError
	if errors.As(err, &spilled) {
		o.log.Warn("audit event spilled to file", "event_id", spilled.Event.EventID, "cause", spilled.Cause)
		return nil
	}
	return err
}

// ROE fetches (60 s cached) the mission's pinned RoE version from gatekeeper.
// Plan validation is fail-closed on error (doc 01 §10.1).
func (o *Orchestrator) ROE(ctx context.Context, m *store.Mission) (*roeRecord, error) {
	key := fmt.Sprintf("%s@%d", m.RoeID, m.RoeVersion)
	o.roeMu.Lock()
	if e, ok := o.roeCache[key]; ok && time.Since(e.fetchedAt) < time.Minute {
		roe := e.roe
		o.roeMu.Unlock()
		return roe, nil
	}
	o.roeMu.Unlock()

	if o.roes == nil {
		return nil, fmt.Errorf("gatekeeper RoE client not configured — fail-closed")
	}
	rec, err := o.roes.GetROE(ctx, m.RoeID, uint64(m.RoeVersion))
	if err != nil {
		return nil, fmt.Errorf("roe-service.GetROE: %w", err)
	}
	roe := roeFromProto(rec)
	o.roeMu.Lock()
	o.roeCache[key] = &roeEntry{roe: roe, fetchedAt: time.Now()}
	o.roeMu.Unlock()
	return roe, nil
}

// InvalidateROE drops cached RoE state (revocation handling).
func (o *Orchestrator) InvalidateROE(roeID string) {
	o.roeMu.Lock()
	defer o.roeMu.Unlock()
	for k := range o.roeCache {
		if len(k) > len(roeID) && k[:len(roeID)] == roeID {
			delete(o.roeCache, k)
		}
	}
}

// EmitMissionEvent records a mission.events item (durable via outbox +
// in-process broker for StreamMissionEvents subscribers). Best-effort:
// failures are logged, not fatal to the state transition that triggered it.
func (o *Orchestrator) EmitMissionEvent(ctx context.Context, missionID, kind, taskID string, detail map[string]any) {
	ev := &platformv1.MissionEvent{
		EventId:   ids.New("evt"),
		MissionId: missionID,
		Kind:      kind,
		TaskId:    taskID,
		Ts:        timestamppb.Now(),
	}
	if detail != nil {
		if s, err := structpb.NewStruct(detail); err == nil {
			ev.Detail = s
		}
	}
	o.events.publish(missionID, ev)

	if o.bus == nil {
		return
	}
	env, err := bus.NewEnvelope(missionID, ev)
	if err != nil {
		o.log.Error("mission event envelope", "err", err)
		return
	}
	data, err := bus.MarshalEnvelope(env)
	if err != nil {
		o.log.Error("mission event marshal", "err", err)
		return
	}
	tx, err := o.store.Pool.Begin(ctx)
	if err != nil {
		o.log.Error("mission event outbox tx", "err", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := store.OutboxAdd(ctx, tx, env.EventId, bus.SubjectMissionEvents, data, ""); err != nil {
		o.log.Error("mission event outbox add", "err", err)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		o.log.Error("mission event outbox commit", "err", err)
		return
	}
	o.wakeRelay()
}

func (o *Orchestrator) wakeRelay() {
	select {
	case o.relayWake <- struct{}{}:
	default:
	}
}

// SubscribeAssignments is used by AgentService.StreamTasks.
func (o *Orchestrator) SubscribeAssignments(agentID string) (<-chan *platformv1.TaskAssignment, func()) {
	return o.assignments.subscribe(agentID)
}

// SubscribeMissionEvents is used by PlannerService.StreamMissionEvents and
// the in-process echo planner.
func (o *Orchestrator) SubscribeMissionEvents(missionID string) (<-chan *platformv1.MissionEvent, func()) {
	return o.events.subscribe(missionID)
}

// detailStruct marshals a small map to json for verdict persistence.
func detailJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return b
}
