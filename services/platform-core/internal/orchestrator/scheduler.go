package orchestrator

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// Run starts every orchestrator loop and blocks until ctx is cancelled:
//
//   - dispatch loop   (Scheduler: QUEUED → gated dispatch, doc 01 §6.3)
//   - reaper          (ack timeout, deadline enforcement, heartbeat TTL,
//     queue TTL, agent-offline redelivery — doc 01 §13)
//   - outbox relay    (bus-outage buffering + replay, doc 01 §13)
//   - bus consumers   (task.result, agent.heartbeat, tasks.revocations.v1)
func (o *Orchestrator) Run(ctx context.Context) {
	o.log.Info("orchestrator starting",
		"scheduler_tick", o.cfg.SchedulerTick, "reaper_tick", o.cfg.ReaperTick)

	go o.loop(ctx, o.cfg.SchedulerTick, o.runDispatchPass)
	go o.loop(ctx, o.cfg.ReaperTick, o.runReaperPass)
	go o.runOutboxRelay(ctx)

	if o.bus != nil {
		go o.consumeResults(ctx)
		go o.consumeRevocations(ctx)
		go o.consumeHeartbeats(ctx)
	} else {
		o.log.Warn("bus unavailable at start — consumers and relay degrade to outbox buffering")
	}

	<-ctx.Done()
	o.log.Info("orchestrator stopped")
}

func (o *Orchestrator) loop(ctx context.Context, tick time.Duration, fn func(context.Context)) {
	t := time.NewTicker(tick)
	defer t.Stop()
	// Run once immediately at startup.
	fn(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fn(ctx)
		}
	}
}

// runDispatchPass picks eligible QUEUED tasks and dispatches them.
func (o *Orchestrator) runDispatchPass(ctx context.Context) {
	tasks, err := o.store.PickQueuedTasks(ctx, 32)
	if err != nil {
		o.log.Error("dispatch pass: pick", "err", err)
		return
	}
	for _, t := range tasks {
		outcome, err := o.dispatchOne(ctx, t)
		if err != nil {
			o.log.Error("dispatch", "task", t.TaskID, "outcome", outcome, "err", err)
			continue
		}
		if outcome == outcomeDispatched {
			o.log.Info("dispatched", "task", t.TaskID, "capability", t.Capability, "risk", t.RiskClass)
		}
	}
}

// runReaperPass enforces the doc 01 §13 failure-mode behaviors.
func (o *Orchestrator) runReaperPass(ctx context.Context) {
	// ACK timeout → redelivery (doc 01 §9 item 3).
	stale, err := o.store.StaleDispatched(ctx, o.cfg.AckTimeout)
	if err != nil {
		o.log.Error("reaper: stale dispatched", "err", err)
	}
	for _, t := range stale {
		o.requeueOrDead(ctx, t, "ack timeout — redelivering")
	}

	// Deadline enforcement → KILLED (doc 01 §6.3).
	expired, err := o.store.ExpiredRunning(ctx)
	if err != nil {
		o.log.Error("reaper: expired running", "err", err)
	}
	for _, t := range expired {
		if err := o.transition(ctx, t, []string{store.TaskRunning}, store.TaskKilled,
			"deadline exceeded (timeout)"); err != nil && err != store.ErrInvalidTransition {
			o.log.Error("reaper: kill expired", "task", t.TaskID, "err", err)
			continue
		}
		o.releaseAllTargetLeases(ctx, t)
		o.EmitMissionEvent(ctx, t.MissionID, "TASK_KILLED", t.TaskID, map[string]any{"reason": "timeout"})
	}

	// Queue TTL → EXPIRED.
	staleQ, err := o.store.StaleQueued(ctx, o.cfg.QueueTTL)
	if err != nil {
		o.log.Error("reaper: stale queued", "err", err)
	}
	for _, t := range staleQ {
		if err := o.transition(ctx, t, []string{store.TaskQueued}, store.TaskExpired,
			"missed dispatch window"); err != nil && err != store.ErrInvalidTransition {
			o.log.Error("reaper: expire", "task", t.TaskID, "err", err)
		}
	}

	// Agent heartbeat TTL → OFFLINE + task redelivery (doc 01 §13).
	offline, err := o.store.MarkStaleAgentsOffline(ctx, o.cfg.AgentHeartbeatTTL)
	if err != nil {
		o.log.Error("reaper: stale agents", "err", err)
	}
	for _, a := range offline {
		o.log.Warn("agent offline (heartbeat TTL)", "agent", a.AgentID)
		tasks, err := o.store.InFlightTasksForAgent(ctx, a.AgentID)
		if err != nil {
			o.log.Error("reaper: agent tasks", "agent", a.AgentID, "err", err)
			continue
		}
		for _, t := range tasks {
			o.requeueOrDead(ctx, t, "agent "+a.AgentID+" offline — redelivering")
		}
	}
}

// requeueOrDead returns a DISPATCHED/RUNNING task to QUEUED (attempt+1) or
// drives it to DEAD when retries are exhausted (doc 01 §6.2/§13).
func (o *Orchestrator) requeueOrDead(ctx context.Context, t *store.Task, reason string) {
	o.releaseAllTargetLeases(ctx, t)
	if t.Attempt >= t.MaxRetries {
		if err := o.transition(ctx, t, []string{t.State}, store.TaskDead, reason+" (retries exhausted)"); err != nil {
			if err != store.ErrInvalidTransition {
				o.log.Error("reaper: dead", "task", t.TaskID, "err", err)
			}
			return
		}
		o.EmitMissionEvent(ctx, t.MissionID, "TASK_DEAD", t.TaskID, map[string]any{"reason": reason})
		return
	}
	if err := o.transition(ctx, t, []string{t.State}, store.TaskQueued, reason,
		store.TaskField{Column: "attempt", Value: t.Attempt + 1}); err != nil {
		if err != store.ErrInvalidTransition {
			o.log.Error("reaper: requeue", "task", t.TaskID, "err", err)
		}
		return
	}
	o.EmitMissionEvent(ctx, t.MissionID, "TASK_REDELIVERED", t.TaskID, map[string]any{
		"attempt": t.Attempt + 1, "reason": reason,
	})
}

// runOutboxRelay publishes pending outbox rows (doc 01 §13 bus-outage
// buffering): rows are written in the same tx as the state change and
// replayed here until the bus accepts them.
func (o *Orchestrator) runOutboxRelay(ctx context.Context) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-o.relayWake:
			o.relayOnce(ctx)
		case <-tick.C:
			o.relayOnce(ctx)
		}
	}
}

func (o *Orchestrator) relayOnce(ctx context.Context) {
	if o.bus == nil {
		return
	}
	msgs, err := o.store.OutboxPending(ctx, 64)
	if err != nil {
		o.log.Error("outbox: pending", "err", err)
		return
	}
	for _, m := range msgs {
		if err := o.bus.PublishEnvelope(m.Subject, m.Payload); err != nil {
			o.log.Warn("outbox: publish failed (will retry)", "subject", m.Subject, "err", err)
			if merr := o.store.OutboxMarkAttempt(ctx, m.ID); merr != nil {
				o.log.Error("outbox: mark attempt", "err", merr)
			}
			continue
		}
		if err := o.store.OutboxMarkPublished(ctx, m.ID); err != nil {
			o.log.Error("outbox: mark published", "err", err)
		}
	}
}

// consumeResults drains task.result (doc 01 §8.1: durable, at-least-once,
// idempotent on task_id).
func (o *Orchestrator) consumeResults(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		sub, err := o.bus.EnsureResultsConsumer()
		if err != nil {
			o.log.Error("results consumer subscribe", "err", err)
			if !sleepCtx(ctx, 3*time.Second) {
				return
			}
			continue
		}
		o.resultsLoop(ctx, sub)
		_ = sub.Unsubscribe()
	}
}

func (o *Orchestrator) resultsLoop(ctx context.Context, sub *nats.Subscription) {
	for {
		msgs, err := sub.Fetch(8, nats.MaxWait(2*time.Second))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			o.log.Error("results fetch", "err", err)
			return
		}
		for _, msg := range msgs {
			if err := o.handleResultMessage(ctx, msg.Data); err != nil {
				o.log.Error("result handling (naks for redelivery)", "err", err)
				_ = msg.Nak()
				continue
			}
			_ = msg.Ack()
		}
	}
}

// handleResultMessage decodes one task.result envelope and applies it.
func (o *Orchestrator) handleResultMessage(ctx context.Context, data []byte) error {
	var env platformv1.Envelope
	if err := proto.Unmarshal(data, &env); err != nil {
		// Poison message — ack and drop (do not retry forever).
		o.log.Error("result envelope decode (dropping)", "err", err)
		return nil
	}
	var res platformv1.TaskResult
	if err := env.GetPayload().UnmarshalTo(&res); err != nil {
		o.log.Error("result payload decode (dropping)", "err", err)
		return nil
	}
	return o.HandleResult(ctx, &res)
}

// consumeRevocations drains tasks.revocations.v1 → kill switch (Ruling C11).
func (o *Orchestrator) consumeRevocations(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}
		sub, err := o.bus.EnsureRevocationsConsumer()
		if err != nil {
			o.log.Error("revocations consumer subscribe", "err", err)
			if !sleepCtx(ctx, 3*time.Second) {
				return
			}
			continue
		}
		o.revocationsLoop(ctx, sub)
		_ = sub.Unsubscribe()
	}
}

func (o *Orchestrator) revocationsLoop(ctx context.Context, sub *nats.Subscription) {
	for {
		msgs, err := sub.Fetch(4, nats.MaxWait(2*time.Second))
		if err != nil {
			if errors.Is(err, nats.ErrTimeout) {
				if ctx.Err() != nil {
					return
				}
				continue
			}
			o.log.Error("revocations fetch", "err", err)
			return
		}
		for _, msg := range msgs {
			if err := o.handleRevocationMessage(ctx, msg.Data); err != nil {
				o.log.Error("revocation handling (naks for redelivery)", "err", err)
				_ = msg.Nak()
				continue
			}
			_ = msg.Ack()
		}
	}
}

// handleRevocationMessage decodes one revocation message and maps it to
// control.kill. Decoding is lenient across producer generations:
// (a) doc 01 §8.2 Envelope with an Any-packed RevocationEvent (canonical),
// (b) a bare RevocationEvent, (c) a bare Revocation.
func (o *Orchestrator) handleRevocationMessage(ctx context.Context, data []byte) error {
	var rev *gatekeeperv1.Revocation
	decoded := false

	// (a) Envelope-wrapped.
	var env platformv1.Envelope
	if err := proto.Unmarshal(data, &env); err == nil && env.GetPayload() != nil {
		var revEv gatekeeperv1.RevocationEvent
		if err := env.GetPayload().UnmarshalTo(&revEv); err == nil && revEv.GetRevocation() != nil {
			rev = revEv.GetRevocation()
			decoded = true
		}
	}
	// (b) bare RevocationEvent.
	if !decoded {
		var revEv gatekeeperv1.RevocationEvent
		if err := proto.Unmarshal(data, &revEv); err == nil && revEv.GetRevocation() != nil {
			rev = revEv.GetRevocation()
			decoded = true
		}
	}
	// (c) bare Revocation.
	if !decoded {
		var r gatekeeperv1.Revocation
		if err := proto.Unmarshal(data, &r); err == nil && r.GetRevocationId() != "" {
			rev = &r
			decoded = true
		}
	}
	if !decoded || rev.GetRevocationId() == "" {
		o.log.Error("revocation undecodable (dropping — poison message)")
		return nil
	}
	o.log.Warn("revocation received", "id", rev.GetRevocationId(),
		"scope", rev.GetScope().String(), "key", rev.GetKey())
	return o.HandleRevocation(ctx, rev)
}

// consumeHeartbeats applies bus heartbeats to the registry (doc 01 §8.1:
// ephemeral, 10 s cadence, 30 s TTL in Registry). The gRPC Heartbeat RPC is
// the primary path; the bus subject exists for bus-native agents.
func (o *Orchestrator) consumeHeartbeats(ctx context.Context) {
	sub, err := o.bus.NC.Subscribe("agent.heartbeat", func(msg *nats.Msg) {
		agentID := string(msg.Data)
		if agentID == "" {
			return
		}
		if _, err := o.store.TouchHeartbeat(ctx, agentID); err != nil {
			o.log.Warn("bus heartbeat from unknown/blocked agent", "agent", agentID)
		}
	})
	if err != nil {
		o.log.Error("heartbeat subscribe", "err", err)
		return
	}
	defer func() { _ = sub.Unsubscribe() }()
	<-ctx.Done()
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
