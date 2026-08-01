package orchestrator

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/structpb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// HandleRevocation maps a gatekeeper RevocationEvent (tasks.revocations.v1)
// to the platform kill switch (doc 01 §8.1 + Ruling C11): engage the DB flag
// the Scheduler checks, broadcast control.kill over CORE NATS (no JetStream
// durable), and drain affected in-flight tasks to KILLED.
func (o *Orchestrator) HandleRevocation(ctx context.Context, rev *gatekeeperv1.Revocation) error {
	if rev == nil {
		return fmt.Errorf("nil revocation")
	}
	scopeName := rev.GetScope().String()
	key := rev.GetKey()
	reason := rev.GetReason()
	if reason == "" {
		reason = "revocation " + rev.GetRevocationId()
	}
	issuedBy := rev.GetIssuedBy()
	if issuedBy == "" {
		issuedBy = "gatekeeper.revocation-service"
	}

	switch rev.GetScope() {
	case gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL:
		if err := o.store.EngageKillSwitch(ctx, store.KillScopeGlobal, "", issuedBy, reason); err != nil {
			return err
		}
		tasks, err := o.store.AllInFlightTasks(ctx)
		if err != nil {
			return err
		}
		if err := o.killTasks(ctx, tasks, "global revocation "+rev.GetRevocationId()); err != nil {
			return err
		}
		if err := o.broadcastKill(ctx, "", bus.KillFields("global", "", rev.GetRevocationId(), reason, nil)); err != nil {
			return err
		}
		return o.AuditLog(ctx, audit.KillSwitch, audit.Subject{}, map[string]any{
			"scope": scopeName, "revocation_id": rev.GetRevocationId(),
			"issued_by": issuedBy, "reason": reason, "tasks_killed": len(tasks),
		})

	case gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE:
		o.InvalidateROE(key)
		missions, err := o.store.ListMissionsByROE(ctx, key)
		if err != nil {
			return err
		}
		total := 0
		for _, missionID := range missions {
			// Per-mission drains do NOT broadcast individually — one
			// roe-scoped control.kill below covers the blast radius.
			n, err := o.killMissionDrain(ctx, missionID,
				"RoE "+key+" revoked: "+reason, issuedBy)
			if err != nil {
				return err
			}
			total += n
		}
		if err := o.broadcastKill(ctx, "", bus.KillFields("roe", key, rev.GetRevocationId(), reason, missions)); err != nil {
			return err
		}
		// ROE_REVOKED mirrors the trigger; KILL_SWITCH records the action.
		if err := o.AuditLog(ctx, audit.ROERevoked, audit.Subject{RoeID: key}, map[string]any{
			"revocation_id": rev.GetRevocationId(), "issued_by": issuedBy, "reason": reason,
		}); err != nil {
			return err
		}
		return o.AuditLog(ctx, audit.KillSwitch, audit.Subject{RoeID: key}, map[string]any{
			"scope": scopeName, "key": key, "revocation_id": rev.GetRevocationId(),
			"missions": anySlice(missions), "tasks_killed": total,
		})

	case gatekeeperv1.RevocationScope_REVOCATION_SCOPE_TARGET:
		tasks, err := o.store.InFlightTasksMatching(ctx, "", key)
		if err != nil {
			return err
		}
		if err := o.killTasks(ctx, tasks, "target "+key+" revoked"); err != nil {
			return err
		}
		if err := o.broadcastKill(ctx, "", bus.KillFields("target", key, rev.GetRevocationId(), reason, nil)); err != nil {
			return err
		}
		return o.AuditLog(ctx, audit.KillSwitch, audit.Subject{}, map[string]any{
			"scope": scopeName, "key": key, "revocation_id": rev.GetRevocationId(),
			"tasks_killed": len(tasks),
		})

	case gatekeeperv1.RevocationScope_REVOCATION_SCOPE_CAPABILITY:
		tasks, err := o.store.InFlightTasksMatching(ctx, key, "")
		if err != nil {
			return err
		}
		if err := o.killTasks(ctx, tasks, "capability "+key+" revoked"); err != nil {
			return err
		}
		if err := o.broadcastKill(ctx, "", bus.KillFields("capability", key, rev.GetRevocationId(), reason, nil)); err != nil {
			return err
		}
		return o.AuditLog(ctx, audit.KillSwitch, audit.Subject{}, map[string]any{
			"scope": scopeName, "key": key, "revocation_id": rev.GetRevocationId(),
			"tasks_killed": len(tasks),
		})
	}
	return fmt.Errorf("unknown revocation scope %s", scopeName)
}

// KillMission engages the per-mission kill switch (Mission API): DB flag,
// mission state, task drain, control.kill broadcast, audit. Returns the
// number of tasks driven to KILLED.
func (o *Orchestrator) KillMission(ctx context.Context, missionID, reason, engagedBy string) (int, error) {
	n, err := o.killMissionDrain(ctx, missionID, reason, engagedBy)
	if err != nil {
		return 0, err
	}
	if err := o.broadcastKill(ctx, missionID,
		bus.KillFields("mission", missionID, "", reason, []string{missionID})); err != nil {
		return 0, err
	}
	return n, nil
}

// killMissionDrain is the shared per-mission drain (flag + state + tasks +
// audit); the caller decides the control.kill broadcast shape (per-mission
// for operator kills, roe-scoped for revocations).
func (o *Orchestrator) killMissionDrain(ctx context.Context, missionID, reason, engagedBy string) (int, error) {
	if err := o.store.EngageKillSwitch(ctx, store.KillScopeMission, missionID, engagedBy, reason); err != nil {
		return 0, err
	}
	// Mission state → KILLED (terminal until operator reactivation, doc 01 §5.1).
	if err := o.store.SetMissionState(ctx, missionID, store.MissionKilled,
		store.MissionDraft, store.MissionActive, store.MissionPaused, store.MissionPlannerDegraded); err != nil && err != store.ErrInvalidTransition {
		return 0, err
	}
	tasks, err := o.store.InFlightTasksForMission(ctx, missionID)
	if err != nil {
		return 0, err
	}
	if err := o.killTasks(ctx, tasks, reason); err != nil {
		return 0, err
	}
	if err := o.AuditLog(ctx, audit.KillSwitch, audit.Subject{MissionID: missionID}, map[string]any{
		"scope": "mission", "reason": reason, "engaged_by": engagedBy, "tasks_killed": len(tasks),
	}); err != nil {
		return 0, err
	}
	o.EmitMissionEvent(ctx, missionID, "MISSION_KILLED", "", map[string]any{"reason": reason})
	return len(tasks), nil
}

// killTasks drives each in-flight task to KILLED and releases its leases.
func (o *Orchestrator) killTasks(ctx context.Context, tasks []*store.Task, reason string) error {
	for _, t := range tasks {
		from := []string{t.State}
		if err := o.transition(ctx, t, from, store.TaskKilled, reason); err != nil {
			if err == store.ErrInvalidTransition {
				continue // raced with a completion — fine
			}
			return err
		}
		o.releaseAllTargetLeases(ctx, t)
		o.EmitMissionEvent(ctx, t.MissionID, "TASK_KILLED", t.TaskID, map[string]any{"reason": reason})
	}
	return nil
}

// broadcastKill publishes the control.kill core-NATS broadcast (doc 01 §8.1:
// NO JetStream durable; agents must ACK within 5 s). When the bus is down
// the DB kill flags still gate the Scheduler and heartbeats carry
// kill_active — the broadcast is the fast path, not the only path.
func (o *Orchestrator) broadcastKill(ctx context.Context, missionID string, fields map[string]any) error {
	if o.bus == nil {
		o.log.Warn("control.kill broadcast skipped — bus unavailable; DB kill flags still engaged")
		return nil
	}
	st, err := structpb.NewStruct(fields)
	if err != nil {
		return err
	}
	env, err := bus.NewEnvelope(missionID, st)
	if err != nil {
		return err
	}
	env.Type = "aegisbastion.platform.v1.ControlKill"
	data, err := bus.MarshalEnvelope(env)
	if err != nil {
		return err
	}
	return o.bus.BroadcastKill(data)
}
