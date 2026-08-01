package orchestrator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/gatekeeper"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/pep"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

// ===========================================================================
// Doc 01 §15 ACCEPTANCE TEST 1: with gatekeeper stopped/unreachable, ZERO
// R1+ dispatches occur and EVERY attempt appears in the audit log.
// Uses a REAL gRPC client dialed to a dead address (not a stub).
// ===========================================================================
func TestAcceptance_GatekeeperDown_ZeroR1Dispatches_AllAttemptsAudited(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	// R3-ceiling sandboxed agent so every task reaches the dispatch PEP.
	e.seedAgent(t, "detect", "detect.scan", store.RiskR3, 4, true)

	r1Task := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR1, []string{"api.acme.com"}, 0)
	r2Task := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR2, []string{"db.acme.com"}, 0)
	r3Task := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR3, []string{"api.acme.com"}, 0)

	// The REAL gatekeeper client pointed at a dead port — gatekeeper stopped.
	gk, err := gatekeeper.Dial(ctx, "127.0.0.1:1", e.cfg.GatekeeperDialTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer gk.Close()
	o := e.orchestrator(pep.New(gk, gk, "itest"), gk)

	const attempts = 3
	for i := 0; i < attempts; i++ {
		for _, task := range []*store.Task{r1Task, r2Task, r3Task} {
			fresh := e.task(t, task.TaskID)
			outcome, err := o.dispatchOne(ctx, fresh)
			if err != nil {
				t.Fatalf("dispatch attempt %d for %s: %v", i, task.TaskID, err)
			}
			if outcome == outcomeDispatched {
				t.Fatalf("INVARIANT VIOLATED: %s dispatched (risk %s) with gatekeeper down",
					task.TaskID, task.RiskClass)
			}
		}
	}

	// Zero dispatches: every task is still QUEUED, nothing in task.assign.*.
	for _, task := range []*store.Task{r1Task, r2Task, r3Task} {
		if st := e.task(t, task.TaskID).State; st != store.TaskQueued {
			t.Errorf("task %s state = %s, want QUEUED (fail-closed)", task.TaskID, st)
		}
	}
	if rows := e.outboxFor(t, bus.SubjectTaskAssignPrefix+"%"); len(rows) != 0 {
		t.Errorf("found %d task.assign publishes — must be zero with gatekeeper down", len(rows))
	}

	// EVERY attempt audited: 3 attempts × 3 tasks AUTHZ_DECISION/UNAVAILABLE.
	for _, task := range []*store.Task{r1Task, r2Task, r3Task} {
		events := e.auditForTask(t, task.TaskID, string(audit.AuthzDecision))
		if len(events) != attempts {
			t.Fatalf("task %s: %d AUTHZ_DECISION events, want %d (every attempt audited)",
				task.TaskID, len(events), attempts)
		}
		for _, ev := range events {
			if ev["decision"] != "UNAVAILABLE" {
				t.Errorf("task %s: audit decision = %v, want UNAVAILABLE", task.TaskID, ev["decision"])
			}
		}
	}

	// The audit chain itself is intact and append-only.
	bad, err := e.al.VerifyChain(ctx)
	if err != nil || bad != 0 {
		t.Fatalf("audit chain: bad seq %d err %v", bad, err)
	}
	if _, err := e.st.Pool.Exec(ctx,
		`UPDATE platform.audit_events SET payload = '{}' WHERE seq = 1`); err == nil {
		t.Fatal("audit_events must reject UPDATE (append-only trigger)")
	}
}

// Failure-posture corollary (doc 01 §13): R0 tasks CONTINUE when gatekeeper
// is down — only R1+ halts.
func TestAcceptance_GatekeeperDown_R0StillDispatches(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	agent := e.seedAgent(t, "monitor", "monitor.feed.sync", store.RiskR0, 4, false)
	r0Task := e.seedQueuedTask(t, m, p, "monitor.feed.sync", store.RiskR0, nil, 0)

	gk, err := gatekeeper.Dial(ctx, "127.0.0.1:1", e.cfg.GatekeeperDialTimeout)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer gk.Close()
	o := e.orchestrator(pep.New(gk, gk, "itest"), gk)

	outcome, err := o.dispatchOne(ctx, e.task(t, r0Task.TaskID))
	if err != nil {
		t.Fatalf("dispatch R0: %v", err)
	}
	if outcome != outcomeDispatched {
		t.Fatalf("R0 task must dispatch with gatekeeper down (doc 01 §13), got %s", outcome)
	}
	fresh := e.task(t, r0Task.TaskID)
	if fresh.State != store.TaskDispatched || fresh.AssignedAgentID != agent.AgentID {
		t.Fatalf("R0 task state=%s agent=%s", fresh.State, fresh.AssignedAgentID)
	}
	if fresh.DecisionID != "" || fresh.AuthorizationTokenJTI != "" {
		t.Fatal("R0 must carry no decision record and no token (doc 11 §1)")
	}
	// But every dispatch is still audited.
	if events := e.auditForTask(t, r0Task.TaskID, string(audit.TaskDispatched)); len(events) != 1 {
		t.Fatalf("R0 dispatch must be audited, found %d", len(events))
	}
}

// ===========================================================================
// Happy path: ALLOW → token minted → decision record linked → dispatched.
// ===========================================================================
func TestDispatch_HappyPath_R1_AllowMintsAndLinks(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	agent := e.seedAgent(t, "monitor", "monitor.rescan", store.RiskR1, 4, false)
	task := e.seedQueuedTask(t, m, p, "monitor.rescan", store.RiskR1, []string{"api.acme.com"}, 0)

	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), allowROE())
	outcome, err := o.dispatchOne(ctx, e.task(t, task.TaskID))
	if err != nil || outcome != outcomeDispatched {
		t.Fatalf("dispatch: outcome=%s err=%v", outcome, err)
	}

	fresh := e.task(t, task.TaskID)
	if fresh.State != store.TaskDispatched {
		t.Fatalf("state = %s", fresh.State)
	}
	if fresh.DecisionID == "" || fresh.AuthorizationTokenJTI == "" {
		t.Fatal("decision record + token jti must be linked on the task (doc 01 §1 invariant)")
	}
	if fresh.AssignedAgentID != agent.AgentID || fresh.Deadline == nil {
		t.Fatal("assignment fields incomplete")
	}

	// AUTHZ_DECISION (ALLOW) + TASK_DISPATCHED, in that order, in the chain.
	authz := e.auditForTask(t, task.TaskID, string(audit.AuthzDecision))
	if len(authz) != 1 || authz[0]["decision"] != "ALLOW" {
		t.Fatalf("AUTHZ_DECISION ALLOW missing: %v", authz)
	}
	if authz[0]["scope_bound"] != true {
		t.Fatal("monitor.rescan R1 must mint the scope-bound watch token (Ruling A)")
	}
	if events := e.auditForTask(t, task.TaskID, string(audit.TaskDispatched)); len(events) != 1 {
		t.Fatal("TASK_DISPATCHED audit missing")
	}

	// The assignment is buffered in the outbox for task.assign.{agent}.
	rows := e.outboxFor(t, bus.SubjectTaskAssignPrefix+agent.AgentID)
	if len(rows) != 1 {
		t.Fatalf("expected 1 outbox row, got %d", len(rows))
	}
	var env platformv1.Envelope
	if err := proto.Unmarshal(rows[0], &env); err != nil {
		t.Fatalf("envelope decode: %v", err)
	}
	var assignment platformv1.TaskAssignment
	if err := env.GetPayload().UnmarshalTo(&assignment); err != nil {
		t.Fatalf("assignment decode: %v", err)
	}
	if assignment.GetAuthorizationToken() == "" {
		t.Fatal("assignment must carry the minted Scope Token")
	}
	if assignment.GetTaskId() != task.TaskID || assignment.GetPlanId() != p.PlanID {
		t.Fatal("assignment ids mismatch")
	}
}

// DENY → task stripped as REJECTED_UNAUTHORIZED, decision audited, replan
// signal emitted. No dispatch.
func TestDispatch_DenyPath(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	e.seedAgent(t, "detect", "detect.scan", store.RiskR2, 4, false)
	task := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR1, []string{"status.acme.com"}, 0)

	deny := allowDecision()
	deny.Decision = gatekeeperv1.Decision_DECISION_DENY
	deny.Reasons = []*gatekeeperv1.Reason{{
		Code:   gatekeeperv1.DenyReason_DENY_REASON_TARGET_EXCLUDED,
		Detail: "status.acme.com excluded",
	}}
	o := e.orchestrator(pep.New(&fakePDP{decision: deny}, &fakeMinter{}, "itest"), allowROE())

	outcome, err := o.dispatchOne(ctx, e.task(t, task.TaskID))
	if err != nil || outcome != outcomeDenied {
		t.Fatalf("outcome=%s err=%v", outcome, err)
	}
	fresh := e.task(t, task.TaskID)
	if fresh.State != store.TaskRejectedUnauthorized {
		t.Fatalf("state = %s, want REJECTED_UNAUTHORIZED", fresh.State)
	}
	if !strings.Contains(fresh.RejectionReason, "TARGET_EXCLUDED") {
		t.Fatalf("rejection reason = %q", fresh.RejectionReason)
	}
	authz := e.auditForTask(t, task.TaskID, string(audit.AuthzDecision))
	if len(authz) != 1 || authz[0]["decision"] != "DENY" || authz[0]["decision_id"] != deny.DecisionId {
		t.Fatalf("DENY decision not audited: %v", authz)
	}
	if rows := e.outboxFor(t, bus.SubjectTaskAssignPrefix+"%"); len(rows) != 0 {
		t.Fatal("DENY must never publish an assignment")
	}
	// Replan signal for the commander on mission.events.
	if rows := e.outboxFor(t, bus.SubjectMissionEvents); len(rows) == 0 {
		t.Fatal("commander replan signal (mission.events) missing")
	}
}

// ===========================================================================
// Doc 01 §6.4 + Ruling C12: per-target intrusive lease mutual exclusion
// against the REAL NATS KV bucket.
// ===========================================================================
func TestLeaseMutualExclusion_R2_SerializesSameTarget(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	agent := e.seedAgent(t, "detect", "detect.scan", store.RiskR2, 8, false)
	target := "db.acme.com"
	t1 := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR2, []string{target}, 0)
	t2 := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR2, []string{target}, 0)

	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), allowROE())

	// First intrusive task takes the lease and dispatches.
	if outcome, err := o.dispatchOne(ctx, e.task(t, t1.TaskID)); err != nil || outcome != outcomeDispatched {
		t.Fatalf("t1 dispatch: %s %v", outcome, err)
	}
	// Second task on the SAME target is serialized (deferred, lease held).
	if outcome, err := o.dispatchOne(ctx, e.task(t, t2.TaskID)); err != nil || outcome != outcomeDeferred {
		t.Fatalf("t2 must defer while lease held: %s %v", outcome, err)
	}
	if st := e.task(t, t2.TaskID).State; st != store.TaskQueued {
		t.Fatalf("t2 state = %s, want QUEUED", st)
	}
	holder, err := e.ls.Holder(ctx, target)
	if err != nil || holder != t1.TaskID {
		t.Fatalf("KV lease holder = %q err %v, want t1", holder, err)
	}

	// t1 finishes → lease released → t2 dispatches.
	res := &platformv1.TaskResult{
		TaskId: t1.TaskID, AgentId: agent.AgentID,
		Status:    platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED,
		StartedAt: timestamppb.Now(), FinishedAt: timestamppb.Now(),
		Metrics: &platformv1.TaskResultMetrics{TargetsTouched: []string{target}},
	}
	if err := o.HandleResult(ctx, res); err != nil {
		t.Fatalf("t1 result: %v", err)
	}
	if st := e.task(t, t1.TaskID).State; st != store.TaskCompleted {
		t.Fatalf("t1 state = %s, want COMPLETED", st)
	}
	if holder, _ := e.ls.Holder(ctx, target); holder != "" {
		t.Fatalf("lease must be released after t1 completed, holder=%q", holder)
	}
	if outcome, err := o.dispatchOne(ctx, e.task(t, t2.TaskID)); err != nil || outcome != outcomeDispatched {
		t.Fatalf("t2 must dispatch after lease release: %s %v", outcome, err)
	}
}

// Per-RoE intrusive concurrency bucket (doc 01 §6.4): cap=1 → second
// intrusive task defers even on a different target.
func TestRateBucket_PerRoEIntrusiveConcurrency(t *testing.T) {
	e := itSetup(t)
	e.cfg.DefaultMaxConcurrentIntrusive = 1
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	e.seedAgent(t, "detect", "detect.scan", store.RiskR2, 8, false)
	t1 := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR2, []string{"a.acme.com"}, 0)
	t2 := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR2, []string{"b.acme.com"}, 0)

	// RoE stub without a rate cap → platform default (1) applies.
	roe := allowROE()
	roe.roe.Constraints.RateCaps = nil
	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), roe)

	if outcome, err := o.dispatchOne(ctx, e.task(t, t1.TaskID)); err != nil || outcome != outcomeDispatched {
		t.Fatalf("t1: %s %v", outcome, err)
	}
	if outcome, err := o.dispatchOne(ctx, e.task(t, t2.TaskID)); err != nil || outcome != outcomeDeferred {
		t.Fatalf("t2 must defer on the concurrency bucket: %s %v", outcome, err)
	}
	// The deferred task's lease attempt must not leak: its target is free.
	if holder, _ := e.ls.Holder(ctx, "b.acme.com"); holder != "" {
		t.Fatalf("deferred task leaked a lease on b.acme.com (holder=%q)", holder)
	}
}

// ===========================================================================
// Kill-switch mapping (doc 01 §8.1 + Ruling C11): gatekeeper
// tasks.revocations.v1 → DB flags + control.kill CORE-NATS broadcast +
// in-flight drain. control.kill has NO JetStream durable.
// ===========================================================================
func TestKillSwitchMapping_ROERevocation(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	agent := e.seedAgent(t, "detect", "detect.scan", store.RiskR2, 4, false)
	task := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR2, []string{"db.acme.com"}, 0)

	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), allowROE())
	if outcome, err := o.dispatchOne(ctx, e.task(t, task.TaskID)); err != nil || outcome != outcomeDispatched {
		t.Fatalf("dispatch: %s %v", outcome, err)
	}
	// Agent ACKs → RUNNING.
	if err := e.st.Transition(ctx, task.TaskID, []string{store.TaskDispatched}, store.TaskRunning, agent.AgentID, "ack"); err != nil {
		t.Fatalf("ack: %v", err)
	}

	// Watch the CORE NATS control.kill subject (no JetStream durable).
	killCh := make(chan []byte, 4)
	sub, err := e.b.NC.Subscribe(bus.SubjectControlKill, func(msg *nats.Msg) {
		killCh <- msg.Data
	})
	if err != nil {
		t.Fatalf("subscribe control.kill: %v", err)
	}
	defer sub.Unsubscribe()
	if err := e.b.NC.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}

	// Gatekeeper revokes the RoE (tasks.revocations.v1).
	rev := &gatekeeperv1.Revocation{
		RevocationId: "rev_itest_1",
		Scope:        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE,
		Key:          m.RoeID,
		IssuedBy:     "op_itest",
		Reason:       "test revocation",
	}
	if err := o.HandleRevocation(ctx, rev); err != nil {
		t.Fatalf("HandleRevocation: %v", err)
	}

	// 1. control.kill broadcast received on CORE NATS, scoped to the RoE +
	//    mapped mission.
	select {
	case data := <-killCh:
		var env platformv1.Envelope
		if err := proto.Unmarshal(data, &env); err != nil {
			t.Fatalf("kill envelope decode: %v", err)
		}
		if env.GetType() != "aegisbastion.platform.v1.ControlKill" {
			t.Fatalf("kill envelope type = %q", env.GetType())
		}
		var payload structpb.Struct
		if err := env.GetPayload().UnmarshalTo(&payload); err != nil {
			t.Fatalf("kill payload decode: %v", err)
		}
		fields := payload.GetFields()
		if fields["scope"].GetStringValue() != "roe" || fields["key"].GetStringValue() != m.RoeID {
			t.Fatalf("kill payload = %v", fields)
		}
		if fields["mission_ids"].GetListValue().GetValues()[0].GetStringValue() != m.MissionID {
			t.Fatalf("kill payload mission_ids = %v", fields["mission_ids"])
		}
	case <-time.After(3 * time.Second):
		t.Fatal("control.kill broadcast not received within 3s (5s SLA is tighter than this)")
	}

	// 2. DB kill flag engaged (Scheduler gate).
	kills, err := e.st.KillSwitchesEngaged(ctx)
	if err != nil || !kills[store.KillScopeMission+"/"+m.MissionID] {
		t.Fatalf("mission kill flag not engaged: %v", kills)
	}

	// 3. Mission KILLED; the in-flight task drained to KILLED; lease released.
	if mm, _ := e.st.GetMission(ctx, m.MissionID); mm.State != store.MissionKilled {
		t.Fatalf("mission state = %s, want KILLED", mm.State)
	}
	if st := e.task(t, task.TaskID).State; st != store.TaskKilled {
		t.Fatalf("task state = %s, want KILLED", st)
	}
	if holder, _ := e.ls.Holder(ctx, "db.acme.com"); holder != "" {
		t.Fatalf("lease must be released on kill, holder=%q", holder)
	}

	// 4. Audited: ROE_REVOKED + KILL_SWITCH.
	if _, err := e.st.Pool.Exec(ctx, `SELECT 1 FROM platform.audit_events WHERE type = 'ROE_REVOKED' LIMIT 1`); err != nil {
		// Exec with no rows is fine — check via query below instead.
	}
	var n int
	if err := e.st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM platform.audit_events WHERE type IN ('ROE_REVOKED','KILL_SWITCH')`).Scan(&n); err != nil || n < 2 {
		t.Fatalf("ROE_REVOKED + KILL_SWITCH audit events missing (n=%d, err=%v)", n, err)
	}
	bad, err := e.al.VerifyChain(ctx)
	if err != nil || bad != 0 {
		t.Fatalf("audit chain broken: seq %d err %v", bad, err)
	}
}

// Global revocation (DISARM-ALL): engages the global flag, kills ALL
// in-flight work, broadcasts scope=global.
func TestKillSwitchMapping_Global(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	agent := e.seedAgent(t, "monitor", "monitor.feed.sync", store.RiskR0, 4, false)
	task := e.seedQueuedTask(t, m, p, "monitor.feed.sync", store.RiskR0, nil, 0)

	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), allowROE())
	if outcome, err := o.dispatchOne(ctx, e.task(t, task.TaskID)); err != nil || outcome != outcomeDispatched {
		t.Fatalf("dispatch: %s %v", outcome, err)
	}
	if err := e.st.Transition(ctx, task.TaskID, []string{store.TaskDispatched}, store.TaskRunning, agent.AgentID, "ack"); err != nil {
		t.Fatalf("ack: %v", err)
	}

	killCh := make(chan []byte, 4)
	sub, err := e.b.NC.Subscribe(bus.SubjectControlKill, func(msg *nats.Msg) { killCh <- msg.Data })
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	defer sub.Unsubscribe()
	_ = e.b.NC.Flush()

	rev := &gatekeeperv1.Revocation{
		RevocationId: "rev_global_1",
		Scope:        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL,
		IssuedBy:     "op_itest",
		Reason:       "DISARM-ALL",
	}
	if err := o.HandleRevocation(ctx, rev); err != nil {
		t.Fatalf("HandleRevocation: %v", err)
	}

	select {
	case data := <-killCh:
		var env platformv1.Envelope
		if err := proto.Unmarshal(data, &env); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var payload structpb.Struct
		if err := env.GetPayload().UnmarshalTo(&payload); err != nil {
			t.Fatalf("kill payload decode: %v", err)
		}
		if payload.GetFields()["scope"].GetStringValue() != "global" {
			t.Fatal("global kill must broadcast scope=global")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no control.kill broadcast for global revocation")
	}
	kills, _ := e.st.KillSwitchesEngaged(ctx)
	if !kills[store.KillScopeGlobal+"/"] {
		t.Fatal("global kill flag not engaged")
	}
	if st := e.task(t, task.TaskID).State; st != store.TaskKilled {
		t.Fatalf("task state = %s, want KILLED (global drain)", st)
	}
}

// ===========================================================================
// Full R0 lifecycle: dispatch → ACK → result → COMPLETED; chain verifies.
// ===========================================================================
func TestLifecycle_EndToEnd_R0(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	agent := e.seedAgent(t, "monitor", "monitor.feed.sync", store.RiskR0, 2, false)
	task := e.seedQueuedTask(t, m, p, "monitor.feed.sync", store.RiskR0, nil, 0)

	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), allowROE())
	if outcome, err := o.dispatchOne(ctx, e.task(t, task.TaskID)); err != nil || outcome != outcomeDispatched {
		t.Fatalf("dispatch: %s %v", outcome, err)
	}
	if err := e.st.Transition(ctx, task.TaskID, []string{store.TaskDispatched}, store.TaskRunning, agent.AgentID, "ack"); err != nil {
		t.Fatalf("ack: %v", err)
	}
	res := &platformv1.TaskResult{
		TaskId: task.TaskID, AgentId: agent.AgentID,
		Status:  platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED,
		Metrics: &platformv1.TaskResultMetrics{},
	}
	if err := o.HandleResult(ctx, res); err != nil {
		t.Fatalf("result: %v", err)
	}
	if st := e.task(t, task.TaskID).State; st != store.TaskCompleted {
		t.Fatalf("state = %s, want COMPLETED", st)
	}
	// Duplicate delivery is an idempotent no-op (doc 01 §8.2).
	if err := o.HandleResult(ctx, res); err != nil {
		t.Fatalf("duplicate result must be idempotent: %v", err)
	}
	if st := e.task(t, task.TaskID).State; st != store.TaskCompleted {
		t.Fatalf("state after dup = %s", st)
	}
	bad, err := e.al.VerifyChain(ctx)
	if err != nil || bad != 0 {
		t.Fatalf("chain: seq %d err %v", bad, err)
	}
}

// ===========================================================================
// Doc 01 §10.5: out-of-scope touch → SCOPE_VIOLATION, agent quarantined,
// mission paused.
// ===========================================================================
func TestScopeViolation_QuarantinesAgentAndPausesMission(t *testing.T) {
	e := itSetup(t)
	ctx := context.Background()

	m := e.seedMission(t, store.MissionActive)
	p := e.seedPlan(t, m.MissionID)
	agent := e.seedAgent(t, "detect", "detect.scan", store.RiskR2, 4, false)
	task := e.seedQueuedTask(t, m, p, "detect.scan", store.RiskR1, []string{"api.acme.com"}, 0)

	o := e.orchestrator(pep.New(&fakePDP{decision: allowDecision()}, &fakeMinter{}, "itest"), allowROE())
	if outcome, err := o.dispatchOne(ctx, e.task(t, task.TaskID)); err != nil || outcome != outcomeDispatched {
		t.Fatalf("dispatch: %s %v", outcome, err)
	}
	if err := e.st.Transition(ctx, task.TaskID, []string{store.TaskDispatched}, store.TaskRunning, agent.AgentID, "ack"); err != nil {
		t.Fatalf("ack: %v", err)
	}

	res := &platformv1.TaskResult{
		TaskId: task.TaskID, AgentId: agent.AgentID,
		Status: platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED,
		Metrics: &platformv1.TaskResultMetrics{
			TargetsTouched: []string{"api.acme.com", "evil.example.net"}, // ← out of scope
		},
	}
	if err := o.HandleResult(ctx, res); err != nil {
		t.Fatalf("HandleResult: %v", err)
	}

	a, err := e.st.GetAgent(ctx, agent.AgentID)
	if err != nil || a.Status != store.AgentQuarantined {
		t.Fatalf("agent status = %v, want QUARANTINED", a.Status)
	}
	mm, _ := e.st.GetMission(ctx, m.MissionID)
	if mm.State != store.MissionPaused {
		t.Fatalf("mission state = %s, want PAUSED", mm.State)
	}
	var n int
	if err := e.st.Pool.QueryRow(ctx,
		`SELECT count(*) FROM platform.audit_events WHERE type = 'SCOPE_VIOLATION'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("SCOPE_VIOLATION audit missing (n=%d)", n)
	}
	if rows := e.outboxFor(t, bus.SubjectMissionEvents); len(rows) == 0 {
		t.Fatal("commander halt signal (SCOPE_VIOLATION mission event) missing")
	}
}
