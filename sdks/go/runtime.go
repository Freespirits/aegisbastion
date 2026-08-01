package agentsdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
	"github.com/aegisbastion/aegisbastion/sdks/go/bus"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/pep"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"
)

// runningTask tracks one in-flight execution for halt propagation.
type runningTask struct {
	taskID  string
	mission string
	roe     string   // set once authorized (empty before)
	caps    []string // token capabilities
	cancel  context.CancelFunc
	halted  *bool
}

// execute runs the full guardrail chain and the module, then reports the
// terminal TaskResult.
func (a *Agent) execute(ctx context.Context, as *platformv1.TaskAssignment, ctl *bus.MessageControl, log *slog.Logger) {
	started := time.Now().UTC()
	task := &Task{Assignment: as}
	emit := a.newEmitter(task)

	status := platformv1.TaskResultStatus_TASK_RESULT_STATUS_SUCCEEDED
	resultErr := ""
	finish := func() {
		res := &platformv1.TaskResult{
			TaskId:       as.GetTaskId(),
			AgentId:      a.AgentID(),
			Status:       status,
			StartedAt:    timestamppb.New(started),
			FinishedAt:   timestamppb.Now(),
			Summary:      emit.resultSummary(),
			ArtifactRefs: emit.resultArtifacts(),
			Metrics: &platformv1.TaskResultMetrics{
				RequestsSent: emit.requests.Load(),
			},
			Error: resultErr,
		}
		if task.guard != nil {
			// Exact-enumerated: concrete touched list. Scope-bound: the
			// ["scope:sha256:<hash>"] checkpoint form — accepted ONLY
			// alongside the per-probe TARGET_TOUCHED records the Guard
			// already emitted (Ruling A.4).
			res.Metrics.TargetsTouched = task.guard.TargetsTouchedMetric()
		}
		a.reportResult(ctx, res, log)
	}

	// Plan gate (doc 01 §9.1).
	if err := a.mod.Plan(task); err != nil {
		status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED
		resultErr = "plan rejected: " + err.Error()
		finish()
		return
	}

	// Authorization gate: R1–R3 need a Scope Token (verified against JWKS);
	// R0 must not contact targets at all (a token on an R0 task is ignored
	// with a warning — R0's contract is zero target contact, doc 11 §1).
	if as.GetRiskClass() != platformv1.RiskClass_RISK_CLASS_R0 {
		guard, stopReauth, err := a.authorize(ctx, as, log)
		if err != nil {
			a.violationAudit(as, "", err.Error())
			status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_REJECTED_UNAUTHORIZED
			resultErr = err.Error()
			finish()
			return
		}
		task.guard = guard
		defer stopReauth()
	} else if as.GetAuthorizationToken() != "" {
		log.Warn("R0 task carried an authorization token — ignoring it (zero target contact)")
	}

	// Execution context: min(timeout_s, deadline), cancelled on halt.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if d, ok := taskDeadline(as); ok {
		var deadlineCancel context.CancelFunc
		runCtx, deadlineCancel = context.WithDeadline(runCtx, d)
		defer deadlineCancel()
	}

	halted := false
	rt := &runningTask{taskID: as.GetTaskId(), mission: as.GetMissionId(), cancel: cancel, halted: &halted}
	if task.guard != nil {
		rt.roe = task.guard.Claims().ROEID
		rt.caps = task.guard.Claims().Capabilities
	}
	a.mu.Lock()
	a.running[as.GetTaskId()] = rt
	a.mu.Unlock()
	defer func() {
		a.mu.Lock()
		delete(a.running, as.GetTaskId())
		a.mu.Unlock()
	}()

	// Keep the bus ack alive while running (redelivery happens on lease
	// expiry, doc 01 §6.3).
	done := make(chan struct{})
	defer close(done)
	if ctl != nil {
		go func() {
			t := time.NewTicker(30 * time.Second)
			defer t.Stop()
			for {
				select {
				case <-done:
					return
				case <-t.C:
					_ = ctl.InProgress()
				}
			}
		}()
	}

	// Watch halt conditions for this task (revocation cache per claims).
	go a.watchHalt(runCtx, as, rt)

	runErr := a.mod.Run(runCtx, task, emit)
	switch {
	case runErr == nil:
		// SUCCEEDED.
	case errors.Is(runCtx.Err(), context.DeadlineExceeded):
		status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_TIMEOUT
		resultErr = "deadline/timeout exceeded"
	case halted || errors.Is(runErr, pep.ErrRevoked):
		status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_KILLED
		resultErr = "halted by kill switch / revocation"
		if runErr != nil && !errors.Is(runErr, context.Canceled) {
			resultErr = runErr.Error()
		}
	case isGuardrailDenial(runErr):
		status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_REJECTED_UNAUTHORIZED
		resultErr = runErr.Error()
	default:
		status = platformv1.TaskResultStatus_TASK_RESULT_STATUS_FAILED
		resultErr = runErr.Error()
	}
	finish()
}

// authorize performs the SDK-side authorization chain for an R1–R3
// assignment (doc 01 §9 item 4 — every check fail-closed):
//
//  1. a token must be present,
//  2. EdDSA signature + claims verify against the cached gatekeeper JWKS,
//  3. the token must be bound to THIS task_id and permit the capability,
//  4. the target manifest is fetched from MinIO and its sha256 verified
//     against the claim (for scope-bound tokens the manifest carries the
//     canonical RoE scope; its hash IS the "scope:sha256:<hash>" audit value),
//  5. the PEP Guard is built and the mid-run re-authorization loop armed.
//
// Any failure ⇒ the SDK refuses target contact (doc 01 §15 acceptance
// test 2) and the task is reported REJECTED_UNAUTHORIZED + audit-logged.
func (a *Agent) authorize(ctx context.Context, as *platformv1.TaskAssignment, log *slog.Logger) (*pep.Guard, context.CancelFunc, error) {
	raw := as.GetAuthorizationToken()
	if raw == "" {
		return nil, nil, fmt.Errorf("%w: no authorization_token on %s task",
			pep.ErrNoAuthorization, as.GetRiskClass())
	}
	claims, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		return nil, nil, fmt.Errorf("token verification failed: %w", err)
	}
	if claims.TaskID != as.GetTaskId() {
		return nil, nil, fmt.Errorf("%w: token task_id %q, assignment %q",
			pep.ErrTaskBinding, claims.TaskID, as.GetTaskId())
	}
	if !claims.Permits(as.GetCapability()) {
		return nil, nil, fmt.Errorf("%w: capability %q",
			pep.ErrTaskBinding, as.GetCapability())
	}
	man, err := manifest.Load(ctx, a.fetcher, claims.Targets, claims.ScopeBound)
	if err != nil {
		return nil, nil, fmt.Errorf("manifest fetch/verify failed: %w", err)
	}
	guard, err := pep.NewGuard(pep.GuardConfig{
		Claims:      claims,
		Manifest:    man,
		TaskID:      as.GetTaskId(),
		Capability:  as.GetCapability(),
		Revocations: a.revocations,
		Emitter:     a.emitter,
		Audit: audit.Ident{
			AgentID:   a.AgentID(),
			MissionID: as.GetMissionId(),
			TaskID:    as.GetTaskId(),
			ROEID:     claims.ROEID,
		},
		ExtraAudit: map[string]any{"capability": as.GetCapability()},
	})
	if err != nil {
		return nil, nil, err
	}

	reauthCtx, stopReauth := context.WithCancel(context.Background())
	go a.reauthLoop(reauthCtx, as.GetTaskId(), raw, guard, log)
	return guard, stopReauth, nil
}

// reauthLoop continuously re-authorizes the 15-minute token mid-run (doc 01
// §5.5, doc 11 §3.2): at RefreshFraction of the TTL it calls
// TokenService.RefreshToken — a full policy re-check, NOT an unauthenticated
// refresh — verifies the successor token against JWKS, reloads its manifest,
// and swaps the Guard onto it. A denial (empty successor) or failure means:
// keep working on the current token and halt when it expires.
func (a *Agent) reauthLoop(ctx context.Context, taskID, current string, guard *pep.Guard, log *slog.Logger) {
	for {
		claims := guard.Claims()
		ttl := time.Duration(claims.ExpiresAt-claims.IssuedAt) * time.Second
		wait := time.Duration(float64(ttl) * a.cfg.RefreshFraction)
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}

		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := a.tokens.RefreshToken(rctx, &gatekeeperv1.RefreshTokenRequest{CurrentToken: current})
		cancel()
		if err != nil {
			log.Warn("re-authorization RPC failed — continuing on current token until exp", "error", err)
			continue
		}
		if resp.GetToken() == "" {
			log.Warn("re-authorization DENIED — halting when current token expires")
			return
		}
		successor, err := a.verifier.Verify(context.Background(), resp.GetToken())
		if err != nil {
			log.Error("successor token failed verification — refusing it", "error", err)
			return
		}
		man, err := manifest.Load(context.Background(), a.fetcher, successor.Targets, successor.ScopeBound)
		if err != nil {
			log.Error("successor manifest fetch/verify failed — refusing successor", "error", err)
			return
		}
		if err := guard.Update(successor, man); err != nil {
			log.Error("successor token rejected by guard", "error", err)
			return
		}
		current = resp.GetToken()
		log.Info("re-authorized mid-run", "jti", successor.ID, "exp", successor.Expiry())
	}
}

// watchHalt cancels a task's context as soon as the revocation cache covers
// its RoE or capability (the per-task leg of the ≤ 5 s halt SLA; the bus
// watcher covers global/target revocations).
func (a *Agent) watchHalt(ctx context.Context, as *platformv1.TaskAssignment, rt *runningTask) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		running := a.running[as.GetTaskId()] != nil
		a.mu.Unlock()
		if !running {
			return
		}
		if revoked, reason := a.revocations.Revoked("", as.GetCapability(), ""); revoked {
			a.log.Warn("capability revoked — halting task", "task_id", as.GetTaskId(), "reason", reason)
			a.haltTask(rt, reason)
			return
		}
	}
}

// haltTask cancels one task and invokes the module's Abort (≤ 5 s, doc 01
// §9 item 5).
func (a *Agent) haltTask(rt *runningTask, reason string) {
	if rt.halted != nil {
		*rt.halted = true
	}
	rt.cancel()
	go a.mod.Abort()
}

// haltMatching cancels every running task whose authorization the revocation
// cache now covers — global halts everything (and marks the agent killed so
// new assignments are refused); RoE/capability revocations halt matching
// tasks (≤ 5 s SLA, doc 11 §7).
func (a *Agent) haltMatching(reason string) {
	a.mu.Lock()
	if global, _ := a.revocations.Halted(); global {
		a.killed = true
	}
	killed := a.killed
	var victims []*runningTask
	for _, rt := range a.running {
		switch {
		case killed:
			victims = append(victims, rt)
		case rt.roe != "" || len(rt.caps) > 0:
			cap := ""
			if len(rt.caps) > 0 {
				cap = rt.caps[0]
			}
			if revoked, _ := a.revocations.Revoked(rt.roe, cap, ""); revoked {
				victims = append(victims, rt)
			}
		}
	}
	a.mu.Unlock()
	for _, rt := range victims {
		a.haltTask(rt, reason)
	}
}

// newEmitter wires the Emitter for one task.
func (a *Agent) newEmitter(task *Task) *Emitter {
	return &Emitter{
		task: task,
		progressFn: func(ctx context.Context, taskID string, s *structpb.Struct) error {
			pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			return a.reg.ReportProgress(pctx, taskID, s)
		},
		eventFn: func(ctx context.Context, subject string, payload proto.Message, missionID string, trace *platformv1.TraceContext) error {
			_, err := a.bus.Publish(ctx, subject, payload, bus.PublishOptions{
				MissionID: missionID,
				Trace:     trace,
			})
			return err
		},
	}
}

// reportResult delivers the terminal TaskResult on the task.result stream
// (durable, at-least-once; dedup on "result:<task_id>"). Retries briefly —
// the Orchestrator treats an unreported result as a crashed agent (doc 01
// §13 lease expiry → redelivery).
func (a *Agent) reportResult(ctx context.Context, res *platformv1.TaskResult, log *slog.Logger) {
	backoff := 500 * time.Millisecond
	for attempt := 1; attempt <= 5; attempt++ {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, err := a.bus.Publish(rctx, bus.SubjectTaskResult, res, bus.PublishOptions{
			MissionID: a.cfgMission(res),
			EventID:   "result-" + res.GetTaskId(),
		})
		cancel()
		if err == nil {
			return
		}
		log.Error("ReportResult publish failed", "attempt", attempt, "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

func (a *Agent) cfgMission(res *platformv1.TaskResult) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if rt, ok := a.running[res.GetTaskId()]; ok {
		return rt.mission
	}
	return ""
}

// violationAudit emits SCOPE_VIOLATION when the SDK refuses a task before
// any target contact (doc 01 §10.5, doc 03 §9.2: dead-lettered and
// audit-logged).
func (a *Agent) violationAudit(as *platformv1.TaskAssignment, target, reason string) {
	evt, err := audit.ScopeViolationEvent(audit.Ident{
		AgentID:   a.AgentID(),
		MissionID: as.GetMissionId(),
		TaskID:    as.GetTaskId(),
	}, target, "", reason)
	if err != nil {
		return
	}
	_ = a.emitter.Emit(context.Background(), evt)
}

// taskDeadline computes min(now+timeout_s, deadline) for an assignment.
func taskDeadline(as *platformv1.TaskAssignment) (time.Time, bool) {
	var d time.Time
	ok := false
	if as.GetTimeoutS() > 0 {
		d = time.Now().Add(time.Duration(as.GetTimeoutS()) * time.Second)
		ok = true
	}
	if dl := as.GetDeadline(); dl != nil {
		if t := dl.AsTime(); !t.IsZero() && (!ok || t.Before(d)) {
			d = t
			ok = true
		}
	}
	return d, ok
}

// isGuardrailDenial classifies module errors that mean "the SDK refused" —
// they map to REJECTED_UNAUTHORIZED (doc 01 §5.7).
func isGuardrailDenial(err error) bool {
	return errors.Is(err, pep.ErrNoAuthorization) ||
		errors.Is(err, pep.ErrTaskBinding) ||
		errors.Is(err, pep.ErrTargetNotInManifest) ||
		errors.Is(err, pep.ErrTargetExcluded) ||
		errors.Is(err, pep.ErrTargetOutOfScope) ||
		errors.Is(err, token.ErrExpired) ||
		errors.Is(err, token.ErrSignature) ||
		errors.Is(err, token.ErrAudience) ||
		errors.Is(err, token.ErrIssuer)
}
