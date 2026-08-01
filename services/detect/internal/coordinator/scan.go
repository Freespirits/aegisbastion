package coordinator

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"

	agentsdk "github.com/aegisbastion/aegisbastion/sdks/go"
	sdkaudit "github.com/aegisbastion/aegisbastion/sdks/go/audit"
	"github.com/aegisbastion/aegisbastion/sdks/go/bus"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/evs"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/planner"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/tokexchange"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/worker"
)

// runScan executes one detect.scan.* task end to end (doc 04 §3.2):
// plan → per-job token exchange (fail-closed) → egress proxy → dispatch →
// validate/score/publish each candidate inline → aggregate TaskResult.
func (c *Coordinator) runScan(ctx context.Context, t *agentsdk.Task, emit *agentsdk.Emitter, params *Params) error {
	as := t.Assignment
	log := c.d.Log.With("task_id", as.GetTaskId(), "capability", as.GetCapability())

	// --- D2 plan ------------------------------------------------------------
	var tokenMaxRPS uint32
	if g := t.Guard(); g != nil && g.Claims().RateCaps != nil {
		tokenMaxRPS = g.Claims().RateCaps.MaxRPS
	}
	plan, err := planner.Plan(planner.Input{
		TaskID:          as.GetTaskId(),
		Capability:      as.GetCapability(),
		Targets:         as.GetTargets(),
		Profile:         params.Profile,
		CheckIDs:        params.CheckIDs,
		ExcludeCheckIDs: params.ExcludeCheckIDs,
		Ports:           params.Ports,
		MaxRequests:     params.MaxRequests,
		TokenMaxRPS:     tokenMaxRPS,
		SafeMode:        params.SafeMode,
		Deadline:        as.GetDeadline().AsTime(),
	})
	if err != nil {
		return err
	}
	planner.SortJobs(plan.Jobs)
	for _, warning := range plan.Warnings {
		log.Warn("planner", "warning", warning)
	}

	// --- Egress proxy (doc 04 §10.2) ---------------------------------------
	// Allowlist = the assignment's authorized targets + the OOB collector
	// endpoint (canary callbacks). Deny-all default; every refusal is a
	// SCOPE_VIOLATION candidate event on audit.events.
	allowTargets := append([]string(nil), as.GetTargets()...)
	if c.d.OOBBaseURL != "" {
		allowTargets = append(allowTargets, c.d.OOBBaseURL)
	}
	proxy := evs.NewProxy(evs.NewAllowlist(allowTargets), c.d.Log)
	tokenJTI, roeID := "", ""
	if g := t.Guard(); g != nil {
		tokenJTI = g.Claims().ID
		roeID = g.Claims().ROEID
	}
	proxy.OnDeny = func(e evs.DenyEvent) {
		c.auditScopeViolation(as.GetMissionId(), as.GetTaskId(), roeID, e.HostPort, tokenJTI,
			fmt.Sprintf("egress proxy denied %s (%s)", e.HostPort, e.Reason))
	}
	proxyURL, err := proxy.Start()
	if err != nil {
		return fmt.Errorf("egress proxy start: %w", err)
	}
	defer func() {
		cctx, ccancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer ccancel()
		_ = proxy.Close(cctx)
	}()

	// --- Ruling C9: narrowed job tokens via gatekeeper exchange -------------
	// Fail-closed: gatekeeper unreachable → jobs HOLD (retried until the task
	// deadline); denial → the task fails. The Coordinator never mints.
	jobReqs := make([]tokexchange.JobRequest, len(plan.Jobs))
	for i, j := range plan.Jobs {
		jobReqs[i] = tokexchange.JobRequest{
			JobID:   ids.New("job"),
			Targets: []string{j.Target},
		}
	}
	workerSubject := c.d.AgentID() + ":worker"
	narrowed, err := c.d.Exchanger.ExchangeForJobs(ctx, c.d.ExchangeRetry,
		as.GetAuthorizationToken(), workerSubject, jobReqs)
	if err != nil {
		return fmt.Errorf("token exchange (fail-closed): %w", err)
	}

	// --- Results subscription (before dispatch) ------------------------------
	results := make(chan worker.ResultMessage, 256)
	sub, err := c.d.Bus.Conn().Subscribe(worker.SubjectResults, func(msg *nats.Msg) {
		var m worker.ResultMessage
		if err := json.Unmarshal(msg.Data, &m); err != nil {
			return
		}
		if m.TaskID != as.GetTaskId() {
			return // another task's traffic on the shared stream
		}
		select {
		case results <- m:
		case <-ctx.Done():
		}
	})
	if err != nil {
		return fmt.Errorf("subscribe %s: %w", worker.SubjectResults, err)
	}
	defer sub.Unsubscribe()

	// --- Dispatch (D10) ------------------------------------------------------
	jobs := make([]scanner.Job, len(plan.Jobs))
	for i, spec := range plan.Jobs {
		jobs[i] = scanner.Job{
			JobID:         jobReqs[i].JobID,
			TaskID:        as.GetTaskId(),
			Target:        spec.Target,
			Adapter:       spec.Adapter,
			Checks:        spec.Checks,
			Tags:          spec.Tags,
			Profile:       spec.Profile,
			Ports:         spec.Ports,
			RPS:           spec.RPS,
			RequestBudget: spec.RequestBudget,
			Deadline:      spec.Deadline,
			Token:         narrowed[i].Token,
			SafeMode:      spec.SafeMode,
			ProxyURL:      proxyURL,
			Capability:    as.GetCapability(),
		}
		data, err := json.Marshal(jobs[i])
		if err != nil {
			return err
		}
		msg := nats.NewMsg(worker.SubjectJobs(spec.Adapter))
		msg.Header.Set(nats.MsgIdHdr, jobReqs[i].JobID)
		msg.Data = data
		if _, err := c.d.Bus.JetStream().PublishMsg(msg, nats.Context(ctx)); err != nil {
			return fmt.Errorf("dispatch job %s: %w", jobReqs[i].JobID, err)
		}
	}
	log.Info("dispatched scan jobs", "jobs", len(jobs))

	// --- Aggregate -----------------------------------------------------------
	pipe := newPipeline(c, t, emit, params, proxyURL)
	done := 0
	failedJobs := 0
	for done < len(jobs) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case m := <-results:
			switch m.Kind {
			case "raw":
				if m.Result != nil {
					pipe.process(ctx, *m.Result)
				}
			case "done":
				done++
				if m.Status != "SUCCEEDED" {
					failedJobs++
					log.Warn("job finished non-OK", "job_id", m.JobID, "status", m.Status, "err", m.Error)
				}
				_ = emit.Progress(ctx, map[string]any{
					"jobs_done": done, "jobs_total": len(jobs),
					"candidates": pipe.counts.candidates, "confirmed": pipe.counts.confirmed,
				})
			}
		}
	}

	// --- TaskResult summary (doc 04 §4.4) ------------------------------------
	allowed, denied := proxy.Stats()
	summary := pipe.summary()
	summary["jobs_total"] = len(jobs)
	summary["jobs_failed"] = failedJobs
	summary["egress_requests_allowed"] = allowed
	summary["egress_denies_scope"] = denied
	if err := emit.SetSummary(summary); err != nil {
		return err
	}
	emit.AddRequests(allowed)
	if failedJobs == len(jobs) {
		return errors.New("all scan jobs failed")
	}
	return nil
}

// auditScopeViolation emits a SCOPE_VIOLATION candidate event for an egress
// refusal (doc 04 §10.2: TCP-RST + audit.events record).
func (c *Coordinator) auditScopeViolation(missionID, taskID, roeID, hostPort, tokenJTI, reason string) {
	evt, err := sdkaudit.ScopeViolationEvent(sdkaudit.Ident{
		AgentID:   c.d.AgentID(),
		MissionID: missionID,
		TaskID:    taskID,
		ROEID:     roeID,
	}, hostPort, tokenJTI, reason)
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := c.d.Bus.Publish(ctx, sdkaudit.Subject, evt, bus.PublishOptions{MissionID: missionID}); err != nil {
		c.d.Log.Warn("scope-violation audit publish failed", "err", err)
	}
}
