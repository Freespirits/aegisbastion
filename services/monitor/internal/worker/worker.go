// Package worker is the M3 probe-worker execution unit (doc 03 §3.1): it
// consumes scan jobs, verifies the carried scope-bound watch token PER JOB
// (doc 03 §9.2 — signature + claims against the gatekeeper JWKS, task
// binding, capability, manifest hash), builds a PEP guard for the job, and
// runs the executor. A job without a valid in-scope token is dead-lettered
// into monitor.scan_jobs_dead and audit-logged (fail-closed, doc 03 §9.2);
// poison jobs dead-letter after the redelivery cap (doc 03 §12).
package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/pep"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/events"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/executor"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/jobs"
)

// DeadLetterStore persists dead-lettered jobs (production: *store.Store).
type DeadLetterStore interface {
	InsertDeadJob(ctx context.Context, job []byte, errText string, attempts int) error
}

// ScanExecutor runs scan jobs (production: *executor.Executor).
type ScanExecutor interface {
	ScanAsset(ctx context.Context, req executor.ScanRequest) (executor.Outcome, error)
}

// Config wires a Worker.
type Config struct {
	AgentID string
	// Verifier verifies job tokens against the cached gatekeeper JWKS.
	Verifier *token.Verifier
	// Fetcher loads token manifests from MinIO (token-manifests bucket).
	Fetcher manifest.Fetcher
	// Revocations is the process-wide revocation cache (fed from
	// tasks.revocations.v1 by the caller).
	Revocations *pep.RevocationCache
	// Emitter is the audit sink (audit.events).
	Emitter audit.Emitter
	// Executor runs the scan pipeline.
	Executor ScanExecutor
	// Store dead-letters failed jobs.
	Store DeadLetterStore
	// EgressCapPerMinute bounds total probes per worker process
	// (doc 03 §9.3 layer c, default 200).
	EgressCapPerMinute int
	Logger             *slog.Logger
}

// OutcomeSink receives per-job outcomes (coordinator counters/checkpoints).
type OutcomeSink interface {
	JobDone(j *jobs.Job, out executor.Outcome)
}

// Worker consumes and executes scan jobs.
type Worker struct {
	cfg  Config
	sink OutcomeSink

	mu          sync.Mutex
	minuteStart time.Time
	minuteCount int
}

// New builds a Worker.
func New(cfg Config, sink OutcomeSink) *Worker {
	if cfg.Revocations == nil {
		cfg.Revocations = pep.NewRevocationCache()
	}
	if cfg.Emitter == nil {
		cfg.Emitter = audit.NopEmitter{}
	}
	if cfg.EgressCapPerMinute <= 0 {
		cfg.EgressCapPerMinute = 200
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Worker{cfg: cfg, sink: sink}
}

// Handle implements jobs.Handler — the per-job gate of doc 03 §9.2.
func (w *Worker) Handle(ctx context.Context, j *jobs.Job, deliveries int) jobs.Disposition {
	log := w.cfg.Logger.With("job_id", j.JobID, "identifier", j.Identifier, "task_id", j.TaskID)

	// 1. Verify the carried token (EdDSA vs JWKS, aud/TTL/claims).
	claims, err := w.cfg.Verifier.Verify(ctx, j.AuthorizationToken)
	if err != nil {
		w.deadLetter(ctx, j, deliveries, "token verification failed: "+err.Error(), "")
		return jobs.Term
	}
	// 2. Task + capability binding (task-bound jti, doc 11 §3.2).
	if claims.TaskID != j.TaskID || !claims.Permits(j.Capability) {
		w.deadLetter(ctx, j, deliveries,
			fmt.Sprintf("token not bound to task %s / capability %s", j.TaskID, j.Capability), claims.ID)
		return jobs.Term
	}
	// 3. Manifest fetch + hash verify (scope-bound: canonical RoE scope).
	man, err := manifest.Load(ctx, w.cfg.Fetcher, claims.Targets, claims.ScopeBound)
	if err != nil {
		w.deadLetter(ctx, j, deliveries, "manifest fetch/verify failed: "+err.Error(), claims.ID)
		return jobs.Term
	}
	// 4. Cheap scope pre-check (the per-probe guard re-checks with audit).
	if dec := man.EvaluateScope(j.Identifier); !dec.Allowed {
		w.deadLetterScope(ctx, j, claims, dec.Reason)
		return jobs.Term
	}

	// 5. Global egress budget (doc 03 §9.3 layer c).
	if !w.egressBudget() {
		log.Warn("worker egress budget exhausted — nacking for redelivery")
		return jobs.Nak
	}

	// 6. Execute. The executor calls Authorize once per probe; each call
	// builds a fresh guard so the per-probe TARGET_TOUCHED record carries
	// the right probe_type extra (doc 03 §9.6).
	req := executor.ScanRequest{
		TaskID: j.TaskID, WatchID: j.WatchID,
		MissionID: j.MissionID, ROEID: j.ROEID, ROEVersion: j.ROEVersion, OrgID: j.OrgID,
		Asset: events.AssetCtx{
			AssetID: j.AssetID, Kind: j.Kind, Identifier: j.Identifier, Criticality: j.Criticality,
		},
		ProbeTypes:         j.ProbeTypes,
		BaselineID:         j.BaselineID,
		AlertThreshold:     j.AlertThreshold,
		EmissionCapPerHour: j.EmissionCapPerHour,
		CadenceProfile:     j.CadenceProfile,
		TokenJTI:           claims.ID,
		ReportEvents:       j.ReportEvents,
		Reactivation:       j.Reactivation,
	}
	req.Authorize = func(pctx context.Context, probeType, target string) error {
		g, err := w.guardFor(claims, man, j, probeType)
		if err != nil {
			return err
		}
		return g.AuthorizeTarget(pctx, target)
	}

	out, err := w.cfg.Executor.ScanAsset(ctx, req)
	if w.sink != nil {
		w.sink.JobDone(j, out)
	}
	switch {
	case err != nil:
		if deliveries >= jobs.MaxDeliver {
			w.deadLetter(ctx, j, deliveries, "execution failed: "+err.Error(), claims.ID)
			return jobs.Term
		}
		log.Warn("scan job failed — nacking", "deliveries", deliveries, "error", err)
		return jobs.Nak
	case out.Unauthorized:
		// Scope/revocation denial mid-job (the guard already audit-logged
		// scope violations): dead-letter per doc 03 §9.2, no redelivery.
		w.deadLetter(ctx, j, deliveries, "unauthorized: "+out.UnauthorizedErr, claims.ID)
		return jobs.Term
	}
	return jobs.Ack
}

// guardFor builds one PEP guard for the job (probe_type in the
// TARGET_TOUCHED extra, doc 03 §9.6).
func (w *Worker) guardFor(claims *token.Claims, man *manifest.Manifest, j *jobs.Job, probeType string) (*pep.Guard, error) {
	extra := map[string]any{"capability": j.Capability}
	if probeType != "" {
		extra["probe_type"] = probeType
	}
	return pep.NewGuard(pep.GuardConfig{
		Claims: claims, Manifest: man,
		TaskID: j.TaskID, Capability: j.Capability,
		Revocations: w.cfg.Revocations,
		Emitter:     w.cfg.Emitter,
		Audit: audit.Ident{
			AgentID: w.cfg.AgentID, MissionID: j.MissionID,
			TaskID: j.TaskID, ROEID: j.ROEID,
		},
		ExtraAudit: extra,
	})
}

// deadLetter persists the job in monitor.scan_jobs_dead + emits the
// SCOPE_VIOLATION audit record for unauthorized jobs (doc 03 §9.2:
// "dead-lettered and audit-logged"). Revocation/expiry are not violations —
// gatekeeper already audited them; those get a plain dead-letter row only.
func (w *Worker) deadLetter(ctx context.Context, j *jobs.Job, attempts int, reason, tokenJTI string) {
	raw, _ := j.Marshal()
	if err := w.cfg.Store.InsertDeadJob(ctx, raw, reason, attempts); err != nil {
		w.cfg.Logger.Error("dead-letter insert failed", "job_id", j.JobID, "error", err)
	}
	if !isNonViolation(reason) {
		evt, err := audit.ScopeViolationEvent(audit.Ident{
			AgentID: w.cfg.AgentID, MissionID: j.MissionID, TaskID: j.TaskID, ROEID: j.ROEID,
		}, j.Identifier, tokenJTI, "scan job dead-lettered: "+reason)
		if err == nil {
			_ = w.cfg.Emitter.Emit(ctx, evt)
		}
	}
	w.cfg.Logger.Warn("scan job dead-lettered", "job_id", j.JobID, "reason", reason)
}

// deadLetterScope dead-letters an out-of-scope job with the target recorded.
func (w *Worker) deadLetterScope(ctx context.Context, j *jobs.Job, claims *token.Claims, reason string) {
	raw, _ := j.Marshal()
	if err := w.cfg.Store.InsertDeadJob(ctx, raw, "out of scope: "+reason, 1); err != nil {
		w.cfg.Logger.Error("dead-letter insert failed", "job_id", j.JobID, "error", err)
	}
	evt, err := audit.ScopeViolationEvent(audit.Ident{
		AgentID: w.cfg.AgentID, MissionID: j.MissionID, TaskID: j.TaskID, ROEID: j.ROEID,
	}, j.Identifier, claims.ID, "scan job target out of scope: "+reason)
	if err == nil {
		_ = w.cfg.Emitter.Emit(ctx, evt)
	}
	w.cfg.Logger.Warn("scan job dead-lettered (out of scope)", "job_id", j.JobID, "reason", reason)
}

func isNonViolation(reason string) bool {
	return strings.Contains(reason, "revoked") ||
		strings.Contains(reason, "expired") ||
		strings.Contains(reason, "not yet valid")
}

// egressBudget is the worker-global probe cap (doc 03 §9.3 layer c).
func (w *Worker) egressBudget() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	now := time.Now()
	if now.Sub(w.minuteStart) >= time.Minute {
		w.minuteStart = now
		w.minuteCount = 0
	}
	if w.minuteCount >= w.cfg.EgressCapPerMinute {
		return false
	}
	w.minuteCount++
	return true
}

// JobEnvelope is a debug/log rendering of a job (no token material).
func JobEnvelope(j *jobs.Job) string {
	redacted := *j
	redacted.AuthorizationToken = ""
	b, _ := json.Marshal(redacted)
	return string(b)
}
