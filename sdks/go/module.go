package agentsdk

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/sdks/go/pep"
)

// Module is the one interface every subordinate agent implements (doc 01
// §9.1). Everything else — registration, heartbeats, transport, token
// verification, target checking, rate limiting, revocation/kill handling,
// re-authorization, audit emission — is library code, not per-team work.
type Module interface {
	// Plan validates the assignment's params and returns an error when the
	// task is unsupported (reported as FAILED, not retried blindly).
	Plan(t *Task) error
	// Run performs the work within SDK-enforced guardrails: every network
	// target contact goes through Task.AuthorizeTarget first. Run must honor
	// ctx cancellation (kill/timeout/revocation) and return promptly.
	Run(ctx context.Context, t *Task, emit *Emitter) error
	// Abort is invoked by the SDK on kill/timeout/revocation — stop target
	// contact, then clean up (doc 01 §9 item 5: halt ≤ 5 s).
	Abort()
}

// Task carries one assignment through execution. Modules read params/targets
// from Assignment and authorize every target contact through AuthorizeTarget.
type Task struct {
	// Assignment is the Orchestrator's dispatch (doc 01 §5.6).
	Assignment *platformv1.TaskAssignment

	guard *pep.Guard // nil for R0 (no target contact permitted)
}

// RequiresAuthorization reports whether this task runs under a Scope Token
// (R1–R3). R0 tasks must not contact targets at all.
func (t *Task) RequiresAuthorization() bool { return t.guard != nil }

// Guard exposes the PEP guard (nil for R0) — for advanced uses
// (Acquire/Release concurrency slots, ScopeAuditValue).
func (t *Task) Guard() *pep.Guard { return t.guard }

// AuthorizeTarget is the ONLY legal way to touch a network target (doc 01 §9
// item 4). It runs the full PEP-2 chain — revocation, token validity,
// manifest membership / scope evaluation (exclusions always win), rate caps —
// records the touch, and emits the per-probe TARGET_TOUCHED audit record.
// For R0 tasks and on any denial it returns an error: DO NOT contact the
// target; denial is audit-logged as SCOPE_VIOLATION.
func (t *Task) AuthorizeTarget(ctx context.Context, target string) error {
	if t.guard == nil {
		return fmt.Errorf("%w: task %s is R0 — zero target contact",
			pep.ErrNoAuthorization, t.Assignment.GetTaskId())
	}
	return t.guard.AuthorizeTarget(ctx, target)
}

// Emitter is the module's reporting channel (doc 01 §9.1 "emit:
// progress|finding"). Progress flows to the Registry; events flow to the bus
// inside the doc 01 §8.2 envelope; summary/requests roll up into the
// terminal TaskResult.
type Emitter struct {
	task *Task

	progressFn func(ctx context.Context, taskID string, progress *structpb.Struct) error
	eventFn    func(ctx context.Context, subject string, payload proto.Message, missionID string, trace *platformv1.TraceContext) error

	mu        sync.Mutex
	summary   *structpb.Struct
	requests  atomic.Uint64
	artifacts []string
}

// Progress reports liveness/progress (doc 03 §4.3: e.g. {assets_watched,
// queue_depth, probes_per_min} every 60 s).
func (e *Emitter) Progress(ctx context.Context, progress map[string]any) error {
	s, err := structpb.NewStruct(progress)
	if err != nil {
		return err
	}
	if e.progressFn == nil {
		return nil
	}
	return e.progressFn(ctx, e.task.Assignment.GetTaskId(), s)
}

// Event publishes a module event on the bus (e.g. monitor.changes,
// detect.findings) wrapped in the canonical envelope with the assignment's
// mission and trace context.
func (e *Emitter) Event(ctx context.Context, subject string, payload proto.Message) error {
	if e.eventFn == nil {
		return fmt.Errorf("agentsdk: no bus configured for event publishing")
	}
	return e.eventFn(ctx, subject, payload,
		e.task.Assignment.GetMissionId(), e.task.Assignment.GetTraceContext())
}

// SetSummary records the module-defined TaskResult summary rollup (e.g.
// findings count; Monitor's WatchCheckpointSummary fields).
func (e *Emitter) SetSummary(summary map[string]any) error {
	s, err := structpb.NewStruct(summary)
	if err != nil {
		return err
	}
	e.mu.Lock()
	e.summary = s
	e.mu.Unlock()
	return nil
}

// AddRequests adds to the requests_sent metric reported with the result.
func (e *Emitter) AddRequests(n uint64) { e.requests.Add(n) }

// AddArtifactRef records an uploaded evidence object (under the assignment's
// artifact prefix only — doc 01 §9 item 6).
func (e *Emitter) AddArtifactRef(ref string) {
	e.mu.Lock()
	e.artifacts = append(e.artifacts, ref)
	e.mu.Unlock()
}

func (e *Emitter) resultSummary() *structpb.Struct {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.summary
}

func (e *Emitter) resultArtifacts() []string {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]string, len(e.artifacts))
	copy(out, e.artifacts)
	return out
}
