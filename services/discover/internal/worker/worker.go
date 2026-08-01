// Package worker is the shared runtime for the discover worker pools
// (worker-passive, worker-ct, worker-cloud — doc 02 §2.2). One binary per
// pool; all tasks idempotent and deadline-bound.
//
// Per task, in order:
//
//  1. order-state check — terminal orders (cancelled/finalized) are skipped
//     (cooperative cancellation, doc 02 §3.1);
//  2. Scope Token verification via pepclient (PEP-2, defense-in-depth
//     re-check of the gatekeeper-issued token — fail-closed; refusals are
//     audit-recorded as SCOPE_VIOLATION and dead-lettered, never retried);
//  3. connector run (rate-limited, circuit-broken, evidence archived);
//  4. findings → discover.results; done marker; ack AFTER publish
//     (doc 02 §2.2 explicit ack after the write).
//
// Retry posture (doc 02 §7.2): transient source failures nak with backoff
// up to queue.MaxDeliveries, then the task is accounted failed
// (SOURCE_UNAVAILABLE) so the order completes PARTIAL; panics dead-letter
// with the stack + seed.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime/debug"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/auditfwd"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/connectors"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/pepclient"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/queue"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

// Deps wires a worker pool.
type Deps struct {
	Lane     string // discover.tasks.passive|ct|cloud
	JS       nats.JetStreamContext
	Registry *connectors.Registry
	PEP      *pepclient.Client // token verification only (VerifyTaskToken)
	Store    *store.Store      // order-state checks; nil ⇒ skip
	Audit    *auditfwd.Emitter // nil ⇒ no audit
	Log      *slog.Logger
	Now      func() time.Time
}

// Worker consumes one lane.
type Worker struct {
	d Deps
}

// New builds a Worker.
func New(d Deps) *Worker {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Worker{d: d}
}

// Run consumes until ctx is done.
func (w *Worker) Run(ctx context.Context) error {
	cons, err := queue.SubscribeTasks(w.d.JS, w.d.Lane)
	if err != nil {
		return err
	}
	defer cons.Close()
	w.d.Log.Info("worker pool consuming", "lane", w.d.Lane)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		msgs, err := cons.Fetch(4, 2*time.Second)
		if err != nil {
			w.d.Log.Warn("fetch failed", "error", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(2 * time.Second):
			}
			continue
		}
		for _, msg := range msgs {
			w.handle(ctx, msg)
		}
	}
}

// handle processes one lane message with panic containment (doc 02 §7.2
// poison task → DLQ with stack + seed).
func (w *Worker) handle(ctx context.Context, msg *nats.Msg) {
	task, err := queue.DecodeTask(msg)
	if err != nil {
		_ = msg.Term() // poison payload — do not loop
		w.d.Log.Warn("undecodable lane task terminated", "error", err)
		return
	}
	defer func() {
		if r := recover(); r != nil {
			stack := string(debug.Stack())
			w.d.Log.Error("task panicked — dead-lettering", "task_id", task.TaskID, "panic", r)
			_ = queue.PublishDLQ(ctx, w.d.JS, task, fmt.Sprintf("panic: %v\n%s", r, stack))
			_ = msg.Ack()
		}
	}()

	log := w.d.Log.With("task_id", task.TaskID, "source", task.Source, "seed", task.Seed.Value)

	// 1. Order-state check (cooperative cancellation).
	if w.d.Store != nil {
		order, err := w.d.Store.GetOrder(ctx, task.OrderID)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				log.Warn("task references unknown order — terminating")
				_ = msg.Term()
				return
			}
			_ = msg.Nak()
			return
		}
		if order.State != model.OrderRunning {
			log.Info("order not RUNNING — skipping task", "state", order.State)
			w.publishDone(ctx, task, 0, "order "+order.State)
			_ = msg.Ack()
			return
		}
	}

	// 2. Scope Token verification (PEP-2 re-check; fail-closed).
	if _, err := w.d.PEP.VerifyTaskToken(ctx, task); err != nil {
		log.Warn("task refused by token verification — dead-lettering", "error", err)
		w.auditRefusal(ctx, task, err)
		_ = queue.PublishDLQ(ctx, w.d.JS, task, "token verification refused: "+err.Error())
		_ = msg.Ack()
		return
	}

	// 3. Connector run under the task deadline.
	deadline := task.Deadline
	if deadline.IsZero() || time.Until(deadline) > 2*time.Minute {
		deadline = w.d.Now().Add(2 * time.Minute) // doc 02 §7.2 default 120 s
	}
	tctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()

	emitted := 0
	emit := func(f model.RawFinding, edges []model.EdgeRef) error {
		emitted++
		return queue.PublishResult(tctx, w.d.JS, queue.FindingMsgID(task.TaskID, f.Asset), &model.ResultMessage{
			Kind:    model.ResultFinding,
			Finding: &f,
			Edges:   edges,
		})
	}
	runErr := w.d.Registry.Run(tctx, task.Source, connectors.RunInput{
		Task: task, ScopeToken: task.ScopeToken,
	}, emit)
	cancel()

	// 4. Settlement (doc 02 §7.2 retry matrix).
	deliveries := queue.Deliveries(msg)
	switch {
	case runErr == nil || errors.Is(runErr, connectors.ErrNotFound):
		w.publishDone(ctx, task, emitted, "")
		_ = msg.Ack()
	case deliveries < queue.MaxDeliveries && !isTerminal(runErr):
		log.Warn("connector failed — redelivering", "attempt", deliveries, "error", runErr)
		_ = msg.NakWithDelay(backoff(deliveries))
	default:
		// Retries exhausted (or a terminal error like missing credentials):
		// account the task failed so the order completes PARTIAL with
		// SOURCE_UNAVAILABLE (doc 02 §3.3/§7.2).
		log.Warn("connector failed terminally", "attempt", deliveries, "error", runErr)
		w.publishDone(ctx, task, emitted, fmt.Sprintf("%s: %v", model.ReasonSourceUnavailable, runErr))
		_ = msg.Ack()
	}
}

// isTerminal marks failures retries cannot fix (missing tenant credentials).
func isTerminal(err error) bool {
	var credErr *connectors.CredentialError
	return errors.As(err, &credErr)
}

// backoff is the doc 02 §7.2 exponential retry (max 5 deliveries).
func backoff(deliveries uint64) time.Duration {
	d := time.Duration(1<<deliveries) * time.Second
	if d > 30*time.Second {
		d = 30 * time.Second
	}
	return d
}

func (w *Worker) publishDone(ctx context.Context, task model.Task, emitted int, errStr string) {
	msg := &model.ResultMessage{
		Kind:     model.ResultDone,
		TaskID:   task.TaskID,
		OrderID:  task.OrderID,
		TenantID: task.TenantID,
		Emitted:  emitted,
		Error:    errStr,
	}
	if err := queue.PublishResult(ctx, w.d.JS, "dres-done-"+task.TaskID, msg); err != nil {
		w.d.Log.Warn("done marker publish failed", "task_id", task.TaskID, "error", err)
	}
}

func (w *Worker) auditRefusal(ctx context.Context, task model.Task, cause error) {
	if w.d.Audit == nil {
		return
	}
	if err := w.d.Audit.Emit(ctx, auditfwd.Event{
		TenantID: task.TenantID,
		Action:   auditfwd.ActionWorkerRefusal,
		Target:   task.TaskID,
		TaskID:   task.TaskID,
		ROEID:    task.ROEID,
		Payload: map[string]any{
			"task_id": task.TaskID, "order_id": task.OrderID,
			"seed": task.Seed.Value, "technique": string(task.Technique),
			"reason": cause.Error(), "denied_before_contact": true,
		},
	}); err != nil {
		w.d.Log.Warn("audit emit failed", "error", err)
	}
}
