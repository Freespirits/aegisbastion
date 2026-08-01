// Package worker is the Detect scanner-worker fleet (doc 04 §3.1 D3, §5.2):
// dumb executors pulling ScanJobs from the module-internal work-queue stream
// (detect.jobs.{adapter}), running them through the scanner adapters, and
// streaming RawResults back on detect.results. Workers never reach the
// platform bus beyond these two module-internal subjects and never see the
// parent Scope Token — jobs carry a narrowed, job-scoped token obtained by
// the Coordinator from gatekeeper (Ruling C9).
package worker

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"golang.org/x/time/rate"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
)

// Stream/subject layout (doc 04 §5.2, D10). The DETECT_JOBS stream is a
// WorkQueue over detect.jobs.*; DETECT_RESULTS is a 24 h durable stream over
// detect.results (provisioned by deploy/jetstream-bootstrap).
const (
	StreamJobs     = "DETECT_JOBS"
	StreamResults  = "DETECT_RESULTS"
	SubjectResults = "detect.results"
)

// SubjectJobs returns the per-adapter job subject (detect.jobs.{adapter}).
func SubjectJobs(adapter string) string { return "detect.jobs." + adapter }

// ResultMessage is one detect.results record. Kind "raw" carries a candidate
// finding; "done" is the per-job terminal marker the Coordinator counts.
type ResultMessage struct {
	Kind   string             `json:"kind"` // raw | done
	JobID  string             `json:"job_id"`
	TaskID string             `json:"task_id"`
	Result *scanner.RawResult `json:"result,omitempty"`
	Status string             `json:"status,omitempty"` // done: SUCCEEDED|FAILED|UNREACHABLE|KILLED
	Error  string             `json:"error,omitempty"`
}

// Worker executes jobs for ONE adapter type with bounded concurrency
// (doc 04 §11: M concurrent jobs per worker, default 2).
type Worker struct {
	adapter string
	reg     *scanner.Registry
	nc      *nats.Conn
	js      nats.JetStreamContext
	conc    int
	ackWait time.Duration
	log     *slog.Logger

	wg sync.WaitGroup
}

// Config wires a Worker.
type Config struct {
	Adapter  string
	Registry *scanner.Registry
	// Conn is the module-internal NATS connection.
	Conn *nats.Conn
	// Concurrency bounds parallel jobs (default 2).
	Concurrency int
	// AckWait is the JetStream ack wait (must exceed the longest job).
	AckWait time.Duration
	Log     *slog.Logger
}

// New builds a Worker.
func New(cfg Config) (*Worker, error) {
	if cfg.Concurrency <= 0 {
		cfg.Concurrency = 2
	}
	if cfg.AckWait <= 0 {
		cfg.AckWait = 5 * time.Minute
	}
	if cfg.Log == nil {
		cfg.Log = slog.Default()
	}
	js, err := cfg.Conn.JetStream()
	if err != nil {
		return nil, fmt.Errorf("worker: JetStream context: %w", err)
	}
	return &Worker{
		adapter: cfg.Adapter, reg: cfg.Registry, nc: cfg.Conn,
		js: js, conc: cfg.Concurrency,
		ackWait: cfg.AckWait, log: cfg.Log,
	}, nil
}

// Adapter returns the adapter name this worker serves.
func (w *Worker) Adapter() string { return w.adapter }

// Run consumes detect.jobs.{adapter} until ctx ends (durable, work-queue
// semantics; redelivery on crash is idempotent by job_id, doc 04 §12). Up to
// Concurrency jobs run in parallel (doc 04 §11: M concurrent jobs per
// worker).
func (w *Worker) Run(ctx context.Context) error {
	subject := SubjectJobs(w.adapter)
	slots := make(chan struct{}, w.conc)
	sub, err := w.js.Subscribe(subject, func(msg *nats.Msg) {
		slots <- struct{}{}
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			defer func() { <-slots }()
			w.handle(ctx, msg)
		}()
	},
		nats.Durable("detect-worker-"+w.adapter),
		nats.BindStream(StreamJobs),
		nats.ManualAck(),
		nats.AckWait(w.ackWait),
		nats.MaxDeliver(3),
	)
	if err != nil {
		return fmt.Errorf("worker: consume %s: %w", subject, err)
	}
	defer sub.Unsubscribe()
	w.log.Info("worker consuming", "adapter", w.adapter, "subject", subject, "concurrency", w.conc)
	<-ctx.Done()
	w.wg.Wait()
	return ctx.Err()
}

func (w *Worker) handle(ctx context.Context, msg *nats.Msg) {
	var job scanner.Job
	if err := json.Unmarshal(msg.Data, &job); err != nil {
		w.log.Error("worker: undecodable job — terminal", "err", err)
		_ = msg.Term()
		return
	}
	log := w.log.With("job_id", job.JobID, "task_id", job.TaskID, "adapter", w.adapter)
	adapter := w.reg.Get(job.Adapter)
	if adapter == nil {
		log.Error("worker: no adapter registered")
		w.publishDone(ctx, &job, "FAILED", "no adapter "+job.Adapter)
		_ = msg.Ack()
		return
	}
	if err := adapter.ValidateJob(job); err != nil {
		// Wrapper refusal (e.g. DoS-class) — never retried (doc 04 §10.3).
		log.Warn("worker: job refused by adapter", "err", err)
		w.publishDone(ctx, &job, "FAILED", err.Error())
		_ = msg.Ack()
		return
	}

	_ = msg.InProgress()
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if !job.Deadline.IsZero() {
		jobCtx, cancel = context.WithDeadline(jobCtx, job.Deadline)
		defer cancel()
	}

	// Keep the ack alive while the scanner runs (long jobs outlive AckWait).
	ackDone := make(chan struct{})
	defer close(ackDone)
	go func() {
		t := time.NewTicker(w.ackWait / 3)
		defer t.Stop()
		for {
			select {
			case <-ackDone:
				return
			case <-jobCtx.Done():
				return
			case <-t.C:
				_ = msg.InProgress()
			}
		}
	}()

	// Per-job limiter (doc 04 §10.3): RPS from the job token's caps (seeded by
	// the planner) plus the hard request budget.
	var wait func(ctx context.Context) error
	if job.RPS > 0 {
		lim := rate.NewLimiter(rate.Limit(job.RPS), 1)
		wait = lim.Wait
	}
	limiter := scanner.NewBudgetLimiter(job.RequestBudget, wait)

	emit := scanner.EmitterFunc(func(r scanner.RawResult) error {
		return w.publish(ctx, ResultMessage{
			Kind: "raw", JobID: job.JobID, TaskID: job.TaskID, Result: &r,
		})
	})

	runErr := adapter.Run(jobCtx, job, limiter, emit)
	switch {
	case runErr == nil:
		w.publishDone(ctx, &job, "SUCCEEDED", "")
	case errors.Is(jobCtx.Err(), context.Canceled):
		w.publishDone(ctx, &job, "KILLED", runErr.Error())
	case errors.Is(jobCtx.Err(), context.DeadlineExceeded):
		log.Warn("worker: job deadline — killed scanner, continuing siblings", "err", runErr)
		w.publishDone(ctx, &job, "FAILED", "deadline: "+runErr.Error())
	default:
		// Scanner-level failure: JetStream redelivery is the retry path for
		// infra losses (doc 04 §5.2); a clean adapter error is terminal.
		log.Error("worker: job failed", "err", runErr)
		w.publishDone(ctx, &job, "FAILED", runErr.Error())
	}
	_ = msg.Ack()
}

func (w *Worker) publish(ctx context.Context, m ResultMessage) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	msg := nats.NewMsg(SubjectResults)
	if m.Kind == "raw" && m.Result != nil {
		// Intra-run idempotency: one message per (job, check, matched-at).
		msg.Header.Set(nats.MsgIdHdr, "raw-"+m.JobID+"-"+m.Result.CheckID+"-"+m.Result.MatchedAt)
	} else {
		msg.Header.Set(nats.MsgIdHdr, "done-"+m.JobID+"-"+m.Status)
	}
	msg.Data = data
	if _, err := w.js.PublishMsg(msg, nats.Context(ctx)); err != nil {
		return fmt.Errorf("worker: publish result: %w", err)
	}
	return nil
}

func (w *Worker) publishDone(ctx context.Context, job *scanner.Job, status, errStr string) {
	if err := w.publish(ctx, ResultMessage{
		Kind: "done", JobID: job.JobID, TaskID: job.TaskID, Status: status, Error: errStr,
	}); err != nil {
		w.log.Error("worker: publish done failed", "job_id", job.JobID, "err", err)
	}
}
