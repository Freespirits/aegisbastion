// Package jobs is the module-internal scan-job work queue (doc 03 §3.3):
// the scheduler publishes one job per due asset onto monitor.scan.jobs
// (JetStream WorkQueue, ack-required, 5 min visibility, max 3 redeliveries);
// probe workers consume, verify the carried scope-bound watch token per job
// (doc 03 §9.2 — no token, no probe), execute, and dead-letter poison or
// unauthorized jobs into monitor.scan_jobs_dead with an audit record.
//
// The wire form is module-private JSON (doc 03 §3.3: internal subjects are
// module-private; cross-module contracts use the §5 envelopes).
package jobs

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/nats-io/nats.go"
)

// Subject is the internal work-queue subject (stream MONITOR_JOBS).
const Subject = "monitor.scan.jobs"

// Stream is the JetStream work-queue stream (provisioned by
// deploy/jetstream-bootstrap).
const Stream = "MONITOR_JOBS"

// Durable is the shared worker consumer (queue group) name.
const Durable = "monitor-workers"

// AckWait is the 5 min visibility timeout (doc 03 §3.3).
const AckWait = 5 * time.Minute

// MaxDeliver is the redelivery cap before dead-lettering (doc 03 §3.3: 3).
const MaxDeliver = 3

// Job is one scan unit: up to 25 probes for ONE asset across the due probe
// types (doc 03 §11 — keeps per-target concurrency at 1 naturally).
type Job struct {
	JobID string `json:"job_id"`

	// Authorization context: the scope-bound watch token the worker verifies
	// per job (doc 03 §9.2) + the task/capability it must bind to.
	AuthorizationToken string `json:"authorization_token"`
	TaskID             string `json:"task_id"`
	Capability         string `json:"capability"` // monitor.watch | monitor.rescan

	// Event-enrichment context (doc 03 §5.1).
	WatchID    string `json:"watch_id,omitempty"`
	MissionID  string `json:"mission_id"`
	ROEID      string `json:"roe_id"`
	ROEVersion uint64 `json:"roe_version,omitempty"`
	OrgID      string `json:"org_id,omitempty"`

	// Asset + probe plan.
	AssetID     string   `json:"asset_id,omitempty"`
	Identifier  string   `json:"identifier"`
	Kind        string   `json:"kind,omitempty"`
	Criticality string   `json:"criticality,omitempty"`
	ProbeTypes  []string `json:"probe_types"`

	// Watch params.
	BaselineID         string `json:"baseline_id,omitempty"`
	AlertThreshold     string `json:"alert_threshold,omitempty"`
	EmissionCapPerHour uint32 `json:"emission_cap_per_hour,omitempty"`
	CadenceProfile     string `json:"cadence_profile,omitempty"`

	// Behavior flags.
	ReportEvents bool   `json:"report_events"`
	Reactivation bool   `json:"reactivation,omitempty"`
	Reason       string `json:"reason,omitempty"`
}

// Marshal renders the wire bytes.
func (j *Job) Marshal() ([]byte, error) { return json.Marshal(j) }

// ParseJob decodes the wire bytes.
func ParseJob(data []byte) (*Job, error) {
	var j Job
	if err := json.Unmarshal(data, &j); err != nil {
		return nil, fmt.Errorf("jobs: decode: %w", err)
	}
	if j.JobID == "" || j.Identifier == "" {
		return nil, fmt.Errorf("jobs: job missing job_id/identifier")
	}
	return &j, nil
}

// Publisher emits scan jobs (dedup on Nats-Msg-Id = job id).
type Publisher struct {
	js nats.JetStreamContext
}

// NewPublisher wraps a JetStream context.
func NewPublisher(js nats.JetStreamContext) *Publisher { return &Publisher{js: js} }

// Publish queues one job.
func (p *Publisher) Publish(ctx context.Context, j *Job) error {
	data, err := j.Marshal()
	if err != nil {
		return err
	}
	msg := nats.NewMsg(Subject)
	msg.Header.Set(nats.MsgIdHdr, "job-"+j.JobID)
	msg.Data = data
	_, err = p.js.PublishMsg(msg, nats.Context(ctx))
	if err != nil {
		return fmt.Errorf("jobs: publish %s: %w", j.JobID, err)
	}
	return nil
}

// Disposition settles a consumed job.
type Disposition int

const (
	// Ack settles the job (executed or intentionally skipped).
	Ack Disposition = iota
	// Nak redelivers (transient infra failure).
	Nak
	// Term settles permanently (poison / unauthorized — caller dead-letters).
	Term
)

// Handler processes one job; deliveries is the JetStream delivery count
// (≥ 2 means a redelivery).
type Handler func(ctx context.Context, j *Job, deliveries int) Disposition

// Consume attaches handler to the shared worker queue (durable, explicit
// acks, 5 min visibility, max 3 deliveries per doc 03 §3.3). The handler runs
// on the NATS callback goroutine — implementations offload to worker pools.
func Consume(js nats.JetStreamContext, h Handler) (*nats.Subscription, error) {
	sub, err := js.Subscribe(Subject, func(msg *nats.Msg) {
		md, _ := msg.Metadata()
		deliveries := 1
		if md != nil {
			deliveries = int(md.NumDelivered)
		}
		j, err := ParseJob(msg.Data)
		if err != nil {
			_ = msg.Term() // unparseable jobs are poison
			return
		}
		switch h(context.Background(), j, deliveries) {
		case Ack:
			_ = msg.Ack()
		case Nak:
			_ = msg.Nak()
		case Term:
			_ = msg.Term()
		}
	},
		nats.Durable(Durable),
		nats.BindStream(Stream),
		nats.ManualAck(),
		nats.AckWait(AckWait),
		nats.MaxDeliver(MaxDeliver),
	)
	if err != nil {
		return nil, fmt.Errorf("jobs: consume %s: %w", Subject, err)
	}
	return sub, nil
}
