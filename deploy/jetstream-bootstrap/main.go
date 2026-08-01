// Command jetstream-bootstrap creates the canonical AegisBastion JetStream
// topology (streams, subjects, consumer-facing QoS) and the NATS KV buckets
// the platform uses for registry leases, per-target intrusive leases and
// rate buckets.
//
// Canonical sources:
//   - doc 01 §8.1 (platform subjects), §6.4 (KV leases/rate buckets)
//   - doc 11 §2.3 (gatekeeper subjects)
//   - doc 03 §3.3/§5 (monitor subjects + retention)
//   - doc 04 §4.3 + Ruling C8 (detect.findings / detect.alert)
//   - doc 05 §5.9 (alert pipeline topics)
//   - doc 09 §2.1/§3.2 (dp.* events)
//   - doc 12 §4.3 re-mapped per Ruling C3 (cross-module topology on JetStream)
//
// The program is idempotent: existing streams/buckets are updated in place.
// control.kill is intentionally NOT a stream — doc 01 §8.1 defines it as a
// core NATS broadcast (no persistence); agents must ACK within 5 s.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/nats-io/nats.go"
)

type streamSpec struct {
	name        string
	description string
	subjects    []string
	retention   nats.RetentionPolicy
	maxAge      time.Duration // 0 = keep
	maxBytes    int64         // 0 = unlimited
	// Consumer-level QoS (ack wait, max redeliveries) is set on the durable
	// consumers each service creates — e.g. doc 03 §3.3's 5 min visibility /
	// 3-redelivery policy on monitor.scan.jobs, and doc 01 §6.3's redelivery
	// on lease expiry for task.assign.*.
}

func streams() []streamSpec {
	const (
		gib = 1 << 30
		h   = time.Hour
	)
	return []streamSpec{
		// --- doc 01 §8.1 platform core -----------------------------------
		{
			name:        "TASK_ASSIGN",
			description: "doc 01 §8.1: Orchestrator → specific agent task assignments (ack-required, redelivery on lease expiry)",
			subjects:    []string{"task.assign.*"},
			retention:   nats.WorkQueuePolicy,
			maxBytes:    gib,
		},
		{
			name:        "TASK_RESULTS",
			description: "doc 01 §8.1: agents → Orchestrator TaskResults (durable, at-least-once; idempotent on task_id)",
			subjects:    []string{"task.result"},
			retention:   nats.LimitsPolicy,
			maxAge:      7 * 24 * h,
			maxBytes:    gib,
		},
		{
			name:        "AGENT_HEARTBEAT",
			description: "doc 01 §8.1: agents → Registry heartbeats (ephemeral, 10 s cadence, 30 s TTL)",
			subjects:    []string{"agent.heartbeat"},
			retention:   nats.LimitsPolicy,
			maxAge:      30 * time.Second,
		},
		{
			name:        "MISSION_EVENTS",
			description: "doc 01 §8.1: Orchestrator → commanders/UI mission events (durable; event-driven replanning)",
			subjects:    []string{"mission.events"},
			retention:   nats.LimitsPolicy,
			maxAge:      7 * 24 * h,
			maxBytes:    gib,
		},
		{
			name:        "AUDIT",
			description: "doc 01 §8.1/§10.4: all services → gatekeeper audit-service (durable, never sampled)",
			subjects:    []string{"audit.events"},
			retention:   nats.LimitsPolicy,
			maxAge:      400 * 24 * h, // audit hot retention (doc 01 §10.4, doc 03 §8)
			maxBytes:    4 * gib,
		},

		// --- doc 11 §2.3 gatekeeper (the single PDP) -----------------------
		{
			name:        "GATEKEEPER",
			description: "doc 11 §2.3: orders in, decisions/denials/RoE events/revocations/approvals/anomalies out (durable)",
			subjects: []string{
				"tasks.orders.v1",
				"authz.decisions.v1",
				"authz.denials.v1",
				"roe.events.v1",
				"tasks.revocations.v1",
				"authz.approvals.v1",
				"audit.anomalies.v1",
			},
			retention: nats.LimitsPolicy,
			maxAge:    30 * 24 * h,
			maxBytes:  gib,
		},

		// --- doc 03 monitor -------------------------------------------------
		{
			name:        "MONITOR_EVENTS",
			description: "doc 03 §3.3/§5: change + new-asset events → commanders, Orchestrator, data platform (durable, 72 h)",
			subjects:    []string{"monitor.changes", "monitor.assets.new"},
			retention:   nats.LimitsPolicy,
			maxAge:      72 * h,
			maxBytes:    gib,
		},
		{
			name:        "MONITOR_JOBS",
			description: "doc 03 §3.3 (module-internal): scheduler → probe workers (workqueue, 5 min visibility, max 3 redeliveries)",
			subjects:    []string{"monitor.scan.jobs"},
			retention:   nats.WorkQueuePolicy,
			maxBytes:    gib,
		},

		// --- doc 04 detect --------------------------------------------------
		{
			name:        "DETECT_FINDINGS",
			description: "doc 04 §4.3: full findings stream → data platform (09), commanders (canonical per Ruling C8)",
			subjects:    []string{"detect.findings"},
			retention:   nats.LimitsPolicy,
			maxAge:      72 * h,
			maxBytes:    gib,
		},
		{
			name:        "DETECT_JOBS",
			description: "doc 04 §5.2/D10 (module-internal): Coordinator → scanner workers, per-adapter work-queue subjects (redelivery on worker loss; idempotent by job_id)",
			subjects:    []string{"detect.jobs.*"},
			retention:   nats.WorkQueuePolicy,
			maxBytes:    gib,
		},
		{
			name:        "DETECT_RESULTS",
			description: "doc 04 §5.2/D10 (module-internal): workers → Coordinator RawResults + job-done markers (durable, task-scoped 24 h TTL for crash resume)",
			subjects:    []string{"detect.results"},
			retention:   nats.LimitsPolicy,
			maxAge:      24 * h,
			maxBytes:    gib,
		},

		// --- doc 05 alert (herald) ingress + pipeline (§5.9) ----------------
		{
			name:        "ALERT_INGRESS",
			description: "doc 05 §5.9: module → herald ingest (*.alert topics + doc 01's alert.outbound; workqueue, 72 h)",
			subjects: []string{
				"detect.alert", // Ruling C8: doc 04's CONFIRMED≥tier mapping
				"monitor.alert",
				"discover.alert",
				"ddos.alert",
				"redteam.alert",
				"phish.alert",
				"alert.outbound", // doc 01 §8.1
			},
			retention: nats.WorkQueuePolicy,
			maxAge:    72 * h,
			maxBytes:  gib,
		},
		{
			name:        "ALERTS_RAW",
			description: "doc 05 §5.9: C1 ingest → C2 enrich (72 h)",
			subjects:    []string{"alerts.raw"},
			retention:   nats.LimitsPolicy,
			maxAge:      72 * h,
			maxBytes:    gib,
		},
		{
			name:        "ALERTS_ENRICHED",
			description: "doc 05 §5.9: C2 → C3 dedup / C4 correlate (72 h)",
			subjects:    []string{"alerts.enriched"},
			retention:   nats.LimitsPolicy,
			maxAge:      72 * h,
			maxBytes:    gib,
		},
		{
			name:        "ALERTS_TASKS",
			description: "doc 05 §5.9: C5 router → C6 per-channel dispatch pools (workqueue, 24 h)",
			subjects:    []string{"alerts.tasks.*"},
			retention:   nats.WorkQueuePolicy,
			maxAge:      24 * h,
			maxBytes:    gib,
		},
		{
			name:        "ALERTS_LIFECYCLE",
			description: "doc 05 §5.9: lifecycle transitions → commanders/audit (7 d)",
			subjects:    []string{"alerts.lifecycle"},
			retention:   nats.LimitsPolicy,
			maxAge:      7 * 24 * h,
			maxBytes:    gib,
		},
		{
			name:        "ALERTS_DLQ",
			description: "doc 05 §5.9: C6 dead letters → ops tooling (30 d)",
			subjects:    []string{"alerts.dlq"},
			retention:   nats.LimitsPolicy,
			maxAge:      30 * 24 * h,
			maxBytes:    gib,
		},

		// --- doc 09 data platform ------------------------------------------
		{
			name:        "DP_EVENTS",
			description: "doc 09 §2.2/§3.2: ingest change events (dp.asset.*, dp.finding.*, dp.task.rollup_finalized) + retention.purged",
			subjects:    []string{"dp.>", "retention.purged"},
			retention:   nats.LimitsPolicy,
			maxAge:      72 * h,
			maxBytes:    gib,
		},

		// --- doc 02 discover module events ----------------------------------
		{
			name:        "DISCOVER_EVENTS",
			description: "doc 02 §3.1: order status + asset-change events",
			subjects:    []string{"hub.discover.order.status_changed", "hub.discover.asset.changed"},
			retention:   nats.LimitsPolicy,
			maxAge:      72 * h,
			maxBytes:    gib,
		},

		// --- doc 01 §9.2 phish-catcher intel feed ---------------------------
		{
			name:        "INTEL_FEEDS",
			description: "doc 01 §9.2: signed phishing-indicator feed bundles (Orchestrator → Phish-Catcher agents)",
			subjects:    []string{"intel.feeds.phishing"},
			retention:   nats.LimitsPolicy,
			maxAge:      7 * 24 * h,
			maxBytes:    gib,
		},

		// --- doc 06 stress engine (MVP-B; topology created now per doc 12 §4.3 / Ruling C3)
		{
			name:        "STRESS",
			description: "doc 12 §4.3 (Ruling C3): commander-facing stress.commands / stress.results, bridged into the Azure fleet by module 06",
			subjects:    []string{"stress.commands", "stress.results"},
			retention:   nats.LimitsPolicy,
			maxAge:      72 * h,
			maxBytes:    gib,
		},
	}
}

type kvSpec struct {
	bucket      string
	description string
	maxAge      time.Duration
}

func kvs() []kvSpec {
	return []kvSpec{
		{
			bucket:      "leases",
			description: "doc 01 §6.4 + Ruling C12: per-target intrusive leases (R2/R3 platform-wide serializer). Keys: target/{sha256(target)}; value TTL = task deadline.",
			maxAge:      24 * time.Hour, // safety net; entries are deleted on release
		},
		{
			bucket:      "rate_buckets",
			description: "doc 01 §6.4: per-RoE token-bucket state (max_rps_per_target, max_concurrent_intrusive) for the Scheduler.",
			maxAge:      time.Hour,
		},
		{
			bucket:      "agent_presence",
			description: "doc 01 §8.1/§6.4: registry presence — heartbeat keys with 30 s TTL.",
			maxAge:      30 * time.Second,
		},
		{
			bucket:      "detect_dedup",
			description: "doc 04 §11 (MVP): Detect cross-run fingerprint dedup KV + per-target buckets.",
			maxAge:      30 * 24 * time.Hour,
		},
	}
}

func main() {
	natsURL := getenv("NATS_URL", "nats://localhost:4222")
	log.Printf("jetstream-bootstrap: connecting to %s", natsURL)

	var nc *nats.Conn
	var err error
	deadline := time.Now().Add(90 * time.Second)
	for {
		nc, err = nats.Connect(natsURL,
			nats.Name("aegisbastion-jetstream-bootstrap"),
			nats.Timeout(5*time.Second),
			nats.RetryOnFailedConnect(false),
		)
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			log.Fatalf("jetstream-bootstrap: could not connect to NATS within 90s: %v", err)
		}
		log.Printf("jetstream-bootstrap: NATS not ready (%v), retrying in 2s", err)
		time.Sleep(2 * time.Second)
	}
	defer nc.Close()

	js, err := nc.JetStream()
	if err != nil {
		log.Fatalf("jetstream-bootstrap: JetStream context: %v", err)
	}

	created, updated := 0, 0
	for _, s := range streams() {
		cfg := &nats.StreamConfig{
			Name:        s.name,
			Description: s.description,
			Subjects:    s.subjects,
			Retention:   s.retention,
			MaxAge:      s.maxAge,
			MaxBytes:    s.maxBytes,
			Storage:     nats.FileStorage,
			Replicas:    1,
			Discard:     nats.DiscardOld,
		}
		if _, err := js.AddStream(cfg); err != nil {
			var apiErr *nats.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode == nats.JSErrCodeStreamNameInUse {
				if _, uerr := js.UpdateStream(cfg); uerr != nil {
					log.Fatalf("jetstream-bootstrap: update stream %s: %v", s.name, uerr)
				}
				updated++
				log.Printf("stream %-16s updated   subjects=%v", s.name, s.subjects)
				continue
			}
			log.Fatalf("jetstream-bootstrap: add stream %s: %v", s.name, err)
		}
		created++
		log.Printf("stream %-16s created   subjects=%v", s.name, s.subjects)
	}

	kvCreated := 0
	for _, k := range kvs() {
		cfg := &nats.KeyValueConfig{
			Bucket:      k.bucket,
			Description: k.description,
			TTL:         k.maxAge,
			History:     1,
			Storage:     nats.FileStorage,
			Replicas:    1,
		}
		if _, err := js.CreateKeyValue(cfg); err != nil {
			var apiErr *nats.APIError
			if errors.As(err, &apiErr) && apiErr.ErrorCode == nats.JSErrCodeStreamNameInUse {
				log.Printf("kv    %-16s exists", k.bucket)
				continue
			}
			log.Fatalf("jetstream-bootstrap: create kv %s: %v", k.bucket, err)
		}
		kvCreated++
		log.Printf("kv    %-16s created", k.bucket)
	}

	fmt.Printf("\njetstream-bootstrap: done — %d streams created, %d updated, %d KV buckets created\n",
		created, updated, kvCreated)
	fmt.Println("note: control.kill is a core NATS broadcast subject (doc 01 §8.1) — no stream by design")
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
