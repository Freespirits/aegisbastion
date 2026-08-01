// Package streamer is the M6 Event Streamer (doc 03 §3.1): dedup (24 h
// fingerprint window), emission-rate caps with burst aggregation, suppression
// checks, the transactional change_events + event_outbox write (doc 03 §8),
// and the outbox relay that publishes monitor.changes / monitor.alert /
// monitor.assets.new onto the bus.
//
// Emission discipline (doc 03 §8/§11/§12, §15 acceptance 5):
//   - dedup repeats inside the 24 h window write nothing (count++ only);
//   - operator suppressions and the per-mission emission cap gate OUTBOUND
//     emission only — the change_events history row is still written
//     ("suppressions never delete events"; "zero event loss under the cap");
//   - cap overflow aggregates into monitor.change_burst events.
package streamer

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	monitorv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/monitor/v1"
	sdkbus "github.com/aegisbastion/aegisbastion/sdks/go/bus"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/alertmap"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/events"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/store"
)

// Bus subjects (doc 03 §3.3 — streams provisioned by jetstream-bootstrap).
const (
	SubjectChanges   = "monitor.changes"
	SubjectAlert     = "monitor.alert"
	SubjectAssetsNew = "monitor.assets.new"
)

// Publisher publishes one pre-built bus message (raw bytes + msg id) — the
// outbox relay's bus adapter (production: JetStream; tests: fake).
type Publisher interface {
	PublishRaw(ctx context.Context, subject, msgID string, data []byte) error
}

// Config tunes M6.
type Config struct {
	// DefaultEmissionCapPerMissionHour — doc 03 §11 default 500 events/h.
	DefaultEmissionCapPerMissionHour int
	// GlobalCeilingPerMinute — platform emission ceiling (doc 03 §11: 10 k/min).
	GlobalCeilingPerMinute int
	// Now — clock injection (tests).
	Now func() time.Time
}

// Outcome is the disposition of one submitted change.
type Outcome string

const (
	OutcomeEmitted         Outcome = "emitted"          // written + outboxed
	OutcomeSuppressedDedup Outcome = "suppressed_dedup" // live 24 h window repeat
	OutcomeSuppressedRule  Outcome = "suppressed_rule"  // operator suppression
	OutcomeSuppressedCap   Outcome = "suppressed_cap"   // emission cap overflow (history kept)
)

// Counters roll up streamer activity for checkpoints and /metrics.
type Counters struct {
	Emitted    uint64
	Deduped    uint64
	Suppressed uint64
	Capped     uint64
	Bursts     uint64
	Relayed    uint64
	RelayErrs  uint64
}

// AuditDecision records one emission/suppression decision (doc 03 §9.6).
type AuditDecision struct {
	EventID     string
	Fingerprint string
	Outcome     Outcome
	Reason      string
	ChangeType  string
	AssetID     string
}

// AuditSink receives emission decisions; the coordinator forwards them to
// audit.events (nil-safe).
type AuditSink interface {
	EmissionDecision(ctx context.Context, d AuditDecision)
}

// burstAgg aggregates cap overflow per mission.
type burstAgg struct {
	byType      map[string]int
	byAsset     map[string]int
	total       int
	windowStart time.Time
}

// Streamer is M6.
type Streamer struct {
	st    *store.Store
	cfg   Config
	audit AuditSink

	mu                sync.Mutex
	counters          Counters
	globalMinuteStart time.Time
	globalMinuteCount int
	bursts            map[string]*burstAgg
}

// New builds a Streamer.
func New(st *store.Store, cfg Config, audit AuditSink) *Streamer {
	if cfg.DefaultEmissionCapPerMissionHour <= 0 {
		cfg.DefaultEmissionCapPerMissionHour = 500
	}
	if cfg.GlobalCeilingPerMinute <= 0 {
		cfg.GlobalCeilingPerMinute = 10000
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Streamer{st: st, cfg: cfg, bursts: map[string]*burstAgg{}, audit: audit}
}

// Counters returns a snapshot of the rollup counters.
func (s *Streamer) Counters() Counters {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.counters
}

// SetAuditSink installs the emission-decision audit sink (post-construction,
// when the sink needs the streamer itself — coordinator).
func (s *Streamer) SetAuditSink(a AuditSink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audit = a
}

// SubmitInput is one change event plus its watch alert context.
type SubmitInput struct {
	Change *monitorv1.MonitorChange
	// Alert carries the watch's alert mapping params (threshold, token jti,
	// passive flag, RoE id, PII classification).
	Alert alertmap.Params
	// EmissionCapPerHour overrides the per-mission cap (watch param;
	// 0 = default).
	EmissionCapPerHour uint32
}

// Submit persists one change and gates its outbound emission (doc 03 §7.1
// tail, §8, §11). It never fails open: on any store error the change is NOT
// emitted and the error propagates to the caller (job nacked for redelivery).
func (s *Streamer) Submit(ctx context.Context, in SubmitInput) (Outcome, error) {
	mc := in.Change
	if mc == nil {
		return "", fmt.Errorf("streamer: nil change")
	}
	now := s.cfg.Now()
	changeType := events.ChangeTypeString(mc.GetChangeType())

	// 1. Dedup window (24 h): a repeat increments the window count and is not
	// re-persisted/re-emitted (doc 03 §8 dedup_window).
	hit, dup, err := s.st.DedupCheckInsert(ctx, mc.GetFingerprint(), mc.GetEventId(), now)
	if err != nil {
		return "", fmt.Errorf("streamer: dedup: %w", err)
	}
	if dup {
		s.mu.Lock()
		s.counters.Deduped++
		s.mu.Unlock()
		s.auditDecision(ctx, mc, OutcomeSuppressedDedup,
			fmt.Sprintf("fingerprint live in 24h window (first=%s count=%d)", hit.FirstEventID, hit.Count))
		return OutcomeSuppressedDedup, nil
	}

	// 2. Operator suppressions gate OUTBOUND emission only (doc 03 §8).
	suppressed, reason, err := s.st.IsSuppressed(ctx,
		mc.GetMissionId(), mc.GetAsset().GetAssetId(),
		mc.GetDiff().GetFields()["rule_id"].GetStringValue(), changeType, now)
	if err != nil {
		return "", fmt.Errorf("streamer: suppressions: %w", err)
	}

	// 3. Emission caps (per-mission hourly + global per-minute ceiling).
	capPerHour := int(in.EmissionCapPerHour)
	if capPerHour <= 0 {
		capPerHour = s.cfg.DefaultEmissionCapPerMissionHour
	}
	capped := false
	if !suppressed {
		n, err := s.st.CountRecentEvents(ctx, mc.GetMissionId(), now.Add(-time.Hour))
		if err != nil {
			return "", fmt.Errorf("streamer: cap count: %w", err)
		}
		if n >= capPerHour || !s.globalBudget(now) {
			capped = true
		}
	}

	outcome := OutcomeEmitted
	switch {
	case suppressed:
		outcome = OutcomeSuppressedRule
	case capped:
		outcome = OutcomeSuppressedCap
	}

	// 4. Build outbox rows (none when gated) + persist tx (doc 03 §8).
	var outbox []store.OutboxRow
	if outcome == OutcomeEmitted {
		changesMsg, err := BuildChangesMessage(mc)
		if err != nil {
			return "", err
		}
		outbox = append(outbox, store.OutboxRow{
			EventID: mc.GetEventId(), Subject: SubjectChanges,
			MissionID: mc.GetMissionId(), Data: changesMsg,
		})
		if alertmap.ShouldAlert(mc, in.Alert) {
			alertBytes, alertID, err := alertmap.Map(mc, in.Alert, now)
			if err != nil {
				return "", fmt.Errorf("streamer: alert mapping: %w", err)
			}
			outbox = append(outbox, store.OutboxRow{
				EventID: alertID, Subject: SubjectAlert,
				MissionID: mc.GetMissionId(), Data: alertBytes,
			})
		}
	}

	payload, err := MarshalChange(mc)
	if err != nil {
		return "", err
	}
	err = s.st.InsertEventWithOutbox(ctx, nil,
		mc.GetEventId(), mc.GetMissionId(), mc.GetAsset().GetAssetId(),
		changeType, events.SeverityString(mc.GetSeverity()), mc.GetFingerprint(),
		payload, mc.GetOccurredAt().AsTime(), outbox)
	if err != nil {
		return "", fmt.Errorf("streamer: persist: %w", err)
	}

	s.mu.Lock()
	switch outcome {
	case OutcomeEmitted:
		s.counters.Emitted++
	case OutcomeSuppressedRule:
		s.counters.Suppressed++
	case OutcomeSuppressedCap:
		s.counters.Capped++
	}
	s.mu.Unlock()
	if outcome == OutcomeSuppressedCap {
		s.aggregateBurst(mc, changeType, now)
	}
	if outcome != OutcomeEmitted {
		s.auditDecision(ctx, mc, outcome, reason)
	}
	return outcome, nil
}

// SubmitCandidate publishes one NewAssetCandidate on monitor.assets.new
// (doc 03 §5.4 — out-of-scope candidates are emitted too, metadata only,
// scope_match carries the classification).
func (s *Streamer) SubmitCandidate(ctx context.Context, nc *monitorv1.NewAssetCandidate) error {
	msg, err := BuildEnvelope(SubjectAssetsNew, nc, nc.GetEventId(), nc.GetMissionId())
	if err != nil {
		return err
	}
	payload, err := protojson.Marshal(nc)
	if err != nil {
		return fmt.Errorf("streamer: candidate json: %w", err)
	}
	return s.st.InsertEventWithOutbox(ctx, nil,
		nc.GetEventId(), nc.GetMissionId(), zeroUUID, "asset.new", "info",
		"candidate:"+nc.GetCandidate().GetIdentifier(),
		payload, s.cfg.Now(), []store.OutboxRow{{
			EventID: nc.GetEventId(), Subject: SubjectAssetsNew,
			MissionID: nc.GetMissionId(), Data: msg,
		}})
}

// zeroUUID satisfies the change_events.asset_id NOT NULL uuid column for
// candidate/burst rows that do not reference an inventory asset.
const zeroUUID = "00000000-0000-0000-0000-000000000000"

// Relay publishes pending outbox rows in batches (doc 03 §11: 500 msg/batch)
// and marks them published. At-least-once: consumers dedup on event_id /
// Nats-Msg-Id (doc 01 §8.2).
func (s *Streamer) Relay(ctx context.Context, pub Publisher, batch int) (int, error) {
	if batch <= 0 {
		batch = 500
	}
	rows, err := s.st.OutboxPending(ctx, batch)
	if err != nil {
		return 0, fmt.Errorf("streamer: outbox pending: %w", err)
	}
	sent := 0
	for _, row := range rows {
		if err := pub.PublishRaw(ctx, row.Subject, row.EventID, row.Data); err != nil {
			s.mu.Lock()
			s.counters.RelayErrs++
			s.mu.Unlock()
			return sent, fmt.Errorf("streamer: publish %s %s: %w", row.Subject, row.EventID, err)
		}
		if err := s.st.OutboxMarkPublished(ctx, row.EventID); err != nil {
			return sent, fmt.Errorf("streamer: mark published: %w", err)
		}
		sent++
	}
	s.mu.Lock()
	s.counters.Relayed += uint64(sent)
	s.mu.Unlock()
	return sent, nil
}

// RunRelay is the relay loop (ticker-driven until ctx is done).
func (s *Streamer) RunRelay(ctx context.Context, pub Publisher, interval time.Duration) {
	if interval <= 0 {
		interval = time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		_, _ = s.Relay(ctx, pub, 500)
	}
}

// ---------------------------------------------------------------------------
// burst aggregation (doc 03 §11/§12: cap overflow → monitor.change_burst)
// ---------------------------------------------------------------------------

func (s *Streamer) aggregateBurst(mc *monitorv1.MonitorChange, changeType string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bursts[mc.GetMissionId()]
	if !ok {
		b = &burstAgg{byType: map[string]int{}, byAsset: map[string]int{}, windowStart: now}
		s.bursts[mc.GetMissionId()] = b
	}
	b.byType[changeType]++
	b.byAsset[mc.GetAsset().GetIdentifier()]++
	b.total++
}

// FlushBursts emits pending monitor.change_burst aggregate events older than
// maxAge (called periodically by the coordinator; doc 03 §5.2 Meta group).
func (s *Streamer) FlushBursts(ctx context.Context, maxAge time.Time, detector events.ChangeCtx) error {
	s.mu.Lock()
	type pending struct {
		mission string
		agg     *burstAgg
	}
	var flush []pending
	for mission, b := range s.bursts {
		if !b.windowStart.After(maxAge) && b.total > 0 {
			flush = append(flush, pending{mission, b})
			delete(s.bursts, mission)
		}
	}
	s.mu.Unlock()

	for _, p := range flush {
		topAssets := topN(p.agg.byAsset, 10)
		typeCounts := map[string]any{}
		for t, n := range p.agg.byType {
			typeCounts[t] = n
		}
		diffStruct, err := events.StructPB(map[string]any{
			"kind":   "emission_cap",
			"before": map[string]any{},
			"after": map[string]any{
				"suppressed_total": p.agg.total,
				"by_type":          typeCounts,
				"top_assets":       topAssets,
			},
			"rule_id": "",
		})
		if err != nil {
			return err
		}
		now := s.cfg.Now()
		mc := &monitorv1.MonitorChange{
			SchemaVersion: events.SchemaVersion,
			EventId:       events.NewID("chg"),
			MissionId:     p.mission,
			RoeId:         detector.ROEID,
			OrgId:         detector.OrgID,
			Asset: &monitorv1.MonitoredAsset{
				AssetId:    zeroUUID,
				Kind:       monitorv1.AssetKind_ASSET_KIND_DOMAIN,
				Identifier: "(mission aggregate)",
			},
			ChangeType: monitorv1.ChangeType_CHANGE_TYPE_MONITOR_CHANGE_BURST,
			Severity:   monitorv1.Severity_SEVERITY_MEDIUM,
			Confidence: monitorv1.Confidence_CONFIDENCE_CONFIRMED,
			Summary: fmt.Sprintf("emission cap engaged: %d change events aggregated in the last window",
				p.agg.total),
			Diff: diffStruct,
			Fingerprint: events.Fingerprint(p.mission, zeroUUID, "monitor.change_burst",
				p.agg.windowStart.Format("2006010215")),
			FirstSeenAt: timestamppb.New(p.agg.windowStart),
			OccurredAt:  timestamppb.New(now),
			Detector: &monitorv1.Detector{
				WorkerId: detector.WorkerID, WatchId: detector.WatchID,
			},
			Labels: map[string]string{"source": "active_probe"},
		}
		// Bypass the cap path (a burst must never aggregate into itself):
		// straight to change_events + outbox.
		msg, err := BuildChangesMessage(mc)
		if err != nil {
			return err
		}
		payload, err := MarshalChange(mc)
		if err != nil {
			return err
		}
		if err := s.st.InsertEventWithOutbox(ctx, nil,
			mc.GetEventId(), mc.GetMissionId(), zeroUUID, "monitor.change_burst",
			"medium", mc.GetFingerprint(), payload, now, []store.OutboxRow{{
				EventID: mc.GetEventId(), Subject: SubjectChanges,
				MissionID: mc.GetMissionId(), Data: msg,
			}}); err != nil {
			return fmt.Errorf("streamer: flush burst %s: %w", p.mission, err)
		}
		s.mu.Lock()
		s.counters.Bursts++
		s.mu.Unlock()
	}
	return nil
}

func (s *Streamer) globalBudget(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now.Sub(s.globalMinuteStart) >= time.Minute {
		s.globalMinuteStart = now
		s.globalMinuteCount = 0
	}
	if s.globalMinuteCount >= s.cfg.GlobalCeilingPerMinute {
		return false
	}
	s.globalMinuteCount++
	return true
}

func (s *Streamer) auditDecision(ctx context.Context, mc *monitorv1.MonitorChange, o Outcome, reason string) {
	if s.audit == nil {
		return
	}
	s.audit.EmissionDecision(ctx, AuditDecision{
		EventID: mc.GetEventId(), Fingerprint: mc.GetFingerprint(),
		Outcome: o, Reason: reason,
		ChangeType: events.ChangeTypeString(mc.GetChangeType()),
		AssetID:    mc.GetAsset().GetAssetId(),
	})
}

func topN(m map[string]int, n int) []string {
	type kv struct {
		k string
		v int
	}
	var all []kv
	for k, v := range m {
		all = append(all, kv{k, v})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].v > all[j].v })
	out := make([]string, 0, n)
	for i, e := range all {
		if i >= n {
			break
		}
		out = append(out, fmt.Sprintf("%s(%d)", e.k, e.v))
	}
	return out
}

// ---------------------------------------------------------------------------
// bus-wire forms
// ---------------------------------------------------------------------------

// BuildEnvelope renders payload in the doc 01 §8.2 protobuf Envelope with
// Nats-Msg-Id dedup identity eventID (sdks/go bus form, outbox-friendly).
func BuildEnvelope(subject string, payload proto.Message, eventID, missionID string) ([]byte, error) {
	msg, err := sdkbus.BuildMessage(subject, payload, sdkbus.PublishOptions{
		MissionID: missionID,
		EventID:   eventID,
	})
	if err != nil {
		return nil, err
	}
	return msg.Data, nil
}

// BuildChangesMessage renders the monitor.changes bus message bytes
// (protobuf Envelope per doc 03 §3.3).
func BuildChangesMessage(mc *monitorv1.MonitorChange) ([]byte, error) {
	return BuildEnvelope(SubjectChanges, mc, mc.GetEventId(), mc.GetMissionId())
}

// MarshalChange renders the MonitorChange JSON form persisted in
// change_events.payload.
func MarshalChange(mc *monitorv1.MonitorChange) ([]byte, error) {
	b, err := protojson.Marshal(mc)
	if err != nil {
		return nil, fmt.Errorf("streamer: change json: %w", err)
	}
	return b, nil
}
