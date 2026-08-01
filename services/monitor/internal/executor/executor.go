// Package executor is the M3/M4/M5 worker pipeline (doc 03 §3.2): one
// authorized scan job flows authorize → probe → normalize → persist snapshot
// → typed diff (M4) → baseline/exposure rules (M5) → change events (via M6
// streamer). Probing is fail-closed: every probe's target contact goes
// through the caller-provided Authorize function (the PEP guard); a passive
// (R0) request performs ZERO target contact (Ruling A.1 passive-only mode).
package executor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/alertmap"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/diff"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/events"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/normalize"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/probes"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/rawstore"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/rules"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/store"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/streamer"
)

// Cadence intervals per profile (doc 03 §6.4). tcp_port is Later.
type Profile struct {
	DNS  time.Duration
	HTTP time.Duration // tls shares the http slot per doc 03 §6.4
	TCP  time.Duration
}

// Profiles are the fixed cadence profiles (no adaptive learning at MVP).
var Profiles = map[string]Profile{
	"fast":     {DNS: 5 * time.Minute, HTTP: 5 * time.Minute, TCP: 15 * time.Minute},
	"standard": {DNS: 15 * time.Minute, HTTP: 30 * time.Minute, TCP: 6 * time.Hour},
	"daily":    {DNS: time.Hour, HTTP: 24 * time.Hour, TCP: 24 * time.Hour},
}

// minInterval floors per-asset cadence (doc 03 §6.4 absolute floor 1 min).
const minInterval = time.Minute

// fastEscalation is the post-change fast-cadence window (doc 03 §6.4: 48 h).
const fastEscalation = 48 * time.Hour

// failingWindow is the persistence window for probe-failing / asset.removed
// (doc 03 §12: consecutive failures > 24 h).
const failingWindow = 24 * time.Hour

// ReactivationInterval is how often parked assets are re-checked
// (doc 03 §12: parked assets are kept for reactivation detection).
const ReactivationInterval = 6 * time.Hour

// needsConfirm marks state-transition change types requiring 2 consecutive
// agreeing probes (doc 03 §7.1). Single-probe facts (cert expiry, record-set
// diffs, dangling CNAME) are 1-shot.
var needsConfirm = map[string]bool{
	"http.status_changed":          true,
	"http.redirect_target_changed": true,
	"tls.protocol_downgrade":       true,
	"tls.hostname_mismatch":        true,
	"port.opened":                  true,
	"port.closed":                  true,
}

// AuthorizeFn authorizes one probe's target contact (the PEP guard's
// AuthorizeTarget). probeType flows into the TARGET_TOUCHED audit extra
// (doc 03 §9.6). Nil means passive mode — zero target contact.
type AuthorizeFn func(ctx context.Context, probeType, target string) error

// Config wires an Executor.
type Config struct {
	WorkerID string
	Region   string
	Now      func() time.Time
}

// Executor runs scan jobs. Safe for concurrent use (all state via store).
type Executor struct {
	cfg      Config
	st       *store.Store
	probes   map[string]probes.Probe
	raw      rawstore.Uploader
	streamer *streamer.Streamer
}

// New builds an Executor.
func New(cfg Config, st *store.Store, probeSet []probes.Probe, raw rawstore.Uploader, sm *streamer.Streamer) *Executor {
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Executor{
		cfg: cfg, st: st,
		probes: probes.ByType(probeSet), raw: raw, streamer: sm,
	}
}

// ScanRequest is one asset scan (from a watch scan job or a rescan order).
type ScanRequest struct {
	// Task/Watch context (empty TaskID for internal reactivation sweeps).
	TaskID  string
	WatchID string
	// Mission/RoE context (event enrichment, doc 03 §5.1).
	MissionID  string
	ROEID      string
	ROEVersion uint64
	OrgID      string
	// Asset identity. AssetID empty → resolved/registered from Identifier.
	Asset events.AssetCtx
	// ProbeTypes to run when due (subset of dns/tls/http).
	ProbeTypes []string
	// Watch params.
	BaselineID         string
	AlertThreshold     string
	EmissionCapPerHour uint32
	CadenceProfile     string
	// Authorization. TokenJTI stamps snapshot authorization + alert mapping.
	TokenJTI  string
	Authorize AuthorizeFn
	// Passive runs passive-only mode: no probing, cached-data diffing only
	// (Ruling A.1 — R0 missions; zero target contact).
	Passive bool
	// ReportEvents=false suppresses event emission (snapshot update only —
	// rescan report_events=false, doc 03 §4.2).
	ReportEvents bool
	// Reactivation marks a parked-asset re-check (doc 03 §12).
	Reactivation bool
}

// Outcome rolls up one scan for checkpoints/metrics.
type Outcome struct {
	ProbesRun        int
	ProbesFailed     int
	EventsEmitted    int
	EventsSuppressed int
	ExposuresOpened  int
	ExposuresClosed  int
	Unauthorized     bool
	UnauthorizedErr  string
}

// ScanAsset executes one scan job. Errors are infrastructure failures (job
// redelivery territory); probe-level failures live in snapshot statuses.
func (e *Executor) ScanAsset(ctx context.Context, req ScanRequest) (Outcome, error) {
	var out Outcome
	now := e.cfg.Now()

	// Resolve/register the watch-asset row (rescan targets join the watch set
	// so snapshots and cadence work uniformly).
	wa, err := e.ensureWatchAsset(ctx, req, now)
	if err != nil {
		return out, err
	}
	req.Asset.AssetID = wa.AssetID
	if req.Asset.Identifier == "" {
		req.Asset.Identifier = wa.Identifier
	}
	if req.Asset.Criticality == "" {
		req.Asset.Criticality = "medium"
	}

	if req.Passive {
		// Ruling A.1 passive-only mode: ZERO target contact. Rules still
		// evaluate over the cached snapshot set; no probes run.
		if err := e.evaluateRules(ctx, req, nil, &out); err != nil {
			return out, err
		}
		return out, nil
	}

	profile := Profiles[req.CadenceProfile]
	if profile.DNS == 0 {
		profile = Profiles["standard"]
	}
	fast := wa.FastUntil != nil && wa.FastUntil.After(now)

	for _, pt := range req.ProbeTypes {
		p, ok := e.probes[pt]
		if !ok {
			continue
		}
		if !e.probeDue(ctx, req.Asset.AssetID, pt, profile, fast, now, req.Reactivation) {
			continue
		}

		// PEP gate — per probe, before ANY network I/O (doc 03 §9.2).
		if req.Authorize == nil {
			out.Unauthorized = true
			out.UnauthorizedErr = "no authorization function (fail-closed)"
			return out, nil
		}
		if err := req.Authorize(ctx, pt, req.Asset.Identifier); err != nil {
			out.Unauthorized = true
			out.UnauthorizedErr = err.Error()
			return out, nil // denial is audit-logged by the guard; do not contact
		}

		res, err := p.Probe(ctx, probes.Request{
			Target: req.Asset.Identifier, AssetID: req.Asset.AssetID,
			MissionID: req.MissionID, ROEID: req.ROEID, ROEVersion: req.ROEVersion,
			TokenJTI: req.TokenJTI, WorkerID: e.cfg.WorkerID, Now: now,
		})
		out.ProbesRun++
		if err != nil {
			out.ProbesFailed++
			return out, fmt.Errorf("executor: %s probe on %s: %w", pt, req.Asset.Identifier, err)
		}
		doc := res.Doc
		doc.SnapshotID = events.NewID("snp")

		// Raw body: PII-redact (doc 03 §9.5) then upload (doc 03 §8 M9);
		// MinIO outage → raw_pending (doc 03 §12).
		if len(res.RawBody) > 0 && doc.Data.HTTP != nil {
			redacted, hits := normalize.RedactPII(res.RawBody, nil)
			doc.Data.HTTP.PIIHits = hits
			if ref, err := e.raw.Upload(ctx, req.MissionID, req.Asset.AssetID,
				doc.SnapshotID, redacted, now); err != nil {
				doc.Data.HTTP.RawPending = true
			} else {
				doc.Data.HTTP.RawRef = ref
			}
		}
		if err := doc.ComputeContentHash(); err != nil {
			return out, err
		}

		if err := e.processObservation(ctx, req, wa, doc, &out, now); err != nil {
			return out, err
		}
	}

	// M5: baseline + exposure evaluation over the refreshed snapshot set.
	if err := e.evaluateRules(ctx, req, wa, &out); err != nil {
		return out, err
	}

	// Reschedule (watch path only — rescan leaves cadence alone).
	if !req.Reactivation {
		if err := e.reschedule(ctx, req, wa, profile, now); err != nil {
			return out, err
		}
	}
	return out, nil
}

// processObservation runs the doc 03 §7.1 diff pipeline for one probe result.
func (e *Executor) processObservation(ctx context.Context, req ScanRequest, wa *store.WatchAsset,
	doc *snapshot.Document, out *Outcome, now time.Time) error {

	latest, err := e.st.GetLatest(ctx, req.Asset.AssetID, doc.ProbeType)
	if err != nil {
		return err
	}

	// Probe failure / NXDOMAIN: persistence-window handling (doc 03 §12).
	if doc.Status != snapshot.StatusOK {
		out.ProbesFailed++
		return e.handleFailure(ctx, req, wa, doc, latest, out, now)
	}

	// Success clears the failing streak.
	if wa.FailingSince != nil {
		if err := e.st.SetFailing(ctx, wa.RowUUID, nil); err != nil {
			return err
		}
		wa.FailingSince = nil
	}

	// Parked asset came back (doc 03 §12 reactivation).
	if wa.State == "paused" {
		if err := e.st.SetWatchState(ctx, wa.RowUUID, "active"); err != nil {
			return err
		}
		wa.State = "active"
		e.emitSimple(ctx, req, diff.Change{
			Type: "asset.reactivated", Severity: diff.SevLow, Confidence: diff.ConfConfirmed,
			Summary:  fmt.Sprintf("asset %s is reachable again", req.Asset.Identifier),
			DiffKind: "asset_lifecycle", DiffKey: "reactivated",
		}, "", doc.SnapshotID, now, out)
	}

	prevHash := ""
	prevSnapID := ""
	var prevDoc *snapshot.Document
	if latest != nil {
		prevHash, prevSnapID = latest.ContentHash, latest.SnapshotID
		if prevHash == doc.ContentHash {
			// Equal → touch last_seen, confirm any parked transitions
			// (doc 03 §7.1 "equal → update last_seen, done").
			if err := e.st.TouchLatest(ctx, req.Asset.AssetID, doc.ProbeType, now, doc.Status); err != nil {
				return err
			}
			return e.confirmPending(ctx, req, doc, prevSnapID, out, now)
		}
		raw, err := e.st.SnapshotData(ctx, prevSnapID)
		if err != nil {
			return err
		}
		if len(raw) > 0 {
			prevDoc = &snapshot.Document{}
			if err := json.Unmarshal(raw, prevDoc); err != nil {
				return fmt.Errorf("executor: prev snapshot %s: %w", prevSnapID, err)
			}
		}
	}

	// Changed (or first observation): persist snapshot (latest + history).
	if err := e.persistSnapshot(ctx, doc); err != nil {
		return err
	}
	if prevDoc == nil {
		return nil // first observation — no events (doc 03 §7.1)
	}

	// Typed diff (M4).
	opts := diff.Options{Now: now, Criticality: req.Asset.Criticality, Passive: req.Passive}
	candidates := diff.Snapshots(prevDoc, doc, opts)
	changed := false
	for _, c := range candidates {
		if c.Silent {
			continue // sub-threshold: snapshot updated silently (doc 03 §7.2)
		}
		changed = true
		if needsConfirm[c.Type] {
			// Park for 2-consecutive confirmation (doc 03 §7.1).
			payload, err := json.Marshal(c)
			if err != nil {
				return err
			}
			fp := events.Fingerprint(req.MissionID, req.Asset.AssetID, c.Type, c.DiffKey)
			if err := e.st.PendingUpsert(ctx, req.Asset.AssetID, doc.ProbeType,
				c.DiffKey, fp, doc.ContentHash, payload, now); err != nil {
				return err
			}
			continue
		}
		e.emitSimple(ctx, req, c, prevSnapID, doc.SnapshotID, now, out)
	}
	if changed {
		// Post-change fast-cadence escalation (doc 03 §6.4).
		if err := e.st.SetFastUntil(ctx, wa.RowUUID, now.Add(fastEscalation)); err != nil {
			return err
		}
	}
	return nil
}

// confirmPending emits parked transitions whose new state persisted to a
// second consecutive probe (doc 03 §7.1 2-consecutive rule). A different
// observation voids the parked transition (no flapping events).
func (e *Executor) confirmPending(ctx context.Context, req ScanRequest, doc *snapshot.Document,
	prevSnapID string, out *Outcome, now time.Time) error {
	pending, err := e.st.PendingForAsset(ctx, req.Asset.AssetID, doc.ProbeType)
	if err != nil {
		return err
	}
	for _, p := range pending {
		if p.AfterHash != doc.ContentHash {
			if err := e.st.PendingDelete(ctx, req.Asset.AssetID, doc.ProbeType, p.DiffKey); err != nil {
				return err
			}
			continue
		}
		var c diff.Change
		if err := json.Unmarshal(p.Payload, &c); err != nil {
			return err
		}
		c.Confidence = diff.ConfConfirmed // 2-consecutive agreement (doc 03 §7.5)
		e.emitSimpleAt(ctx, req, c, prevSnapID, doc.SnapshotID, p.FirstSeenAt, now, out)
		if err := e.st.PendingDelete(ctx, req.Asset.AssetID, doc.ProbeType, p.DiffKey); err != nil {
			return err
		}
	}
	return nil
}

// handleFailure implements doc 03 §12 failure persistence windows.
func (e *Executor) handleFailure(ctx context.Context, req ScanRequest, wa *store.WatchAsset,
	doc *snapshot.Document, latest *store.LatestSnapshot, out *Outcome, now time.Time) error {
	if wa.FailingSince == nil {
		if err := e.st.SetFailing(ctx, wa.RowUUID, &now); err != nil {
			return err
		}
		wa.FailingSince = &now
	}
	// Keep the last good snapshot; record status/ts on the hot row
	// (first observation of a failing asset writes no snapshot).
	if latest != nil {
		if err := e.st.TouchLatest(ctx, req.Asset.AssetID, doc.ProbeType, now, doc.Status); err != nil {
			return err
		}
	}
	if now.Sub(*wa.FailingSince) < failingWindow {
		return nil
	}

	// Unprobeable > 24 h → monitor.probe_failing (Meta; dedup window bounds
	// the rate to once per 24 h per probe type).
	e.emitSimple(ctx, req, diff.Change{
		Type: "monitor.probe_failing", Severity: diff.SevLow, Confidence: diff.ConfProbable,
		Summary: fmt.Sprintf("asset %s unprobeable via %s since %s (status %s)",
			req.Asset.Identifier, doc.ProbeType, wa.FailingSince.Format(time.RFC3339), doc.Status),
		DiffKind: "probe_health", DiffKey: "failing:" + doc.ProbeType,
		Before: map[string]any{"status": "ok"},
		After:  map[string]any{"status": doc.Status},
	}, "", "", now, out)

	// Definitive disappearance (NXDOMAIN on the dns probe) > 24 h →
	// asset.removed + park for reactivation detection (doc 03 §12).
	if doc.ProbeType == snapshot.ProbeDNS && doc.Status == snapshot.StatusDNSNXDomain && wa.State == "active" {
		e.emitSimple(ctx, req, diff.Change{
			Type: "asset.removed", Severity: diff.SevMedium, Confidence: diff.ConfConfirmed,
			Summary:  fmt.Sprintf("asset %s no longer resolves (NXDOMAIN > 24 h)", req.Asset.Identifier),
			DiffKind: "asset_lifecycle", DiffKey: "removed",
			Followups: []diff.Followup{{Capability: "detect.scan",
				Reason: "asset disappeared — resolve open findings"}},
		}, "", "", now, out)
		if err := e.st.SetWatchState(ctx, wa.RowUUID, "paused"); err != nil {
			return err
		}
		wa.State = "paused"
	}
	return nil
}

// evaluateRules runs M5 baseline drift + exposure detection over the asset's
// latest snapshot set (doc 03 §7.3/§7.4; sticky state — transitions only).
func (e *Executor) evaluateRules(ctx context.Context, req ScanRequest, wa *store.WatchAsset, out *Outcome) error {
	docs, err := e.latestDocuments(ctx, req.Asset.AssetID)
	if err != nil {
		return err
	}
	if len(docs) == 0 {
		return nil
	}
	in := rules.InputFromSnapshots(req.Asset.AssetID, req.Asset.Identifier,
		req.Asset.Criticality, docs)
	now := e.cfg.Now()

	// Baselines (doc 03 §7.3).
	if req.BaselineID != "" {
		ruleset, err := e.st.BaselineRules(ctx, req.BaselineID)
		if err != nil {
			return err
		}
		for _, row := range ruleset {
			br, err := rules.ParseBaselineRule(row.Config)
			if err != nil {
				continue
			}
			if br.Type == "http_header" {
				if h, _ := br.Expect["header"].(string); h == "strict-transport-security" {
					if present, _ := br.Expect["present"].(bool); present {
						in.BaselineRequiresHSTS = true
					}
				}
			}
			v := rules.EvaluateBaseline(br, in)
			state, err := e.st.DriftState(ctx, req.Asset.AssetID, br.ID)
			if err != nil {
				return err
			}
			switch {
			case v != nil && state != "drifted":
				if err := e.st.SetDriftState(ctx, req.Asset.AssetID, br.ID, "drifted"); err != nil {
					return err
				}
				e.emitSimple(ctx, req, diff.Change{
					Type: "baseline.drift", Severity: v.Severity, Confidence: diff.ConfConfirmed,
					Summary:  fmt.Sprintf("baseline rule %s violated: %s", br.ID, v.Detail),
					DiffKind: "baseline_rule", RuleID: br.ID, DiffKey: "rule:" + br.ID,
					Before: map[string]any{"state": "in_baseline"},
					After:  map[string]any{"state": "drifted", "detail": v.Detail, "observed": v.Observed},
				}, "", "", now, out)
			case v == nil && state == "drifted":
				if err := e.st.SetDriftState(ctx, req.Asset.AssetID, br.ID, "in_baseline"); err != nil {
					return err
				}
				e.emitSimple(ctx, req, diff.Change{
					Type: "baseline.drift_resolved", Severity: diff.SevInfo, Confidence: diff.ConfConfirmed,
					Summary:  fmt.Sprintf("baseline rule %s back to compliance", br.ID),
					DiffKind: "baseline_rule", RuleID: br.ID, DiffKey: "rule:" + br.ID,
					Before: map[string]any{"state": "drifted"},
					After:  map[string]any{"state": "in_baseline"},
				}, "", "", now, out)
			}
		}
	}

	// Exposure ruleset v1 (doc 03 §7.4; CLOSED→OPEN→CLOSED, transitions only).
	hits := rules.EvaluateExposure(in)
	hitting := map[string]rules.Finding{}
	for _, f := range hits {
		hitting[f.RuleID] = f
	}
	states, err := e.st.ExposureStates(ctx, req.Asset.AssetID)
	if err != nil {
		return err
	}
	open := map[string]bool{}
	for _, st := range states {
		if st.State == "open" {
			open[st.RuleID] = true
		}
	}
	for _, f := range hits {
		if open[f.RuleID] {
			continue
		}
		if err := e.st.SetExposureState(ctx, req.Asset.AssetID, f.RuleID, "open"); err != nil {
			return err
		}
		out.ExposuresOpened++
		e.emitSimple(ctx, req, diff.Change{
			Type: "exposure.opened", Severity: f.Severity,
			Confidence: confidenceFor(req.Passive),
			Summary:    fmt.Sprintf("%s: %s (%s)", f.RuleID, f.Title, f.Detail),
			DiffKind:   "exposure_rule", RuleID: f.RuleID, DiffKey: "rule:" + f.RuleID,
			Before: map[string]any{"state": "closed"},
			After:  map[string]any{"state": "open", "detail": f.Detail, "evidence": f.Evidence},
			Followups: []diff.Followup{{Capability: "detect.scan",
				Reason: "exposure " + f.RuleID + " — validate with active scanning"}},
		}, "", "", now, out)
	}
	for ruleID := range open {
		if _, still := hitting[ruleID]; still {
			continue
		}
		if err := e.st.SetExposureState(ctx, req.Asset.AssetID, ruleID, "closed"); err != nil {
			return err
		}
		out.ExposuresClosed++
		e.emitSimple(ctx, req, diff.Change{
			Type: "exposure.closed", Severity: diff.SevInfo,
			Confidence: confidenceFor(req.Passive),
			Summary:    fmt.Sprintf("exposure %s no longer detected", ruleID),
			DiffKind:   "exposure_rule", RuleID: ruleID, DiffKey: "rule:" + ruleID,
			Before: map[string]any{"state": "open"},
			After:  map[string]any{"state": "closed"},
		}, "", "", now, out)
	}
	return nil
}

// ---------------------------------------------------------------------------
// emission helpers
// ---------------------------------------------------------------------------

func (e *Executor) emitSimple(ctx context.Context, req ScanRequest, c diff.Change,
	prevSnapID, newSnapID string, occurred time.Time, out *Outcome) {
	e.emitSimpleAt(ctx, req, c, prevSnapID, newSnapID, occurred, occurred, out)
}

func (e *Executor) emitSimpleAt(ctx context.Context, req ScanRequest, c diff.Change,
	prevSnapID, newSnapID string, firstSeen, occurred time.Time, out *Outcome) {
	if !req.ReportEvents {
		return
	}
	source := "active_probe"
	if req.Passive {
		source = "passive_feed"
	}
	mc, err := events.NewChange(events.ChangeCtx{
		MissionID: req.MissionID, ROEID: req.ROEID, OrgID: req.OrgID,
		Asset:          req.Asset,
		ProbeType:      probeTypeOf(c),
		WorkerID:       e.cfg.WorkerID,
		WatchID:        req.WatchID,
		SnapshotBefore: prevSnapID,
		SnapshotAfter:  newSnapID,
		FirstSeen:      firstSeen,
		OccurredAt:     occurred,
		Labels:         map[string]string{"surface": "external", "source": source},
	}, c)
	if err != nil {
		return
	}
	o, err := e.streamer.Submit(ctx, streamer.SubmitInput{
		Change: mc,
		Alert: alertmap.Params{
			AlertThreshold: req.AlertThreshold,
			TokenJTI:       req.TokenJTI,
			ROEID:          req.ROEID,
			Passive:        req.Passive,
		},
		EmissionCapPerHour: req.EmissionCapPerHour,
	})
	if err != nil {
		return
	}
	if o == streamer.OutcomeEmitted {
		out.EventsEmitted++
	} else {
		out.EventsSuppressed++
	}
}

// probeTypeOf derives the detector probe type from the change type group.
func probeTypeOf(c diff.Change) string {
	switch {
	case strings.HasPrefix(c.Type, "dns."):
		return snapshot.ProbeDNS
	case strings.HasPrefix(c.Type, "tls."):
		return snapshot.ProbeTLS
	case strings.HasPrefix(c.Type, "http."):
		return snapshot.ProbeHTTP
	case strings.HasPrefix(c.Type, "port."):
		return snapshot.ProbeTCPPort
	}
	return ""
}

func confidenceFor(passive bool) string {
	if passive {
		return diff.ConfProbable
	}
	return diff.ConfConfirmed
}

// ---------------------------------------------------------------------------
// scheduling helpers
// ---------------------------------------------------------------------------

// ensureWatchAsset resolves the watch_assets row for the request, creating it
// (deterministic asset id) when the target is not yet watched (rescan path).
func (e *Executor) ensureWatchAsset(ctx context.Context, req ScanRequest, now time.Time) (*store.WatchAsset, error) {
	assets, err := e.st.ListWatchAssets(ctx, req.MissionID, "")
	if err != nil {
		return nil, err
	}
	for i := range assets {
		if assets[i].Identifier == req.Asset.Identifier {
			wa := &assets[i]
			if wa.AssetID != "" {
				return wa, nil
			}
		}
	}
	assetID := req.Asset.AssetID
	if assetID == "" {
		assetID = deterministicUUID(req.Asset.Identifier)
	}
	cadence := req.CadenceProfile
	if cadence == "" {
		cadence = "standard"
	}
	if err := e.st.UpsertWatchAsset(ctx, assetID, req.MissionID, req.Asset.Identifier, cadence, now); err != nil {
		return nil, err
	}
	assets, err = e.st.ListWatchAssets(ctx, req.MissionID, "")
	if err != nil {
		return nil, err
	}
	for i := range assets {
		if assets[i].Identifier == req.Asset.Identifier {
			return &assets[i], nil
		}
	}
	return nil, fmt.Errorf("executor: watch asset %s vanished after upsert", req.Asset.Identifier)
}

// probeDue reports whether probe type pt is due for the asset under the
// (possibly fast-escalated) profile, using snapshots_latest.probe_ts as the
// per-probe last-run record (doc 03 §6.4; floor 1 min/asset).
func (e *Executor) probeDue(ctx context.Context, assetID, pt string, profile Profile, fast bool, now time.Time, force bool) bool {
	if force {
		return true
	}
	interval := profile.HTTP
	switch pt {
	case snapshot.ProbeDNS:
		interval = profile.DNS
	case snapshot.ProbeTCPPort:
		interval = profile.TCP
	}
	if fast && interval > Profiles["fast"].HTTP {
		interval = Profiles["fast"].HTTP
	}
	if interval < minInterval {
		interval = minInterval
	}
	latest, err := e.st.GetLatest(ctx, assetID, pt)
	if err != nil || latest == nil {
		return true // never probed
	}
	return latest.ProbeTS.Add(interval).Before(now) || latest.ProbeTS.Add(interval).Equal(now)
}

// reschedule computes the asset's next due time with ±10 % jitter
// (doc 03 §6.4) and records the probe time.
func (e *Executor) reschedule(ctx context.Context, req ScanRequest, wa *store.WatchAsset, profile Profile, now time.Time) error {
	interval := profile.DNS
	for _, pt := range req.ProbeTypes {
		var d time.Duration
		switch pt {
		case snapshot.ProbeDNS:
			d = profile.DNS
		case snapshot.ProbeTCPPort:
			d = profile.TCP
		default:
			d = profile.HTTP
		}
		if d > 0 && d < interval {
			interval = d
		}
	}
	if wa.FastUntil != nil && wa.FastUntil.After(now) && interval > Profiles["fast"].HTTP {
		interval = Profiles["fast"].HTTP
	}
	if interval < minInterval {
		interval = minInterval
	}
	// Deterministic ±10 % jitter per asset (flattens load, doc 03 §6.4).
	h := sha256.Sum256([]byte(wa.RowUUID))
	frac := float64(h[0])/255.0*0.2 - 0.1 // [-0.1, +0.1]
	jittered := time.Duration(float64(interval) * (1 + frac))
	if wa.State == "paused" {
		jittered = ReactivationInterval
	}
	return e.st.Reschedule(ctx, wa.RowUUID, now.Add(jittered), now)
}

// persistSnapshot writes latest + history (doc 03 §7.1).
func (e *Executor) persistSnapshot(ctx context.Context, doc *snapshot.Document) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	var rawRef *string
	if doc.Data.HTTP != nil && doc.Data.HTTP.RawRef != "" {
		rawRef = &doc.Data.HTTP.RawRef
	}
	return e.st.WriteSnapshot(ctx, nil, doc.AssetID, doc.ProbeType, doc.SnapshotID,
		doc.ContentHash, doc.ProbeTS, doc.Status, raw, rawRef)
}

// latestDocuments loads the current SnapshotDocument per probe type (rules
// input assembly).
func (e *Executor) latestDocuments(ctx context.Context, assetID string) (map[string]*snapshot.Document, error) {
	out := map[string]*snapshot.Document{}
	for _, pt := range []string{snapshot.ProbeDNS, snapshot.ProbeTLS, snapshot.ProbeHTTP} {
		latest, err := e.st.GetLatest(ctx, assetID, pt)
		if err != nil {
			return nil, err
		}
		if latest == nil {
			continue
		}
		raw, err := e.st.SnapshotData(ctx, latest.SnapshotID)
		if err != nil {
			return nil, err
		}
		if len(raw) == 0 {
			continue
		}
		doc := &snapshot.Document{}
		if err := json.Unmarshal(raw, doc); err != nil {
			return nil, fmt.Errorf("executor: latest %s/%s: %w", assetID, pt, err)
		}
		out[pt] = doc
	}
	return out, nil
}

// deterministicUUID renders a stable uuid-shaped id for non-inventory assets
// (CT candidates added to the watch set before 09 ingests them).
func deterministicUUID(identifier string) string {
	h := sha256.Sum256([]byte("aegisbastion.monitor.asset|" + identifier))
	h[6] = (h[6] & 0x0f) | 0x80 // version 8 (custom)
	h[8] = (h[8] & 0x3f) | 0x80 // variant RFC 4122
	return fmt.Sprintf("%x-%x-%x-%x-%x", h[0:4], h[4:6], h[6:8], h[8:10], h[10:16])
}

// ClassifyIdentifier maps a target string to an asset kind (doc 03 §5.1).
func ClassifyIdentifier(identifier string) string {
	if _, err := netip.ParseAddr(strings.TrimSuffix(identifier, ".")); err == nil {
		return "ip"
	}
	host := strings.TrimSuffix(strings.ToLower(identifier), ".")
	if strings.Count(host, ".") <= 1 {
		return "domain"
	}
	return "subdomain"
}

// NewULID mints a bare ULID (job ids).
func NewULID() string { return ulid.Make().String() }
