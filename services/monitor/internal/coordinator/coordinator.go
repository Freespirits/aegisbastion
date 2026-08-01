// Package coordinator is the M1 Coordinator + M2 Scheduler (doc 03 §3.1):
// the agentsdk.Module host for monitor.watch / monitor.rescan /
// monitor.baseline.set / monitor.feed.sync (doc 03 §4.1 registration).
//
// Standing watches (doc 03 §2): Run keeps the watch set synced from the
// data-platform inventory, purges out-of-scope assets within one scheduler
// pass (doc 03 §4.4), publishes per-asset scan jobs carrying the CURRENT
// scope-bound watch token (refreshed continuously, doc 03 §9.2), reports
// progress every 60 s, and checkpoints with renewal_requested at the
// assignment deadline. A mission whose RoE allows only R0 arrives as an R0
// task and runs passive-only mode (Ruling A.1): feed ingestion + cached
// diffing, ZERO target contact.
package coordinator

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/structpb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	agentsdk "github.com/aegisbastion/aegisbastion/sdks/go"
	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	sdkscope "github.com/aegisbastion/aegisbastion/sdks/go/scope"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/ctlog"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/events"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/executor"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/jobs"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/rules"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/store"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/streamer"
)

// Capabilities registered by this module (doc 03 §4.1).
const (
	CapWatch       = "monitor.watch"
	CapRescan      = "monitor.rescan"
	CapBaselineSet = "monitor.baseline.set"
	CapFeedSync    = "monitor.feed.sync"
)

// Config tunes the coordinator.
type Config struct {
	AgentID  string
	WorkerID string
	Region   string
	// SchedulerInterval — scheduler pass cadence (doc 03 §4.4: purge ≤ 60 s).
	SchedulerInterval time.Duration
	// WatchSetSyncInterval — inventory sync cadence.
	WatchSetSyncInterval time.Duration
	// ProgressInterval — ReportProgress cadence (doc 03 §4.3: 60 s).
	ProgressInterval time.Duration
	// BurstFlushInterval — monitor.change_burst aggregation window.
	BurstFlushInterval time.Duration
	// BatchSize — due assets claimed per pass (doc 03 §11).
	BatchSize int
	// RefreshFraction — token refresh point of the 15 min TTL (0.6).
	RefreshFraction float64
	Logger          *slog.Logger
	Now             func() time.Time
}

// Deps are the coordinator's collaborators.
type Deps struct {
	Store    *store.Store
	Streamer *streamer.Streamer
	Jobs     *jobs.Publisher
	Executor *executor.Executor
	Feeds    *ctlog.FeedRegistry
	// Tokens is gatekeeper TokenService (RefreshToken mid-run re-auth).
	Tokens gatekeeperv1.TokenServiceClient
	// Verifier verifies refreshed successor tokens (JWKS).
	Verifier *token.Verifier
	// Fetcher loads token manifests (scope purge evaluation).
	Fetcher manifest.Fetcher
	// Emitter is the audit.events sink (purge + emission decisions).
	Emitter audit.Emitter
}

// Coordinator implements agentsdk.Module plus the worker/streamer/ctlog
// sinks. Safe for concurrent task execution (max_concurrent_tasks 8).
type Coordinator struct {
	cfg  Config
	deps Deps

	mu      sync.Mutex
	runs    map[string]*watchRun // task_id → live watch
	aborted bool
}

// New builds the Coordinator.
func New(cfg Config, deps Deps) *Coordinator {
	if cfg.SchedulerInterval <= 0 {
		cfg.SchedulerInterval = 15 * time.Second
	}
	if cfg.WatchSetSyncInterval <= 0 {
		cfg.WatchSetSyncInterval = time.Minute
	}
	if cfg.ProgressInterval <= 0 {
		cfg.ProgressInterval = time.Minute
	}
	if cfg.BurstFlushInterval <= 0 {
		cfg.BurstFlushInterval = time.Minute
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 25
	}
	if cfg.RefreshFraction <= 0 || cfg.RefreshFraction >= 1 {
		cfg.RefreshFraction = 0.6
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Now == nil {
		cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	return &Coordinator{cfg: cfg, deps: deps, runs: map[string]*watchRun{}}
}

// ---------------------------------------------------------------------------
// agentsdk.Module
// ---------------------------------------------------------------------------

// Plan validates params (doc 01 §9.1).
func (c *Coordinator) Plan(t *agentsdk.Task) error {
	switch t.Assignment.GetCapability() {
	case CapWatch:
		_, err := parseWatchParams(t.Assignment.GetParams())
		return err
	case CapRescan:
		_, err := parseRescanParams(t.Assignment.GetParams())
		return err
	case CapBaselineSet:
		_, err := parseBaselineParams(t.Assignment.GetParams())
		return err
	case CapFeedSync:
		_, err := parseFeedSyncParams(t.Assignment.GetParams())
		return err
	}
	return fmt.Errorf("coordinator: unsupported capability %q", t.Assignment.GetCapability())
}

// Run executes the assignment (doc 01 §9.1).
func (c *Coordinator) Run(ctx context.Context, t *agentsdk.Task, emit *agentsdk.Emitter) error {
	c.mu.Lock()
	if c.aborted {
		c.mu.Unlock()
		return fmt.Errorf("coordinator aborted (kill switch)")
	}
	c.mu.Unlock()

	switch t.Assignment.GetCapability() {
	case CapWatch:
		return c.runWatch(ctx, t, emit)
	case CapRescan:
		return c.runRescan(ctx, t, emit)
	case CapBaselineSet:
		return c.runBaselineSet(ctx, t, emit)
	case CapFeedSync:
		return c.runFeedSync(ctx, t, emit)
	}
	return fmt.Errorf("coordinator: unsupported capability %q", t.Assignment.GetCapability())
}

// Abort halts all running tasks (doc 01 §9 item 5: ≤ 5 s; the SDK also
// cancels each task's context).
func (c *Coordinator) Abort() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.aborted = true
	for _, r := range c.runs {
		r.cancel()
	}
}

// ---------------------------------------------------------------------------
// watch (doc 03 §2 standing watches)
// ---------------------------------------------------------------------------

// watchRun tracks one live watch for checkpoints, mgmt API, and abort.
type watchRun struct {
	taskID    string
	watchID   string
	missionID string
	roeID     string
	orgID     string
	passive   bool
	startedAt time.Time
	cancel    context.CancelFunc

	mu                 sync.Mutex
	assetsWatched      int
	probesExecuted     uint64
	probeFailures      uint64
	eventsEmitted      uint64
	eventsSuppressed   uint64
	exposuresOpened    uint64
	exposuresClosed    uint64
	tokenRefreshFails  uint64
	lastPurge          int
	lastProgressReport time.Time
}

// WatchStatus is the mgmt-API view (doc 03 §13 GET /v1/watches).
type WatchStatus struct {
	TaskID        string    `json:"task_id"`
	WatchID       string    `json:"watch_id"`
	MissionID     string    `json:"mission_id"`
	ROEID         string    `json:"roe_id"`
	Passive       bool      `json:"passive"`
	StartedAt     time.Time `json:"started_at"`
	AssetsWatched int       `json:"assets_watched"`
}

// Watches lists live watches (mgmt API).
func (c *Coordinator) Watches() []WatchStatus {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]WatchStatus, 0, len(c.runs))
	for _, r := range c.runs {
		r.mu.Lock()
		out = append(out, WatchStatus{
			TaskID: r.taskID, WatchID: r.watchID, MissionID: r.missionID,
			ROEID: r.roeID, Passive: r.passive, StartedAt: r.startedAt,
			AssetsWatched: r.assetsWatched,
		})
		r.mu.Unlock()
	}
	return out
}

func (c *Coordinator) runWatch(ctx context.Context, t *agentsdk.Task, emit *agentsdk.Emitter) error {
	params, err := parseWatchParams(t.Assignment.GetParams())
	if err != nil {
		return err
	}
	as := t.Assignment
	missionID := params.AssetSelector.MissionID
	if missionID == "" {
		missionID = as.GetMissionId()
	}
	passive := !t.RequiresAuthorization() // R0 watch = passive-only (Ruling A.1)

	mc, err := c.deps.Store.GetMissionContext(ctx, missionID)
	if err != nil {
		return fmt.Errorf("mission context: %w", err)
	}
	if mc == nil {
		return fmt.Errorf("mission %s not found (fail-closed)", missionID)
	}

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	run := &watchRun{
		taskID: as.GetTaskId(), watchID: params.WatchID, missionID: missionID,
		roeID: mc.ROEID, orgID: mc.OrgID, passive: passive,
		startedAt: c.cfg.Now(), cancel: cancel,
	}
	c.mu.Lock()
	c.runs[as.GetTaskId()] = run
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		delete(c.runs, as.GetTaskId())
		c.mu.Unlock()
	}()

	log := c.cfg.Logger.With("task_id", as.GetTaskId(), "watch_id", params.WatchID,
		"mission", missionID, "passive", passive)
	log.Info("watch starting", "cadence", params.CadenceProfile, "probes", params.ProbeTypes)

	// Passive-mode scope (for purge + candidate classification): the RoE
	// record's canonical scope. Active mode evaluates via the token manifest.
	var passiveScope *sdkscope.Scope
	if passive {
		passiveScope = scopeFromJSON(mc.ScopeJSON)
	}

	// Current raw token for scan jobs (active mode); refreshed continuously
	// (doc 03 §9.2). The agent SDK refreshes the Task guard in parallel —
	// RefreshToken mints successors without revoking predecessors.
	tokenMu := &sync.Mutex{}
	currentToken := as.GetAuthorizationToken()
	if !passive {
		go c.refreshLoop(runCtx, run, tokenMu, &currentToken, log)
	}

	// Assignment deadline (rolling 24 h); finish just before it to deliver
	// the checkpoint TaskResult (doc 03 §4.3).
	deadline := time.Time{}
	if dl := as.GetDeadline(); dl != nil {
		deadline = dl.AsTime()
	}
	if to := as.GetTimeoutS(); to > 0 {
		if d := c.cfg.Now().Add(time.Duration(to) * time.Second); deadline.IsZero() || d.Before(deadline) {
			deadline = d
		}
	}

	sched := time.NewTicker(c.cfg.SchedulerInterval)
	defer sched.Stop()
	progress := time.NewTicker(c.cfg.ProgressInterval)
	defer progress.Stop()
	bursts := time.NewTicker(c.cfg.BurstFlushInterval)
	defer bursts.Stop()
	lastSync := time.Time{}

	pass := func() {
		if c.cfg.Now().Sub(lastSync) >= c.cfg.WatchSetSyncInterval || lastSync.IsZero() {
			c.syncWatchSet(runCtx, run, params, mc, t, passiveScope, log)
			if passive {
				// Ruling A.1 passive-only mode: cached-data diffing, ZERO
				// target contact (no scan jobs, no token, no probes).
				c.passiveSweep(runCtx, run, params, mc, log)
			}
			lastSync = c.cfg.Now()
		}
		if !passive {
			c.publishDueJobs(runCtx, run, params, mc, tokenMu, &currentToken, log)
		}
	}
	pass() // immediate first pass

	for {
		select {
		case <-runCtx.Done():
			c.checkpoint(run, emit, runCtx)
			return runCtx.Err()
		case <-sched.C:
			pass()
		case <-progress.C:
			c.reportProgress(runCtx, run, emit)
		case <-bursts.C:
			_ = c.deps.Streamer.FlushBursts(runCtx, c.cfg.Now().Add(-c.cfg.BurstFlushInterval),
				events.ChangeCtx{ROEID: run.roeID, OrgID: run.orgID,
					WorkerID: c.cfg.WorkerID, WatchID: run.watchID})
		}
		if !deadline.IsZero() && c.cfg.Now().After(deadline.Add(-90*time.Second)) {
			c.checkpoint(run, emit, runCtx)
			return nil // SUCCEEDED; renewal_expected → commander re-issues
		}
	}
}

// syncWatchSet converges the watch set with the inventory + purges
// out-of-scope assets (doc 03 §4.2/§4.4).
func (c *Coordinator) syncWatchSet(ctx context.Context, run *watchRun, params watchParams,
	mc *store.MissionContext, t *agentsdk.Task, passiveScope *sdkscope.Scope, log *slog.Logger) {

	kinds := dpKinds(params.AssetSelector.Kinds)
	assets, err := c.deps.Store.SyncInventory(ctx, mc.ROEID, kinds)
	if err != nil {
		log.Warn("inventory sync failed", "error", err)
		return
	}
	now := c.cfg.Now()
	cadence := params.CadenceProfile
	if cadence == "" {
		cadence = "standard"
	}
	for _, a := range assets {
		if err := c.deps.Store.UpsertWatchAsset(ctx, a.AssetID, run.missionID, a.Value, cadence, now); err != nil {
			log.Warn("watch asset upsert failed", "identifier", a.Value, "error", err)
		}
	}

	// Scope purge (doc 03 §4.4: out-of-scope assets purged ≤ 60 s, purge
	// list audit-logged). Exclusions always win.
	scopeEval := c.scopeEvaluator(ctx, t, passiveScope)
	watched, err := c.deps.Store.ListWatchAssets(ctx, run.missionID, "active")
	if err != nil {
		return
	}
	var purged []string
	kept := 0
	for _, w := range watched {
		if scopeEval != nil && !scopeEval(w.Identifier) {
			if err := c.deps.Store.SetWatchState(ctx, w.RowUUID, "removed"); err == nil {
				purged = append(purged, w.Identifier)
			}
			continue
		}
		kept++
	}
	run.mu.Lock()
	run.assetsWatched = kept
	run.lastPurge = len(purged)
	run.mu.Unlock()
	if len(purged) > 0 {
		log.Warn("purged out-of-scope assets from watch set", "count", len(purged))
		c.auditRecord(ctx, run, "monitor.scope_purge", map[string]any{
			"watch_id": run.watchID, "purged": purged, "count": len(purged),
		})
	}
}

// scopeEvaluator returns the current scope check. Active watches evaluate
// through the CURRENT token manifest (post-refresh, so a narrowed RoE bites
// within one pass); passive watches use the RoE record scope. A nil result
// keeps every asset (fail-safe for scheduling; probing stays fail-closed at
// the worker's per-job token verification).
func (c *Coordinator) scopeEvaluator(ctx context.Context, t *agentsdk.Task, passiveScope *sdkscope.Scope) func(string) bool {
	if passiveScope != nil {
		return func(id string) bool { return passiveScope.Evaluate(id).Allowed }
	}
	guard := t.Guard()
	if guard == nil {
		return nil
	}
	claims := guard.Claims()
	man, err := manifest.Load(ctx, c.deps.Fetcher, claims.Targets, claims.ScopeBound)
	if err != nil {
		return nil // probing still gated per job; purge deferred to next pass
	}
	return func(id string) bool { return man.EvaluateScope(id).Allowed }
}

// publishDueJobs claims due assets and queues scan jobs carrying the current
// token (doc 03 §2/§11).
func (c *Coordinator) publishDueJobs(ctx context.Context, run *watchRun, params watchParams,
	mc *store.MissionContext, tokenMu *sync.Mutex, currentToken *string, log *slog.Logger) {
	tokenMu.Lock()
	raw := *currentToken
	tokenMu.Unlock()
	if raw == "" {
		return // token refresh pending; workers never see an empty token
	}

	now := c.cfg.Now()
	due, err := c.deps.Store.ListDueAssets(ctx, run.missionID, now, c.cfg.BatchSize)
	if err != nil {
		log.Warn("due assets query failed", "error", err)
		return
	}
	parked, err := c.deps.Store.ListDueAssetsState(ctx, run.missionID, "paused", now, 5)
	if err != nil {
		log.Warn("reactivation query failed", "error", err)
	}
	for _, w := range parked {
		due = append(due, w)
	}

	probes := normalizeProbeTypes(params.ProbeTypes)
	for _, w := range due {
		probeTypes := probes
		reactivation := false
		if w.State == "paused" {
			probeTypes = []string{snapshot.ProbeDNS} // reactivation check is dns-only
			reactivation = true
		}
		j := &jobs.Job{
			JobID:              fmt.Sprintf("%s-%d", w.RowUUID, now.Unix()),
			AuthorizationToken: raw,
			TaskID:             run.taskID,
			Capability:         CapWatch,
			WatchID:            run.watchID,
			MissionID:          run.missionID,
			ROEID:              run.roeID,
			ROEVersion:         uint64(mc.ROEVersion),
			OrgID:              run.orgID,
			AssetID:            w.AssetID,
			Identifier:         w.Identifier,
			Kind:               executor.ClassifyIdentifier(w.Identifier),
			Criticality:        "medium",
			ProbeTypes:         probeTypes,
			BaselineID:         params.BaselineID,
			AlertThreshold:     params.AlertThreshold,
			EmissionCapPerHour: params.EmissionCapPerHour,
			CadenceProfile:     w.CadenceProfile,
			ReportEvents:       true,
			Reactivation:       reactivation,
		}
		if err := c.deps.Jobs.Publish(ctx, j); err != nil {
			log.Warn("scan job publish failed", "identifier", w.Identifier, "error", err)
		}
	}
}

// passiveSweep is Ruling A.1's cached-data diffing for R0-only missions: M5
// baseline/exposure rules evaluate over each watched asset's CACHED snapshot
// set — zero target contact (no scan jobs, no token, no probes). Sticky rule
// state (doc 03 §7.3/§7.4) means transitions emit exactly once, so the sweep
// is idempotent across passes.
func (c *Coordinator) passiveSweep(ctx context.Context, run *watchRun, params watchParams,
	mc *store.MissionContext, log *slog.Logger) {
	assets, err := c.deps.Store.ListWatchAssets(ctx, run.missionID, "active")
	if err != nil {
		log.Warn("passive sweep: list watch assets failed", "error", err)
		return
	}
	for _, w := range assets {
		req := executor.ScanRequest{
			TaskID: run.taskID, WatchID: run.watchID,
			MissionID: run.missionID, ROEID: run.roeID, ROEVersion: uint64(mc.ROEVersion), OrgID: run.orgID,
			Asset: events.AssetCtx{
				AssetID: w.AssetID, Kind: executor.ClassifyIdentifier(w.Identifier),
				Identifier: w.Identifier, Criticality: "medium",
			},
			BaselineID:         params.BaselineID,
			AlertThreshold:     params.AlertThreshold,
			EmissionCapPerHour: params.EmissionCapPerHour,
			Passive:            true, // executor runs rules-only, zero contact
			ReportEvents:       true,
		}
		out, err := c.deps.Executor.ScanAsset(ctx, req)
		if err != nil {
			log.Warn("passive evaluation failed", "identifier", w.Identifier, "error", err)
			continue
		}
		c.JobDone(&jobs.Job{TaskID: run.taskID}, out)
	}
}

// refreshLoop continuously re-authorizes the 15-min watch token (doc 03
// §9.2): at RefreshFraction of the TTL it calls TokenService.RefreshToken —
// a full policy re-check, not an unauthenticated refresh.
func (c *Coordinator) refreshLoop(ctx context.Context, run *watchRun, tokenMu *sync.Mutex, currentToken *string, log *slog.Logger) {
	for {
		tokenMu.Lock()
		raw := *currentToken
		tokenMu.Unlock()
		claims, err := c.deps.Verifier.Verify(ctx, raw)
		if err != nil {
			// Current token no longer verifies (expired before any refresh
			// succeeded) — stop publishing; workers fail closed.
			tokenMu.Lock()
			*currentToken = ""
			tokenMu.Unlock()
			run.mu.Lock()
			run.tokenRefreshFails++
			run.mu.Unlock()
			log.Error("watch token no longer verifies — probing halted (fail-closed)", "error", err)
			return
		}
		ttl := time.Duration(claims.ExpiresAt-claims.IssuedAt) * time.Second
		wait := time.Duration(float64(ttl) * c.cfg.RefreshFraction)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}

		rctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		resp, err := c.deps.Tokens.RefreshToken(rctx, &gatekeeperv1.RefreshTokenRequest{CurrentToken: raw})
		cancel()
		if err != nil {
			run.mu.Lock()
			run.tokenRefreshFails++
			run.mu.Unlock()
			log.Warn("token refresh RPC failed — retrying next cycle", "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(10 * time.Second):
			}
			continue
		}
		if resp.GetToken() == "" {
			log.Warn("token refresh DENIED — probing halts at current token expiry")
			// Keep the current token until exp; workers fail closed after.
			return
		}
		if _, err := c.deps.Verifier.Verify(context.Background(), resp.GetToken()); err != nil {
			log.Error("successor token failed verification — refusing it", "error", err)
			return
		}
		tokenMu.Lock()
		*currentToken = resp.GetToken()
		tokenMu.Unlock()
		log.Info("watch token re-authorized", "jti", resp.GetClaims().GetJti())
	}
}

// reportProgress emits the 60 s liveness rollup (doc 03 §4.3).
func (c *Coordinator) reportProgress(ctx context.Context, run *watchRun, emit *agentsdk.Emitter) {
	run.mu.Lock()
	assets := run.assetsWatched
	probes := run.probesExecuted
	run.mu.Unlock()
	queueDepth, _ := c.deps.Store.CountDueAssets(ctx, run.missionID, c.cfg.Now())
	_ = emit.Progress(ctx, map[string]any{
		"assets_watched": assets,
		"queue_depth":    queueDepth,
		"probes_per_min": probes,
	})
}

// checkpoint delivers the terminal watch summary (doc 03 §4.3): probe/event
// counts + renewal_requested; metrics.targets_touched (the scope:sha256
// checkpoint form) is attached by the SDK from the guard.
func (c *Coordinator) checkpoint(run *watchRun, emit *agentsdk.Emitter, ctx context.Context) {
	run.mu.Lock()
	defer run.mu.Unlock()
	_ = emit.SetSummary(map[string]any{
		"watch_id":                 run.watchID,
		"assets_watched":           run.assetsWatched,
		"probes_executed":          run.probesExecuted,
		"probe_failures":           run.probeFailures,
		"change_events_emitted":    run.eventsEmitted,
		"change_events_suppressed": run.eventsSuppressed,
		"exposures_open":           run.exposuresOpened,
		"exposures_closed":         run.exposuresClosed,
		"renewal_requested":        true,
	})
	emit.AddRequests(run.probesExecuted)
}

// ---------------------------------------------------------------------------
// rescan (doc 03 §4.2 — bounded, commander-ordered verification)
// ---------------------------------------------------------------------------

func (c *Coordinator) runRescan(ctx context.Context, t *agentsdk.Task, emit *agentsdk.Emitter) error {
	params, err := parseRescanParams(t.Assignment.GetParams())
	if err != nil {
		return err
	}
	as := t.Assignment
	missionID := as.GetMissionId()
	mc, err := c.deps.Store.GetMissionContext(ctx, missionID)
	if err != nil || mc == nil {
		return fmt.Errorf("mission %s context unavailable (fail-closed)", missionID)
	}

	probes := normalizeProbeTypes(params.ProbeTypes)
	tokenJTI := ""
	if t.Guard() != nil {
		tokenJTI = t.Guard().Claims().ID
	}
	var scanned, failed int
	var emitted, suppressed int
	for _, target := range params.Targets {
		req := executor.ScanRequest{
			TaskID: as.GetTaskId(), WatchID: "rescan:" + as.GetTaskId(),
			MissionID: missionID, ROEID: mc.ROEID, ROEVersion: uint64(mc.ROEVersion), OrgID: mc.OrgID,
			Asset: events.AssetCtx{
				Identifier: target, Kind: executor.ClassifyIdentifier(target), Criticality: "medium",
			},
			ProbeTypes:   probes,
			TokenJTI:     tokenJTI,
			ReportEvents: params.ReportEvents,
			// The task's SDK guard runs the full PEP chain per probe
			// (doc 01 §9 item 4); R0 rescans cannot probe (fail-closed).
			Authorize: func(pctx context.Context, probeType, tgt string) error {
				return t.AuthorizeTarget(pctx, tgt)
			},
		}
		out, err := c.deps.Executor.ScanAsset(ctx, req)
		if err != nil {
			failed++
			continue
		}
		if out.Unauthorized {
			return fmt.Errorf("rescan target %s unauthorized: %s", target, out.UnauthorizedErr)
		}
		scanned++
		emitted += out.EventsEmitted
		suppressed += out.EventsSuppressed
		emit.AddRequests(uint64(out.ProbesRun))
	}
	return emit.SetSummary(map[string]any{
		"targets_scanned": scanned, "targets_failed": failed,
		"change_events_emitted": emitted, "change_events_suppressed": suppressed,
		"reason": params.Reason,
	})
}

// ---------------------------------------------------------------------------
// baseline.set (R0, doc 03 §4.2/§7.3)
// ---------------------------------------------------------------------------

func (c *Coordinator) runBaselineSet(ctx context.Context, t *agentsdk.Task, emit *agentsdk.Emitter) error {
	params, err := parseBaselineParams(t.Assignment.GetParams())
	if err != nil {
		return err
	}
	missionID := params.AssetSelector.MissionID
	if missionID == "" {
		missionID = t.Assignment.GetMissionId()
	}
	if params.From != "" && params.From != "current_snapshots" {
		return fmt.Errorf("baseline source %q unsupported (want current_snapshots)", params.From)
	}
	assets, err := c.deps.Store.ListWatchAssets(ctx, missionID, "")
	if err != nil {
		return err
	}
	set := 0
	for _, w := range assets {
		docs, err := c.latestDocuments(ctx, w.AssetID)
		if err != nil || len(docs) == 0 {
			continue
		}
		in := rules.InputFromSnapshots(w.AssetID, w.Identifier, "medium", docs)
		rule := rules.CaptureBaseline(params.BaselineID, w.AssetID, "medium", in)
		raw, err := json.Marshal(rule)
		if err != nil {
			continue
		}
		if err := c.deps.Store.UpsertBaselineRule(ctx, store.BaselineRule{
			RuleID: rule.ID, MissionID: missionID,
			Name: params.BaselineID, RegoRef: "builtin:captured/v1", Config: raw,
		}); err != nil {
			return err
		}
		set++
	}
	return emit.SetSummary(map[string]any{
		"baseline_id": params.BaselineID, "rules_captured": set, "from": "current_snapshots",
	})
}

func (c *Coordinator) latestDocuments(ctx context.Context, assetID string) (map[string]*snapshot.Document, error) {
	out := map[string]*snapshot.Document{}
	for _, pt := range []string{snapshot.ProbeDNS, snapshot.ProbeTLS, snapshot.ProbeHTTP} {
		latest, err := c.deps.Store.GetLatest(ctx, assetID, pt)
		if err != nil || latest == nil {
			continue
		}
		raw, err := c.deps.Store.SnapshotData(ctx, latest.SnapshotID)
		if err != nil || len(raw) == 0 {
			continue
		}
		doc := &snapshot.Document{}
		if err := json.Unmarshal(raw, doc); err != nil {
			return nil, err
		}
		out[pt] = doc
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// feed.sync (R0, doc 03 §4.2/§9.4)
// ---------------------------------------------------------------------------

func (c *Coordinator) runFeedSync(ctx context.Context, t *agentsdk.Task, emit *agentsdk.Emitter) error {
	params, err := parseFeedSyncParams(t.Assignment.GetParams())
	if err != nil {
		return err
	}
	missionID := t.Assignment.GetMissionId()
	mc, err := c.deps.Store.GetMissionContext(ctx, missionID)
	if err != nil || mc == nil {
		return fmt.Errorf("mission %s context unavailable (fail-closed)", missionID)
	}
	attached := 0
	for _, domain := range params.Domains {
		domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
		if domain == "" {
			continue
		}
		c.deps.Feeds.Register(ctlog.Feed{
			MissionID: missionID, ROEID: mc.ROEID, OrgID: mc.OrgID,
			Domain: domain, Scope: scopeFromJSON(mc.ScopeJSON),
		})
		attached++
	}
	return emit.SetSummary(map[string]any{
		"feeds": params.Feeds, "domains_attached": attached,
	})
}

// ---------------------------------------------------------------------------
// sinks (worker outcomes, streamer emission decisions, CT candidates)
// ---------------------------------------------------------------------------

// JobDone implements worker.OutcomeSink — folds per-job outcomes into the
// owning watch's counters.
func (c *Coordinator) JobDone(j *jobs.Job, out executor.Outcome) {
	c.mu.Lock()
	run := c.runs[j.TaskID]
	c.mu.Unlock()
	if run == nil {
		return
	}
	run.mu.Lock()
	defer run.mu.Unlock()
	run.probesExecuted += uint64(out.ProbesRun)
	run.probeFailures += uint64(out.ProbesFailed)
	run.eventsEmitted += uint64(out.EventsEmitted)
	run.eventsSuppressed += uint64(out.EventsSuppressed)
	run.exposuresOpened += uint64(out.ExposuresOpened)
	run.exposuresClosed += uint64(out.ExposuresClosed)
}

// EmissionDecision implements streamer.AuditSink — every emitted/suppressed
// event decision is audit-logged (doc 03 §9.6). The platform audit enum has
// no module-emission type (proto/ is contracts-locked), so these carry
// UNSPECIFIED with a monitor.emission_decision payload kind — the gatekeeper
// audit consumer stores any type.
func (c *Coordinator) EmissionDecision(ctx context.Context, d streamer.AuditDecision) {
	c.auditRecord(ctx, nil, "monitor.emission_decision", map[string]any{
		"event_id": d.EventID, "fingerprint": d.Fingerprint,
		"outcome": string(d.Outcome), "reason": d.Reason,
		"change_type": d.ChangeType, "asset_id": d.AssetID,
	})
}

// OnCandidate implements ctlog.CandidateSink — the monitor.assets.new
// pipeline + §9.4 discipline.
func (c *Coordinator) OnCandidate(ctx context.Context, cand ctlog.Candidate) error {
	if cand.ScopeMatch == 2 { // SCOPE_MATCH_EXCLUDED
		// Exclusions are customer-declared do-not-touch: audit only (§9.4).
		c.auditRecord(ctx, nil, "monitor.passive_observation", map[string]any{
			"identifier": cand.Name, "scope_match": "excluded",
			"source": cand.Source["detail"], "mission_id": cand.MissionID,
		})
		return nil
	}
	nc, err := events.NewCandidate(events.CandidateCtx{
		MissionID: cand.MissionID, ROEID: cand.ROEID,
		Kind: cand.Kind, Identifier: cand.Name,
		Source: cand.Source, ScopeMatch: cand.ScopeMatch, Confidence: cand.Confidence,
	})
	if err != nil {
		return err
	}
	if err := c.deps.Streamer.SubmitCandidate(ctx, nc); err != nil {
		return err
	}
	if cand.ScopeMatch != 1 { // not IN_SCOPE — metadata only (§9.4)
		return nil
	}

	// In-scope: join the watch set immediately and emit asset.new (passive,
	// confidence probable — doc 03 §5.3/§5.4).
	assetID := deterministicAssetID(cand.Name)
	if err := c.deps.Store.UpsertWatchAsset(ctx, assetID, cand.MissionID, cand.Name,
		"standard", c.cfg.Now()); err != nil {
		return err
	}
	now := c.cfg.Now()
	mc, err := events.NewChange(events.ChangeCtx{
		MissionID: cand.MissionID, ROEID: cand.ROEID, OrgID: cand.OrgID,
		Asset: events.AssetCtx{
			AssetID: assetID, Kind: cand.Kind, Identifier: cand.Name, Criticality: "medium",
		},
		WorkerID:   c.cfg.WorkerID,
		OccurredAt: now,
		Labels:     map[string]string{"surface": "external", "source": "passive_feed"},
	}, diffChangeAssetNew(cand))
	if err != nil {
		return err
	}
	_, err = c.deps.Streamer.Submit(ctx, streamer.SubmitInput{
		Change: mc,
		Alert:  alertParamsPassive(cand.ROEID),
	})
	return err
}

// auditRecord emits one module audit record (see EmissionDecision for the
// UNSPECIFIED-type rationale).
func (c *Coordinator) auditRecord(ctx context.Context, run *watchRun, kind string, payload map[string]any) {
	if c.deps.Emitter == nil {
		return
	}
	id := audit.Ident{AgentID: c.cfg.AgentID}
	if run != nil {
		id.MissionID = run.missionID
		id.TaskID = run.taskID
		id.ROEID = run.roeID
	}
	if m, ok := payload["mission_id"].(string); ok && id.MissionID == "" {
		id.MissionID = m
	}
	payload["kind"] = kind
	evt, err := audit.NewEvent(platformv1.AuditEventType_AUDIT_EVENT_TYPE_UNSPECIFIED, id, payload)
	if err != nil {
		return
	}
	_ = c.deps.Emitter.Emit(ctx, evt)
}

// ---------------------------------------------------------------------------
// params parsing + misc helpers
// ---------------------------------------------------------------------------

func structToMap(s *structpb.Struct) (map[string]any, error) {
	if s == nil {
		return map[string]any{}, nil
	}
	return s.AsMap(), nil
}

type watchParams struct {
	WatchID       string
	AssetSelector struct {
		MissionID string
		Kinds     []string
	}
	CadenceProfile     string
	ProbeTypes         []string
	BaselineID         string
	AlertThreshold     string
	EmissionCapPerHour uint32
}

func parseWatchParams(s *structpb.Struct) (watchParams, error) {
	var p watchParams
	m, err := structToMap(s)
	if err != nil {
		return p, err
	}
	p.WatchID = strOf(m["watch_id"])
	if p.WatchID == "" {
		return p, fmt.Errorf("monitor.watch: watch_id is required")
	}
	if sel, ok := m["asset_selector"].(map[string]any); ok {
		p.AssetSelector.MissionID = strOf(sel["mission_id"])
		p.AssetSelector.Kinds = kindStrings(listOf(sel["kinds"]))
	}
	p.CadenceProfile = strOf(m["cadence_profile"])
	if p.CadenceProfile == "" {
		p.CadenceProfile = "standard"
	}
	if _, ok := map[string]bool{"fast": true, "standard": true, "daily": true}[p.CadenceProfile]; !ok {
		return p, fmt.Errorf("monitor.watch: unknown cadence_profile %q", p.CadenceProfile)
	}
	p.ProbeTypes = probeStrings(listOf(m["probe_types"]))
	if len(p.ProbeTypes) == 0 {
		p.ProbeTypes = []string{"dns", "tls", "http"}
	}
	p.BaselineID = strOf(m["baseline_id"])
	p.AlertThreshold = strOf(m["alert_threshold"])
	p.EmissionCapPerHour = uint32(numOf(m["emission_cap_per_hour"]))
	return p, nil
}

type rescanParams struct {
	Targets      []string
	ProbeTypes   []string
	Reason       string
	ReportEvents bool
}

func parseRescanParams(s *structpb.Struct) (rescanParams, error) {
	var p rescanParams
	m, err := structToMap(s)
	if err != nil {
		return p, err
	}
	for _, v := range listOf(m["targets"]) {
		if t := strOf(v); t != "" {
			p.Targets = append(p.Targets, t)
		}
	}
	if len(p.Targets) == 0 {
		return p, fmt.Errorf("monitor.rescan: targets is required")
	}
	p.ProbeTypes = probeStrings(listOf(m["probe_types"]))
	if len(p.ProbeTypes) == 0 {
		p.ProbeTypes = []string{"dns", "tls", "http"}
	}
	p.Reason = strOf(m["reason"])
	p.ReportEvents = boolOf(m["report_events"])
	return p, nil
}

type baselineParams struct {
	BaselineID    string
	AssetSelector struct{ MissionID string }
	From          string
}

func parseBaselineParams(s *structpb.Struct) (baselineParams, error) {
	var p baselineParams
	m, err := structToMap(s)
	if err != nil {
		return p, err
	}
	p.BaselineID = strOf(m["baseline_id"])
	if p.BaselineID == "" {
		return p, fmt.Errorf("monitor.baseline.set: baseline_id is required")
	}
	if sel, ok := m["asset_selector"].(map[string]any); ok {
		p.AssetSelector.MissionID = strOf(sel["mission_id"])
	}
	p.From = strOf(m["from"])
	return p, nil
}

type feedSyncParams struct {
	Feeds   []string
	Domains []string
}

func parseFeedSyncParams(s *structpb.Struct) (feedSyncParams, error) {
	var p feedSyncParams
	m, err := structToMap(s)
	if err != nil {
		return p, err
	}
	for _, v := range listOf(m["feeds"]) {
		if f := strOf(v); f != "" {
			if f != "ct_logs" {
				return p, fmt.Errorf("monitor.feed.sync: feed %q unsupported at MVP (ct_logs only)", f)
			}
			p.Feeds = append(p.Feeds, f)
		}
	}
	for _, v := range listOf(m["domains"]) {
		if d := strOf(v); d != "" {
			p.Domains = append(p.Domains, d)
		}
	}
	if len(p.Domains) == 0 {
		return p, fmt.Errorf("monitor.feed.sync: domains is required")
	}
	return p, nil
}

// kindStrings normalizes asset-kind params (wire strings or proto enum
// numbers) to the dp type vocabulary.
func kindStrings(in []any) []string {
	var out []string
	for _, v := range in {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case float64:
			switch int(t) {
			case 1:
				out = append(out, "domain")
			case 2:
				out = append(out, "subdomain")
			case 3:
				out = append(out, "ip")
			}
		}
	}
	return out
}

// probeStrings normalizes probe-type params (wire strings or proto enum
// numbers) to probe_type strings.
func probeStrings(in []any) []string {
	var out []string
	for _, v := range in {
		switch t := v.(type) {
		case string:
			out = append(out, t)
		case float64:
			switch int(t) {
			case 1:
				out = append(out, "dns")
			case 2:
				out = append(out, "tls")
			case 3:
				out = append(out, "http")
			case 4:
				out = append(out, "tcp_port")
			}
		}
	}
	return out
}

func normalizeProbeTypes(in []string) []string {
	var out []string
	for _, p := range in {
		switch p {
		case snapshot.ProbeDNS, snapshot.ProbeTLS, snapshot.ProbeHTTP:
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		out = []string{snapshot.ProbeDNS, snapshot.ProbeTLS, snapshot.ProbeHTTP}
	}
	return out
}

// dpKinds maps watch kinds to dp.assets types (empty = the probeable set).
func dpKinds(kinds []string) []string {
	if len(kinds) == 0 {
		return []string{"domain", "subdomain", "ip"}
	}
	out := kinds[:0:0]
	for _, k := range kinds {
		switch k {
		case "domain", "subdomain", "ip":
			out = append(out, k)
		}
	}
	if len(out) == 0 {
		out = []string{"domain", "subdomain", "ip"}
	}
	return out
}

// scopeFromJSON parses the gatekeeper roe_records.scope JSON into the SDK's
// canonical Scope (domains/cidrs/explicit_excludes).
func scopeFromJSON(raw []byte) *sdkscope.Scope {
	if len(raw) == 0 {
		return nil
	}
	var sc sdkscope.Scope
	if err := json.Unmarshal(raw, &sc); err != nil {
		return nil
	}
	return &sc
}

func strOf(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func boolOf(v any) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return false
}

func numOf(v any) float64 {
	if n, ok := v.(float64); ok {
		return n
	}
	return 0
}

func listOf(v any) []any {
	if l, ok := v.([]any); ok {
		return l
	}
	return nil
}
