// Package coordinator is the Detect Coordinator (doc 04 §3.1 D1): the
// registered platform agent (agent_type: detect). It consumes
// TaskAssignments via the platform Agent SDK, re-validates scope/params as
// defense-in-depth (Ruling B — gatekeeper is the single PDP; Detect never
// decides, never mints), plans scanner sub-jobs, obtains narrowed job-scoped
// Scope Tokens from gatekeeper via token exchange (Ruling C9, fail-closed),
// dispatches jobs onto the module-internal queue, validates every candidate
// through the AVE (and EVS where triggered), scores risk, and publishes
// findings (detect.findings) and alerts (detect.alert, Ruling C8).
//
// The per-target intrusive lease is taken by the Orchestrator (doc 01 §6.4)
// — the Coordinator consumes dispatched tasks and never takes its own
// leases.
package coordinator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	agentsdk "github.com/aegisbastion/aegisbastion/sdks/go"
	"github.com/aegisbastion/aegisbastion/sdks/go/bus"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/evs"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/normalize"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/planner"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/publish"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/risk"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/tokexchange"
)

// SuppressionView is the false-positive suppression list (doc 04 §7.3).
type SuppressionView interface {
	Suppressed(ctx context.Context, signatureHash string) (bool, error)
}

// FindingsPublisher emits FindingReports on detect.findings
// (publish.FindingsPublisher satisfies it; tests use fakes).
type FindingsPublisher interface {
	PublishFinding(ctx context.Context, fr *detectv1.FindingReport, missionID string, trace *platformv1.TraceContext) (string, error)
}

// EvidenceStore uploads redacted evidence to the artifact prefix
// (evidence.Store satisfies it; tests use fakes).
type EvidenceStore interface {
	Upload(ctx context.Context, bucket, prefix, name string, data []byte) (ref, contentHash string, err error)
}

// AlertPublisher is the bus surface detect.alert publishes through
// (*bus.Client satisfies it; tests use fakes).
type AlertPublisher interface {
	PublishMsg(ctx context.Context, msg *nats.Msg) error
}

// RevalidateStore is the revalidate read/write path over the local fallback
// store (doc 04 §4.1 detect.revalidate; 09's query API post-MVP).
type RevalidateStore interface {
	FindingByFingerprint(ctx context.Context, tenantID, fingerprint string) (*RevalidateTarget, error)
	TransitionState(ctx context.Context, tenantID, findingID, toState string) error
}

// RevalidateTarget is what revalidate needs to re-aim a validator.
type RevalidateTarget struct {
	FindingID string
	Target    string
	MatchedAt string
	CheckID   string
	VulnClass string
	State     string
}

// Deps wires the Coordinator.
type Deps struct {
	Bus      *bus.Client
	Adapters *scanner.Registry
	AVE      *ave.Engine
	// EVS is nil when the sandbox path is disabled (config).
	EVS *evs.Engine
	// Exchanger is the Ruling C9 gatekeeper token-exchange client.
	Exchanger *tokexchange.Client
	Findings  FindingsPublisher
	Alerts    *publish.AlertMapper
	Sink      publish.FindingSink
	// KnownView is the cross-run fingerprint view (nil → run-local dedup).
	KnownView normalize.KnownView
	// Suppressions is the FP triage list (nil → no triage).
	Suppressions SuppressionView
	// Revalidate backs detect.revalidate (the fallback store adapter; nil →
	// revalidate tasks fail with a structured error).
	Revalidate RevalidateStore
	Intel      *risk.Mirror
	// OOB canary client for AVE/EVS (nil → OOB validators NOT_VALIDATABLE).
	OOB        ave.OOBClient
	OOBBaseURL string
	// Evidence uploads transcripts/raw output to the artifact prefix
	// (nil → CONFIRMED downgraded to INCONCLUSIVE; the zero-FP contract
	// forbids evidence-less CONFIRMED findings, doc 04 §12).
	Evidence EvidenceStore
	// AlertBus publishes detect.alert messages (default: Bus). Tests
	// substitute a fake; production never overrides.
	AlertBus AlertPublisher
	// ExchangeRetry paces token-exchange retries while gatekeeper is
	// unreachable (jobs hold, fail-closed, doc 04 §12).
	ExchangeRetry time.Duration
	// AgentID resolves the registered agent id (worker token subject).
	AgentID func() string
	// AuthorizeFn is the per-target SDK guard call (default
	// Task.AuthorizeTarget). Tests substitute a stub; production NEVER
	// overrides it (fail-closed PEP-2 chain, doc 01 §9 item 4).
	AuthorizeFn func(ctx context.Context, t *agentsdk.Task, target string) error
	// TenantID / OrgID scope sinks and alerts (MVP single cohort).
	TenantID string
	OrgID    string
	Log      *slog.Logger
	// Now is the clock (tests).
	Now func() time.Time
}

// Coordinator implements agentsdk.Module.
type Coordinator struct {
	d Deps

	mu      sync.Mutex
	running map[string]context.CancelFunc // task_id → cancel (Abort path)
}

// New builds the Coordinator module.
func New(d Deps) *Coordinator {
	if d.Log == nil {
		d.Log = slog.Default()
	}
	if d.ExchangeRetry <= 0 {
		d.ExchangeRetry = 5 * time.Second
	}
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.AgentID == nil {
		d.AgentID = func() string { return "detect" }
	}
	return &Coordinator{d: d, running: map[string]context.CancelFunc{}}
}

// capabilities is the registered set (doc 04 §4.1; risk_class_max R2 for the
// module, R1 for detect.enrich).
var capabilities = map[string]platformv1.RiskClass{
	planner.CapScanWeb:     platformv1.RiskClass_RISK_CLASS_R2,
	planner.CapScanNetwork: platformv1.RiskClass_RISK_CLASS_R2,
	planner.CapScanAPI:     platformv1.RiskClass_RISK_CLASS_R2,
	planner.CapRevalidate:  platformv1.RiskClass_RISK_CLASS_R2,
	planner.CapEnrich:      platformv1.RiskClass_RISK_CLASS_R1,
}

// ManifestCapabilities renders the AgentManifest capability list.
func ManifestCapabilities() []*platformv1.Capability {
	out := make([]*platformv1.Capability, 0, len(capabilities))
	for _, name := range []string{
		planner.CapScanWeb, planner.CapScanNetwork, planner.CapScanAPI,
		planner.CapRevalidate, planner.CapEnrich,
	} {
		out = append(out, &platformv1.Capability{
			Name:          name,
			RiskClassMax:  capabilities[name],
			SchemaVersion: "v1",
		})
	}
	return out
}

// Plan implements agentsdk.Module — params validation and the module-level
// risk ceiling (defense in depth; the dispatch PEP already gated this).
func (c *Coordinator) Plan(t *agentsdk.Task) error {
	as := t.Assignment
	cap := as.GetCapability()
	maxRisk, ok := capabilities[cap]
	if !ok {
		return fmt.Errorf("unsupported capability %q", cap)
	}
	if as.GetRiskClass() > maxRisk {
		return fmt.Errorf("risk class %s exceeds %s ceiling for %s", as.GetRiskClass(), maxRisk, cap)
	}
	if cap != planner.CapRevalidate && len(as.GetTargets()) == 0 {
		return fmt.Errorf("%s requires at least one target", cap)
	}
	if _, err := ParseParams(cap, as.GetParams()); err != nil {
		return err
	}
	return nil
}

// Run implements agentsdk.Module.
func (c *Coordinator) Run(ctx context.Context, t *agentsdk.Task, emit *agentsdk.Emitter) error {
	as := t.Assignment
	ctx, cancel := context.WithCancel(ctx)
	c.mu.Lock()
	c.running[as.GetTaskId()] = cancel
	c.mu.Unlock()
	defer func() {
		cancel()
		c.mu.Lock()
		delete(c.running, as.GetTaskId())
		c.mu.Unlock()
	}()

	params, err := ParseParams(as.GetCapability(), as.GetParams())
	if err != nil {
		return err
	}

	// Coordinator pre-flight (doc 04 §10.1 layer 2 — defense-in-depth
	// re-check of the gatekeeper-issued token; Ruling B.2): every target
	// string must pass the SDK guard BEFORE any job is planned. The SDK
	// already verified signature/expiry/manifest; this re-check also seeds
	// the honest targets_touched record.
	for _, target := range as.GetTargets() {
		if err := c.authorizeTarget(ctx, t, target); err != nil {
			return err // REJECTED_UNAUTHORIZED + SCOPE_VIOLATION via the SDK
		}
	}

	switch as.GetCapability() {
	case planner.CapScanWeb, planner.CapScanNetwork, planner.CapScanAPI:
		return c.runScan(ctx, t, emit, params)
	case planner.CapRevalidate:
		return c.runRevalidate(ctx, t, emit, params)
	case planner.CapEnrich:
		return c.runEnrich(ctx, t, emit, params)
	default:
		return fmt.Errorf("unsupported capability %q", as.GetCapability())
	}
}

// Abort implements agentsdk.Module — stop target contact ≤ 5 s (kill /
// revocation): cancel task contexts (scanner children are killed by the
// adapters via the SDK path; EVS sandboxes tear down on ctx).
func (c *Coordinator) Abort() {
	c.mu.Lock()
	cancels := make([]context.CancelFunc, 0, len(c.running))
	for _, cancel := range c.running {
		cancels = append(cancels, cancel)
	}
	c.mu.Unlock()
	for _, cancel := range cancels {
		cancel()
	}
	for _, name := range c.d.Adapters.Names() {
		c.d.Adapters.Get(name).Abort()
	}
}

// authorizeTarget runs the per-target guard (Deps.AuthorizeFn seam; default
// the SDK's Task.AuthorizeTarget — the full PEP-2 chain).
func (c *Coordinator) authorizeTarget(ctx context.Context, t *agentsdk.Task, target string) error {
	if c.d.AuthorizeFn != nil {
		return c.d.AuthorizeFn(ctx, t, target)
	}
	return t.AuthorizeTarget(ctx, target)
}

func (c *Coordinator) now() time.Time { return c.d.Now() }
