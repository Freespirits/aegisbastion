// Package policy implements policy-service — the platform's single PDP
// (doc 11 §2.1.3/§3.3, Ruling B). The evaluation pipeline is HARD-CODED in
// the doc 11 §3.3 order; MVP implements steps 1–11 (OPA step 12 is a Later
// item). Every dependency failure fails closed for R1–R3.
package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/blackout"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/capreg"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ratelimit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/revocation"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/scopecanon"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
)

// DefaultR1RPS is doc 01 §5.3's default rate cap for R1 (100 rps/target)
// applied when the RoE declares no explicit cap for the capability.
const DefaultR1RPS = 100

// ROEReader is the policy-service view of roe-service.
type ROEReader interface {
	LoadROE(ctx context.Context, roeID string, version uint64) (*gatekeeperv1.RulesOfEngagement, error)
	EffectiveTargets(ctx context.Context, roeID string, version uint64) (includes, excludes []string, err error)
}

// ApprovalFinder is the policy-service view of approval-service.
type ApprovalFinder interface {
	FindValidApproval(ctx context.Context, roeID string, roeVersion uint64, capability string, targets []string) (*gatekeeperv1.Approval, error)
}

// RevocationSet is the policy-service view of revocation-service.
type RevocationSet interface {
	Active(ctx context.Context) ([]*revocation.Record, error)
}

// InventoryVerifier checks R2/R3 targets against module 09's verified asset
// inventory (pipeline step 4). Nil at Phase 0 (documented deviation: the
// check is skipped until data-platform lands; set DP_INVENTORY_URL to enable).
type InventoryVerifier interface {
	VerifyTargets(ctx context.Context, targets []string) (verified map[string]bool, err error)
}

// RoleChecker is the policy-service view of rbac-service.
type RoleChecker interface {
	HasPermission(ctx context.Context, org, principal, permission string) (bool, error)
}

// Service implements gatekeeper.v1.PolicyService.
type Service struct {
	gatekeeperv1.UnimplementedPolicyServiceServer
	db        *store.DB
	roes      ROEReader
	approvals ApprovalFinder
	revokes   RevocationSet
	roles     RoleChecker
	registry  *capreg.Registry
	limiter   *ratelimit.Limiter
	aud       *audit.Service
	pub       bus.Publisher
	inventory InventoryVerifier // may be nil (Phase 0)
	now       func() time.Time
}

// New wires the PDP.
func New(db *store.DB, roes ROEReader, approvals ApprovalFinder, revokes RevocationSet,
	roles RoleChecker, registry *capreg.Registry, limiter *ratelimit.Limiter,
	aud *audit.Service, pub bus.Publisher, inventory InventoryVerifier) *Service {
	return &Service{
		db: db, roes: roes, approvals: approvals, revokes: revokes, roles: roles,
		registry: registry, limiter: limiter, aud: aud, pub: pub, inventory: inventory, now: time.Now,
	}
}

// commanderPrincipal maps commander names to their canonical service
// identities (doc 11 §4: spiffe://platform/cai | /hexstrike).
var commanderPrincipal = map[string]struct{ id, spiffe string }{
	"cai":       {"svc-cai-commander", "spiffe://platform/cai"},
	"hexstrike": {"svc-hexstrike-commander", "spiffe://platform/hexstrike"},
}

// Authorize runs the hard-coded pipeline and returns the DecisionEvent.
// gRPC-level errors are reserved for malformed requests; policy outcomes are
// always DecisionEvents (allow or deny), never transport errors.
func (s *Service) Authorize(ctx context.Context, req *gatekeeperv1.AuthorizeRequest) (*gatekeeperv1.AuthorizeResponse, error) {
	start := s.now()
	ar := req.GetRequest()
	if ar == nil {
		return nil, errors.New("policy: request is required")
	}
	eval := &evaluation{svc: s, req: ar, decidedAt: start}

	risk, ok := s.registry.Lookup(ar.GetCapability())
	if !ok {
		return eval.finish(ctx, platformv1.RiskClass_RISK_CLASS_UNSPECIFIED,
			deny(gatekeeperv1.DenyReason_DENY_REASON_CAPABILITY_NOT_ALLOWED,
				fmt.Sprintf("capability %q has no registered risk class (fail-closed)", ar.GetCapability())))
	}
	eval.risk = risk // steps 4–10 read the resolved risk class

	// Steps 1–11, hard-coded order (doc 11 §3.3). First failure decides.
	steps := []func(context.Context) *gatekeeperv1.Reason{
		eval.stepAuth,         // 1 AUTH
		eval.stepRevocation,   // 2 REVOCATION
		eval.stepROEActive,    // 3 ROE_ACTIVE
		eval.stepTargetScope,  // 4 TARGET_SCOPE
		eval.stepCapability,   // 5 CAPABILITY
		eval.stepLegal,        // 6 LEGAL
		eval.stepApproval,     // 7 APPROVAL
		eval.stepWindow,       // 8 WINDOW
		eval.stepJurisdiction, // 9 JURISDICTION/DATA
		eval.stepRate,         // 10 RATE
	}
	for _, step := range steps {
		if reason := step(ctx); reason != nil {
			return eval.finish(ctx, risk, deny(reason.GetCode(), reason.GetDetail()))
		}
		if eval.failed { // dependency failure already converted to a deny
			return eval.finish(ctx, risk, deny(eval.failCode, eval.failDetail))
		}
	}
	// Step 11 (AUDIT_WRITE) runs inside finish for both allow and deny.
	return eval.finish(ctx, risk, allow())
}

// ---------------------------------------------------------------------------
// evaluation state
// ---------------------------------------------------------------------------

type evaluation struct {
	svc       *Service
	req       *gatekeeperv1.AuthorizationRequest
	roe       *gatekeeperv1.RulesOfEngagement
	risk      platformv1.RiskClass
	decidedAt time.Time

	approvalID   string // set by step 7, consumed by token-service at mint
	retryAfterMs uint32 // set by step 10 on RATE_LIMITED

	// dependency failure converted to deny (fail-closed)
	failed     bool
	failCode   gatekeeperv1.DenyReason
	failDetail string
}

type outcome struct {
	allow  bool
	code   gatekeeperv1.DenyReason
	detail string
}

func allow() outcome { return outcome{allow: true} }

func deny(code gatekeeperv1.DenyReason, detail string) outcome {
	return outcome{code: code, detail: detail}
}

func (e *evaluation) dependencyFail(code gatekeeperv1.DenyReason, detail string) *gatekeeperv1.Reason {
	e.failed = true
	e.failCode = code
	e.failDetail = detail
	return nil
}

// Step 1 — AUTH: caller identity valid; commander may only submit for its own
// tasks; caller must hold a role that may submit work (doc 11 §4: commanders
// have no permission to mint/approve/modify — but they may REQUEST).
func (e *evaluation) stepAuth(ctx context.Context) *gatekeeperv1.Reason {
	p := e.req.GetPrincipal()
	if p == nil || p.GetId() == "" {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_UNAUTHENTICATED,
			Detail: "principal.id is required"}
	}
	if p.GetKind() != "service" && p.GetKind() != "user" {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_UNAUTHENTICATED,
			Detail: fmt.Sprintf("principal.kind %q must be service|user", p.GetKind())}
	}
	if sp := p.GetSpiffeId(); sp != "" && !strings.HasPrefix(sp, "spiffe://") {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_UNAUTHENTICATED,
			Detail: fmt.Sprintf("malformed spiffe_id %q", sp)}
	}
	// Commander binding: a commander may only submit for its own tasks.
	if cmdr := e.req.GetTask().GetCommander(); cmdr != "" {
		want, known := commanderPrincipal[cmdr]
		if !known {
			return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_UNAUTHENTICATED,
				Detail: fmt.Sprintf("unknown commander %q", cmdr)}
		}
		if p.GetId() != want.id && p.GetSpiffeId() != want.spiffe {
			return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_UNAUTHENTICATED,
				Detail: fmt.Sprintf("commander %q may only submit via %s (%s)", cmdr, want.id, want.spiffe)}
		}
	}
	// Role check: task:submit (commanders) or revocation… any principal that may
	// request work holds task:submit, task:execute, or is operator/admin.
	ok, err := e.svc.roles.HasPermission(ctx, "", p.GetId(), "task:submit")
	if err != nil {
		return e.dependencyFail(gatekeeperv1.DenyReason_DENY_REASON_UNAUTHENTICATED,
			"rbac store unavailable (fail-closed): "+err.Error())
	}
	if !ok {
		ok, err = e.svc.roles.HasPermission(ctx, "", p.GetId(), "task:execute")
		if err != nil {
			return e.dependencyFail(gatekeeperv1.DenyReason_DENY_REASON_UNAUTHENTICATED,
				"rbac store unavailable (fail-closed): "+err.Error())
		}
	}
	if !ok {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_FORBIDDEN_ROLE,
			Detail: fmt.Sprintf("principal %q holds no role that may request authorization", p.GetId())}
	}
	return nil
}

// Step 2 — REVOCATION: global/RoE/target/capability (fail-closed when the set
// cannot be read: deny as if globally revoked).
func (e *evaluation) stepRevocation(ctx context.Context) *gatekeeperv1.Reason {
	recs, err := e.svc.revokes.Active(ctx)
	if err != nil {
		return e.dependencyFail(gatekeeperv1.DenyReason_DENY_REASON_REVOKED_GLOBAL,
			"revocation set unavailable (fail-closed): "+err.Error())
	}
	byScope := map[string]map[string]bool{}
	for _, r := range recs {
		if byScope[r.Scope] == nil {
			byScope[r.Scope] = map[string]bool{}
		}
		byScope[r.Scope][r.ScopeValue] = true
	}
	if len(byScope["global"]) > 0 {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_REVOKED_GLOBAL,
			Detail: "global revocation active (kill switch)"}
	}
	if byScope["roe"][e.req.GetRoeId()] {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_REVOKED_ROE,
			Detail: fmt.Sprintf("RoE %s is revoked", e.req.GetRoeId())}
	}
	for _, t := range e.req.GetTargets() {
		ct, _ := scopecanon.Canonical(t)
		if byScope["target"][ct] || byScope["target"][t] {
			return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_REVOKED_TARGET,
				Detail: fmt.Sprintf("target %s is revoked", t)}
		}
	}
	if byScope["capability"][e.req.GetCapability()] {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_REVOKED_CAPABILITY,
			Detail: fmt.Sprintf("capability %s is revoked", e.req.GetCapability())}
	}
	return nil
}

// Step 3 — ROE_ACTIVE: exists, active, in window, version matches.
func (e *evaluation) stepROEActive(ctx context.Context) *gatekeeperv1.Reason {
	roe, err := e.svc.roes.LoadROE(ctx, e.req.GetRoeId(), 0)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_ROE_NOT_ACTIVE,
				Detail: fmt.Sprintf("RoE %s not found", e.req.GetRoeId())}
		}
		return e.dependencyFail(gatekeeperv1.DenyReason_DENY_REASON_ROE_NOT_ACTIVE,
			"RoE store unavailable (fail-closed): "+err.Error())
	}
	e.roe = roe
	switch roe.GetStatus() {
	case gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE:
	case gatekeeperv1.ROEStatus_ROE_STATUS_EXPIRED:
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_ROE_EXPIRED,
			Detail: fmt.Sprintf("RoE %s v%d expired (window closed %s)", roe.GetRoeId(), roe.GetVersion(), roe.GetValidUntil().AsTime().Format(time.RFC3339))}
	default:
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_ROE_NOT_ACTIVE,
			Detail: fmt.Sprintf("RoE %s v%d is %s", roe.GetRoeId(), roe.GetVersion(), roe.GetStatus())}
	}
	now := e.svc.now().UTC()
	if now.Before(roe.GetValidFrom().AsTime()) {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_ROE_NOT_ACTIVE,
			Detail: fmt.Sprintf("RoE %s window opens %s", roe.GetRoeId(), roe.GetValidFrom().AsTime().Format(time.RFC3339))}
	}
	if !now.Before(roe.GetValidUntil().AsTime()) {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_ROE_EXPIRED,
			Detail: fmt.Sprintf("RoE %s window closed %s", roe.GetRoeId(), roe.GetValidUntil().AsTime().Format(time.RFC3339))}
	}
	if want := e.req.GetRoeVersion(); want != 0 && want != roe.GetVersion() {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_ROE_NOT_ACTIVE,
			Detail: fmt.Sprintf("RoE version mismatch: request pins v%d, latest is v%d", want, roe.GetVersion())}
	}
	return nil
}

// Step 4 — TARGET_SCOPE: every target ∈ resolved list, ∉ excludes (exclusions
// win); R2/R3 also ∈ verified inventory when module 09 is wired.
func (e *evaluation) stepTargetScope(ctx context.Context) *gatekeeperv1.Reason {
	targets := e.req.GetTargets()
	if len(targets) == 0 {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_TARGET_NOT_IN_SCOPE,
			Detail: "no targets supplied"}
	}
	includes, excludes, err := e.svc.roes.EffectiveTargets(ctx, e.roe.GetRoeId(), e.roe.GetVersion())
	if err != nil {
		return e.dependencyFail(gatekeeperv1.DenyReason_DENY_REASON_TARGET_NOT_IN_SCOPE,
			"resolved target list unavailable (fail-closed): "+err.Error())
	}
	for _, t := range targets {
		inScope, excluded := scopecanon.Evaluate(includes, excludes, t)
		if excluded {
			return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_TARGET_EXCLUDED,
				Detail: fmt.Sprintf("%s hits an explicit exclusion (exclusions always win)", t)}
		}
		if !inScope {
			return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_TARGET_NOT_IN_SCOPE,
				Detail: fmt.Sprintf("%s outside resolved target list v%d", t, e.roe.GetVersion())}
		}
	}
	// R2/R3 verified-inventory membership (module 09). Phase-0 deviation:
	// skipped while data-platform is not deployed; once DP_INVENTORY_URL is
	// set this fails closed on unreachable/erroring inventory.
	if (e.risk == platformv1.RiskClass_RISK_CLASS_R2 || e.risk == platformv1.RiskClass_RISK_CLASS_R3) && e.svc.inventory != nil {
		verified, err := e.svc.inventory.VerifyTargets(ctx, targets)
		if err != nil {
			return e.dependencyFail(gatekeeperv1.DenyReason_DENY_REASON_TARGET_UNVERIFIED,
				"asset inventory unavailable (fail-closed): "+err.Error())
		}
		for _, t := range targets {
			if !verified[t] {
				return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_TARGET_UNVERIFIED,
					Detail: fmt.Sprintf("%s not in verified asset inventory", t)}
			}
		}
	}
	return nil
}

// Step 5 — CAPABILITY: ∈ allowed_capabilities (exact or "prefix.*" wildcard);
// risk class ≤ max_risk_class.
func (e *evaluation) stepCapability(ctx context.Context) *gatekeeperv1.Reason {
	if !capabilityAllowed(e.roe.GetConstraints().GetAllowedCapabilities(), e.req.GetCapability()) {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_CAPABILITY_NOT_ALLOWED,
			Detail: fmt.Sprintf("capability %s ∉ allowed_capabilities", e.req.GetCapability())}
	}
	if riskRank(e.risk) > riskRank(e.roe.GetConstraints().GetMaxRiskClass()) {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_RISK_CLASS_EXCEEDED,
			Detail: fmt.Sprintf("%s exceeds RoE max_risk_class %s",
				capreg.RiskClassString(e.risk), capreg.RiskClassString(e.roe.GetConstraints().GetMaxRiskClass()))}
	}
	return nil
}

func capabilityAllowed(allowed []string, capability string) bool {
	for _, a := range allowed {
		if a == capability {
			return true
		}
		if strings.HasSuffix(a, ".*") && strings.HasPrefix(capability, strings.TrimSuffix(a, "*")) {
			return true
		}
	}
	return false
}

func riskRank(rc platformv1.RiskClass) int {
	switch rc {
	case platformv1.RiskClass_RISK_CLASS_R0:
		return 0
	case platformv1.RiskClass_RISK_CLASS_R1:
		return 1
	case platformv1.RiskClass_RISK_CLASS_R2:
		return 2
	case platformv1.RiskClass_RISK_CLASS_R3:
		return 3
	default:
		return -1
	}
}

// Step 6 — LEGAL: R2/R3 legal artifact present + verified; Azure stress id.
func (e *evaluation) stepLegal(ctx context.Context) *gatekeeperv1.Reason {
	if riskRank(e.risk) >= riskRank(platformv1.RiskClass_RISK_CLASS_R2) {
		la := e.roe.GetLegalArtifact()
		if la == nil || la.GetDocumentSha256() == "" || la.GetStorageUri() == "" ||
			la.GetVerifiedBy() == "" || la.GetVerifiedAt() == nil {
			return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_LEGAL_ARTIFACT_MISSING,
				Detail: "R2/R3 requires a present + verified legal artifact"}
		}
	}
	if strings.HasPrefix(e.req.GetCapability(), "stress.") &&
		e.roe.GetConstraints().GetAzurePentestNotificationId() == "" {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_LEGAL_ARTIFACT_MISSING,
			Detail: "stress.* requires azure_pentest_notification_id (Azure pen-test rules of engagement)"}
	}
	return nil
}

// Step 7 — APPROVAL: R3 always; R2 stress.* when the RoE binds
// "R2:stress.*:production". Valid four-eyes approval, not expired (72 h),
// targets ⊆ approved set.
func (e *evaluation) stepApproval(ctx context.Context) *gatekeeperv1.Reason {
	required := e.risk == platformv1.RiskClass_RISK_CLASS_R3
	if e.risk == platformv1.RiskClass_RISK_CLASS_R2 && strings.HasPrefix(e.req.GetCapability(), "stress.") {
		for _, binding := range e.roe.GetConstraints().GetRequiresApprovalFor() {
			if binding == "R2:stress.*:production" {
				required = true
				break
			}
		}
	}
	if !required {
		return nil
	}
	a, err := e.svc.approvals.FindValidApproval(ctx, e.roe.GetRoeId(), e.roe.GetVersion(),
		e.req.GetCapability(), e.req.GetTargets())
	if err != nil {
		return e.dependencyFail(gatekeeperv1.DenyReason_DENY_REASON_APPROVAL_MISSING,
			"approval store unavailable (fail-closed): "+err.Error())
	}
	if a == nil {
		code := gatekeeperv1.DenyReason_DENY_REASON_APPROVAL_MISSING
		detail := fmt.Sprintf("%s %s requires a valid four-eyes approval covering the requested targets",
			capreg.RiskClassString(e.risk), e.req.GetCapability())
		return &gatekeeperv1.Reason{Code: code, Detail: detail}
	}
	e.approvalID = a.GetApprovalId()
	return nil
}

// Step 8 — WINDOW: not inside a blackout window (RoE-declared tz).
func (e *evaluation) stepWindow(ctx context.Context) *gatekeeperv1.Reason {
	windows := e.roe.GetConstraints().GetBlackoutWindows()
	if len(windows) == 0 {
		return nil
	}
	ws := make([]blackout.Window, 0, len(windows))
	for _, w := range windows {
		ws = append(ws, blackout.Window{RRULE: w.GetRrule(), TZ: w.GetTz()})
	}
	if blackout.Active(e.svc.now().UTC(), ws) {
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_BLACKOUT_WINDOW,
			Detail: "inside a declared blackout window"}
	}
	return nil
}

// Step 9 — JURISDICTION/DATA: region allowed; data classes ⊆.
func (e *evaluation) stepJurisdiction(ctx context.Context) *gatekeeperv1.Reason {
	c := e.roe.GetConstraints()
	if region := e.req.GetContext().GetSourceRegion(); region != "" && len(c.GetJurisdictionsAllowed()) > 0 {
		ok := false
		for _, j := range c.GetJurisdictionsAllowed() {
			if j == region {
				ok = true
				break
			}
		}
		if !ok {
			return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_JURISDICTION_DENIED,
				Detail: fmt.Sprintf("source region %s ∉ jurisdictions_allowed", region)}
		}
	}
	allowed := map[string]bool{}
	for _, d := range c.GetDataClasses() {
		allowed[d] = true
	}
	for _, d := range e.req.GetContext().GetDataClassesTouched() {
		if !allowed[d] {
			return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_DATA_CLASS_DENIED,
				Detail: fmt.Sprintf("data class %s ∉ RoE data_classes", d)}
		}
	}
	return nil
}

// Step 10 — RATE: projected use under caps (RoE rate_caps; doc 01 default
// 100 rps for R1 when undeclared).
func (e *evaluation) stepRate(ctx context.Context) *gatekeeperv1.Reason {
	caps := e.roe.GetConstraints().GetRateCaps()
	capability := e.req.GetCapability()
	var rps uint32
	var matched string
	if entry, ok := caps[capability]; ok {
		rps, matched = entry.GetRps(), capability
	} else {
		// Longest wildcard pattern match ("stress.*").
		best := ""
		for pattern, entry := range caps {
			if strings.HasSuffix(pattern, ".*") && strings.HasPrefix(capability, strings.TrimSuffix(pattern, "*")) {
				if len(pattern) > len(best) {
					best, rps, matched = pattern, entry.GetRps(), pattern
				}
			}
		}
	}
	if rps == 0 {
		if e.risk == platformv1.RiskClass_RISK_CLASS_R1 {
			rps = DefaultR1RPS // doc 01 §5.3 default cap
		} else {
			return nil // no cap declared for this capability
		}
	}
	key := e.roe.GetRoeId() + ":" + matched
	allowed, retry := e.svc.limiter.Allow(key, rps)
	if !allowed {
		e.retryAfterMs = uint32(retry.Milliseconds()) + 1
		return &gatekeeperv1.Reason{Code: gatekeeperv1.DenyReason_DENY_REASON_RATE_LIMITED,
			Detail: fmt.Sprintf("projected use exceeds rate cap %s=%d rps", matched, rps)}
	}
	return nil
}

// ---------------------------------------------------------------------------
// decision finalization (step 11 AUDIT_WRITE + persistence + bus)
// ---------------------------------------------------------------------------

func (e *evaluation) finish(ctx context.Context, risk platformv1.RiskClass, oc outcome) (*gatekeeperv1.AuthorizeResponse, error) {
	e.risk = risk
	now := e.svc.now().UTC()
	ev := &gatekeeperv1.DecisionEvent{
		DecisionId:    ids.New("dec"),
		RequestId:     e.req.GetRequestId(),
		RiskClass:     risk,
		RoeId:         e.req.GetRoeId(),
		RoeVersion:    e.roeVersion(),
		EvalLatencyMs: uint32(now.Sub(e.decidedAt).Milliseconds()),
		DecidedAt:     timestamppb.New(now),
		RetryAfterMs:  e.retryAfterMs,
	}
	if ev.RequestId == "" {
		ev.RequestId = ids.New("req")
	}
	if oc.allow {
		ev.Decision = gatekeeperv1.Decision_DECISION_ALLOW
	} else {
		ev.Decision = gatekeeperv1.Decision_DECISION_DENY
		ev.Reasons = []*gatekeeperv1.Reason{{Code: oc.code, Detail: oc.detail}}
	}

	if e.req.GetDryRun() {
		// Dry-run (PEP-3 preflight): no persistence, no publish, no audit
		// (AuthorizationRequest contract comment, proto policy.proto).
		return &gatekeeperv1.AuthorizeResponse{Decision: ev}, nil
	}

	// Step 11 — AUDIT_WRITE: the decision must be durably recorded. The
	// decision row (authz_decisions) and the hash-chained audit event are
	// both durability requirements; R1–R3 fail closed to AUDIT_UNAVAILABLE.
	if err := e.svc.persistDecision(ctx, e.req, ev, e.approvalID); err != nil {
		return e.auditGate(ctx, ev, "decision persistence failed: "+err.Error())
	}
	if err := e.svc.recordDecisionAudit(ctx, e.req, ev); err != nil {
		return e.auditGate(ctx, ev, "audit ingest failed: "+err.Error())
	}

	// Bus: decisions on authz.decisions.v1; denials additionally on
	// authz.denials.v1 (doc 11 §2.3). Publish is best-effort after durable
	// record — the RPC response is the synchronous contract.
	if err := e.svc.pub.Publish(ctx, bus.SubjectDecisions, ev); err != nil {
		fmt.Printf("policy: WARNING publish decision %s: %v\n", ev.GetDecisionId(), err)
	}
	if ev.GetDecision() == gatekeeperv1.Decision_DECISION_DENY {
		if err := e.svc.pub.Publish(ctx, bus.SubjectDenials, ev); err != nil {
			fmt.Printf("policy: WARNING publish denial %s: %v\n", ev.GetDecisionId(), err)
		}
	}
	return &gatekeeperv1.AuthorizeResponse{Decision: ev}, nil
}

// auditGate converts a durability failure into the fail-closed outcome
// (doc 11 §2.2/§7): R1–R3 deny with AUDIT_UNAVAILABLE; R0 (never minted a
// token for) also denies here — "passive is not unaccountable" (doc 11 §10)
// but R0 audit MAY be locally spooled per doc 11 §2.2, so R0 keeps its
// original outcome... At MVP a failed audit write means the decision was not
// recorded at all, so we deny at every class and let the caller retry.
func (e *evaluation) auditGate(ctx context.Context, ev *gatekeeperv1.DecisionEvent, detail string) (*gatekeeperv1.AuthorizeResponse, error) {
	ev.Decision = gatekeeperv1.Decision_DECISION_DENY
	ev.Reasons = []*gatekeeperv1.Reason{{
		Code:   gatekeeperv1.DenyReason_DENY_REASON_AUDIT_UNAVAILABLE,
		Detail: detail,
	}}
	// Best-effort: publish the AUDIT_UNAVAILABLE denial so commanders see it.
	if err := e.svc.pub.Publish(ctx, bus.SubjectDecisions, ev); err != nil {
		fmt.Printf("policy: WARNING publish decision %s: %v\n", ev.GetDecisionId(), err)
	}
	if err := e.svc.pub.Publish(ctx, bus.SubjectDenials, ev); err != nil {
		fmt.Printf("policy: WARNING publish denial %s: %v\n", ev.GetDecisionId(), err)
	}
	return &gatekeeperv1.AuthorizeResponse{Decision: ev}, nil
}

func (e *evaluation) roeVersion() uint64 {
	if e.roe == nil {
		return 0
	}
	return e.roe.GetVersion()
}

// persistDecision writes the authz_decisions row (MintToken's precondition:
// no token without a DecisionEvent grant).
func (s *Service) persistDecision(ctx context.Context, ar *gatekeeperv1.AuthorizationRequest, ev *gatekeeperv1.DecisionEvent, approvalID string) error {
	principalJSON, _ := json.Marshal(map[string]string{
		"kind": ar.GetPrincipal().GetKind(), "id": ar.GetPrincipal().GetId(),
		"spiffe_id": ar.GetPrincipal().GetSpiffeId(),
	})
	targetsJSON, _ := json.Marshal(ar.GetTargets())
	type reasonDoc struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	var reasons []reasonDoc
	for _, r := range ev.GetReasons() {
		reasons = append(reasons, reasonDoc{Code: reasonCodeString(r.GetCode()), Detail: r.GetDetail()})
	}
	reasonsJSON, _ := json.Marshal(reasons)
	if reasons == nil {
		reasonsJSON = []byte("[]")
	}
	decision := "allow"
	if ev.GetDecision() == gatekeeperv1.Decision_DECISION_DENY {
		decision = "deny"
	}
	riskClass := capreg.RiskClassString(ev.GetRiskClass())
	var riskArg any
	if riskClass != "" {
		riskArg = riskClass
	}
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO authz_decisions
		  (decision_id, request_id, principal, task_id, parent_plan_id, capability, targets,
		   roe_id, roe_version, risk_class, decision, reasons, eval_latency_ms, decided_at)
		VALUES ($1,$2,$3::jsonb,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12::jsonb,$13,$14)`,
		ev.GetDecisionId(), ev.GetRequestId(), string(principalJSON),
		nullStr(ar.GetTask().GetTaskId()), nullStr(ar.GetTask().GetParentPlanId()),
		ar.GetCapability(), string(targetsJSON),
		nullStr(ev.GetRoeId()), nullInt(int(ev.GetRoeVersion())), riskArg, decision,
		string(reasonsJSON), int(ev.GetEvalLatencyMs()), ev.GetDecidedAt().AsTime())
	if err != nil {
		return fmt.Errorf("policy: persist decision: %w", err)
	}
	return nil
}

// recordDecisionAudit hash-chains the decision into the audit log.
func (s *Service) recordDecisionAudit(ctx context.Context, ar *gatekeeperv1.AuthorizationRequest, ev *gatekeeperv1.DecisionEvent) error {
	reasons := []map[string]any{}
	for _, r := range ev.GetReasons() {
		reasons = append(reasons, map[string]any{"code": reasonCodeString(r.GetCode()), "detail": r.GetDetail()})
	}
	decision := "allow"
	if ev.GetDecision() == gatekeeperv1.Decision_DECISION_DENY {
		decision = "deny"
	}
	// Tenancy: MVP-A runs a single tenant cohort, so decisions chain in the
	// platform partition (""); per-org partitions arrive with the RLS work.
	payload := map[string]any{
		"decision_id":    ev.GetDecisionId(),
		"request_id":     ev.GetRequestId(),
		"decision":       decision,
		"risk_class":     capreg.RiskClassString(ev.GetRiskClass()),
		"capability":     ar.GetCapability(),
		"roe_id":         ev.GetRoeId(),
		"roe_version":    ev.GetRoeVersion(),
		"target_count":   len(ar.GetTargets()),
		"reasons":        reasons,
		"parent_plan_id": ar.GetTask().GetParentPlanId(),
	}
	_, err := s.aud.Record(ctx, audit.Input{
		Kind: audit.KindAuthorizationDecision,
		Actor: map[string]any{
			"kind":      ar.GetPrincipal().GetKind(),
			"id":        ar.GetPrincipal().GetId(),
			"spiffe_id": ar.GetPrincipal().GetSpiffeId(),
		},
		Subject: map[string]any{
			"task_id": ar.GetTask().GetTaskId(),
			"roe_id":  ev.GetRoeId(),
		},
		Payload: payload,
	})
	if err != nil {
		return fmt.Errorf("policy: audit decision: %w", err)
	}
	return nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func nullInt(i int) any {
	if i == 0 {
		return nil
	}
	return i
}

// reasonCodeString renders the proto enum as the doc 11 §3.3 stable code
// (UNAUTHENTICATED, TARGET_NOT_IN_SCOPE, …).
func reasonCodeString(c gatekeeperv1.DenyReason) string {
	return strings.TrimPrefix(c.String(), "DENY_REASON_")
}
