// Package pepclient is Discover's thin PEP wrapper over gatekeeper (doc 02
// §9: "a thin wrapper over gatekeeper's pep-sdk — no module-local token or
// policy logic"; Ruling B: module-local pre-flights survive only as
// defense-in-depth re-checks of gatekeeper-issued tokens — never as
// independent issuers).
//
// Orchestrator side (PEP-1-style, order intake): policy-service.Authorize
// fail-closed on every order + ROEService.GetROE for the gatekeeper-resolved
// effective scope (planner seed checks, reducer quarantine, discover://scopes
// mirror).
//
// Worker side (PEP-2): Scope Token verification via the platform agent SDK
// (EdDSA vs gatekeeper JWKS over HTTP :8080, task binding, capability,
// manifest/scope membership, revocation cache) — the module mints nothing.
package pepclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/oklog/ulid/v2"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/pep"
	sdkscope "github.com/aegisbastion/aegisbastion/sdks/go/scope"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// ErrGatekeeperUnreachable marks PDP outages — every caller fails closed
// (doc 02 §7.2: order intake fails closed when gatekeeper is unreachable).
var ErrGatekeeperUnreachable = errors.New("gatekeeper unreachable")

// Client wraps the gatekeeper clients + SDK token verifier.
type Client struct {
	policy   gatekeeperv1.PolicyServiceClient
	roe      gatekeeperv1.ROEServiceClient
	verifier *token.Verifier
	fetcher  manifest.Fetcher
	// Revocations is the shared revocation cache (fed by tasks.revocations.v1
	// via the agentsdk runtime on workers, or a standalone subscriber here).
	Revocations *pep.RevocationCache
	// ActorID is the service identity used as the Authorize principal.
	ActorID string
	// Now — clock injection (tests).
	Now func() time.Time
}

// New builds a Client over an existing gatekeeper gRPC conn and a token
// verifier. jwksSource: token.NewHTTPKeySource(GATEKEEPER_JWKS_URL, nil) in
// production (JWKS from gatekeeper :8080, per the module contract).
func New(conn *grpc.ClientConn, verifier *token.Verifier, fetcher manifest.Fetcher) *Client {
	return &Client{
		policy:      gatekeeperv1.NewPolicyServiceClient(conn),
		roe:         gatekeeperv1.NewROEServiceClient(conn),
		verifier:    verifier,
		fetcher:     fetcher,
		Revocations: pep.NewRevocationCache(),
		ActorID:     "discover-orchestrator",
		Now:         time.Now,
	}
}

// NewVerifier builds the SDK token verifier over an HTTP JWKS source
// (gatekeeper :8080 /.well-known/gatekeeper-jwks.json).
func NewVerifier(jwksURL string) *token.Verifier {
	return token.NewVerifier(token.NewKeyCache(token.NewHTTPKeySource(jwksURL, nil)))
}

// Decision pairs the model.Gate record with the evaluated risk class.
type Decision struct {
	Gate      model.Gate
	RiskClass string // "R0".."R3" as evaluated by gatekeeper's capreg
	Allowed   bool
}

// AuthorizeTechnique asks gatekeeper's policy-service to authorize one
// technique of an order over the given seed targets (doc 02 §2.2
// authz-precheck; PEP-1-style at order intake). Fail-closed: transport
// errors map to ErrGatekeeperUnreachable and must deny intake.
func (c *Client) AuthorizeTechnique(ctx context.Context, order *model.DiscoveryOrder, technique model.Technique, roeVersion uint64, targets []string) (*Decision, error) {
	req := &gatekeeperv1.AuthorizeRequest{
		Request: &gatekeeperv1.AuthorizationRequest{
			RequestId: "req_" + ulid.Make().String(),
			Principal: &gatekeeperv1.Principal{
				Kind: "service",
				Id:   c.ActorID,
			},
			Task: &gatekeeperv1.TaskContext{
				TaskId:    order.OrderID,
				Commander: order.RequestedBy.Commander,
			},
			Capability:  technique.Capability(),
			Targets:     targets,
			RoeId:       order.Authorization.ROEID,
			RoeVersion:  roeVersion,
			RequestedAt: timestamppb.New(c.Now().UTC()),
		},
	}
	resp, err := c.policy.Authorize(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("%w: authorize: %v", ErrGatekeeperUnreachable, err)
	}
	d := resp.GetDecision()
	gate := model.Gate{
		Decision:   "deny",
		Reasons:    []string{},
		ROEID:      d.GetRoeId(),
		DecisionID: d.GetDecisionId(),
		DecidedAt:  d.GetDecidedAt().AsTime().UTC().Format(time.RFC3339),
	}
	allowed := d.GetDecision() == gatekeeperv1.Decision_DECISION_ALLOW
	if allowed {
		gate.Decision = "allow"
	}
	for _, r := range d.GetReasons() {
		code := r.GetCode().String()
		code = trimDenyReasonPrefix(code)
		if r.GetDetail() != "" {
			code = code + ": " + r.GetDetail()
		}
		gate.Reasons = append(gate.Reasons, code)
	}
	return &Decision{Gate: gate, RiskClass: riskClassString(d.GetRiskClass()), Allowed: allowed}, nil
}

func trimDenyReasonPrefix(s string) string {
	// DENY_REASON_TARGET_NOT_IN_SCOPE → TARGET_NOT_IN_SCOPE (the doc 02 §3.3
	// surface form — gatekeeper's stable enum, verbatim).
	const p = "DENY_REASON_"
	if len(s) > len(p) && s[:len(p)] == p {
		return s[len(p):]
	}
	return s
}

func riskClassString(rc platformv1.RiskClass) string {
	switch rc {
	case platformv1.RiskClass_RISK_CLASS_R0:
		return "R0"
	case platformv1.RiskClass_RISK_CLASS_R1:
		return "R1"
	case platformv1.RiskClass_RISK_CLASS_R2:
		return "R2"
	case platformv1.RiskClass_RISK_CLASS_R3:
		return "R3"
	}
	return ""
}

// ResolvedROE is the gatekeeper record + its scope in SDK-evaluable form.
type ResolvedROE struct {
	ROE     *gatekeeperv1.RulesOfEngagement
	Scope   *sdkscope.Scope
	Version uint64
}

// ResolveROE fetches the RoE record and maps its scope into the SDK scope
// form (planner seed checks, reducer quarantine, discover://scopes mirror —
// the gatekeeper-resolved effective scope, doc 02 §6.1).
func (c *Client) ResolveROE(ctx context.Context, roeID string) (*ResolvedROE, error) {
	resp, err := c.roe.GetROE(ctx, &gatekeeperv1.GetROERequest{RoeId: roeID})
	if err != nil {
		return nil, fmt.Errorf("%w: get roe %s: %v", ErrGatekeeperUnreachable, roeID, err)
	}
	roe := resp.GetRoe()
	s := roe.GetScope()
	return &ResolvedROE{
		ROE: roe,
		Scope: &sdkscope.Scope{
			Domains:          s.GetDomains(),
			CIDRs:            s.GetCidrs(),
			CloudAccounts:    s.GetCloudAccounts(),
			AssetGroupIDs:    s.GetAssetGroupIds(),
			ExplicitExcludes: s.GetExplicitExcludes(),
		},
		Version: roe.GetVersion(),
	}, nil
}

// VerifyTaskToken is the worker-side PEP-2 re-check (doc 02 §2.3 step 2 +
// §6.1: the worker refuses a task whose seed is not covered by its Scope
// Token manifest/scope). Behavior:
//
//   - R0 task without a token ⇒ allowed (R0 requires no per-target token,
//     doc 11 §1); connectors still contact only sources, never targets.
//   - R1+ task without a token ⇒ refuse (fail-closed).
//   - Any token present ⇒ full SDK verification (EdDSA vs JWKS, expiry,
//     task binding, capability grant) + manifest/scope membership of the
//     seed + revocation cache. Gatekeeper unreachable (JWKS) ⇒ refuse.
//
// The module never mints tokens (Ruling B/C5) — this only RE-verifies.
func (c *Client) VerifyTaskToken(ctx context.Context, task model.Task) (*token.Claims, error) {
	if c.Revocations != nil {
		if revoked, reason := c.Revocations.Revoked(task.ROEID, task.Technique.Capability(), task.Seed.Value); revoked {
			return nil, fmt.Errorf("%w: %s", pep.ErrRevoked, reason)
		}
	}
	if task.ScopeToken == "" {
		if task.RiskClass != "" && task.RiskClass != "R0" {
			return nil, fmt.Errorf("%w: %s task %s carries no scope token",
				pep.ErrNoAuthorization, task.RiskClass, task.TaskID)
		}
		return nil, nil // R0 without token: allowed, zero target contact
	}
	claims, err := c.verifier.Verify(ctx, task.ScopeToken)
	if err != nil {
		return nil, fmt.Errorf("scope token verification failed: %w", err)
	}
	if claims.TaskID != task.TaskID {
		return nil, fmt.Errorf("%w: token task_id %q, task %q",
			pep.ErrTaskBinding, claims.TaskID, task.TaskID)
	}
	if !claims.Permits(task.Technique.Capability()) {
		return nil, fmt.Errorf("%w: capability %q not granted by token",
			pep.ErrTaskBinding, task.Technique.Capability())
	}
	man, err := manifest.Load(ctx, c.fetcher, claims.Targets, claims.ScopeBound)
	if err != nil {
		return nil, fmt.Errorf("token manifest fetch/verify failed: %w", err)
	}
	if claims.ScopeBound {
		dec := man.EvaluateScope(task.Seed.Value)
		if !dec.Allowed {
			return nil, fmt.Errorf("%w: %s", pep.ErrTargetOutOfScope, dec.Reason)
		}
	} else if !man.Contains(task.Seed.Value) {
		return nil, fmt.Errorf("%w: seed %q", pep.ErrTargetNotInManifest, task.Seed.Value)
	}
	return claims, nil
}
