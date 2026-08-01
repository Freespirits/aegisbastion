package token

import (
	"context"
	"crypto/ed25519"
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
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/capreg"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/config"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/keys"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/revocation"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/roe"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/scopecanon"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
)

// ROEReader is the token-service view of roe-service.
type ROEReader interface {
	LoadROE(ctx context.Context, roeID string, version uint64) (*gatekeeperv1.RulesOfEngagement, error)
	EffectiveTargets(ctx context.Context, roeID string, version uint64) (includes, excludes []string, err error)
}

// ApprovalFinder is the token-service view of approval-service.
type ApprovalFinder interface {
	FindValidApproval(ctx context.Context, roeID string, roeVersion uint64, capability string, targets []string) (*gatekeeperv1.Approval, error)
}

// Authorizer re-runs policy for RefreshToken (mid-run re-authorization —
// NOT an unauthenticated refresh, doc 11 §3.2).
type Authorizer interface {
	Authorize(ctx context.Context, req *gatekeeperv1.AuthorizeRequest) (*gatekeeperv1.AuthorizeResponse, error)
}

// RevocationIssuer records+broadcasts token-scope revocations.
type RevocationIssuer interface {
	Issue(ctx context.Context, scope, key, issuedBy, reason string, expiresAt time.Time) (*revocation.Record, error)
}

// Service implements gatekeeper.v1.TokenService.
type Service struct {
	gatekeeperv1.UnimplementedTokenServiceServer
	db         *store.DB
	key        *keys.Keypair
	objects    ObjectStore
	roes       ROEReader
	approvals  ApprovalFinder
	revokes    RevocationIssuer
	authorizer Authorizer // policy-service, for RefreshToken re-authorization
	aud        *audit.Service
	cfg        tokenConfig
	now        func() time.Time
}

type tokenConfig struct {
	issuer         string
	audience       string
	ttl            time.Duration
	manifestBucket string
	uriPrefix      string
}

// New wires the service. authorizer may be nil and set later via
// SetAuthorizer (policy-service and token-service are constructed together).
func New(db *store.DB, key *keys.Keypair, objects ObjectStore, roes ROEReader,
	approvals ApprovalFinder, revokes RevocationIssuer, auditSvc *audit.Service, cfg *config.Config) *Service {
	return &Service{
		db: db, key: key, objects: objects, roes: roes, approvals: approvals,
		revokes: revokes, aud: auditSvc,
		cfg: tokenConfig{
			issuer:         cfg.TokenIssuer,
			audience:       cfg.TokenAudience,
			ttl:            cfg.TokenTTL,
			manifestBucket: cfg.ManifestBucket,
			uriPrefix:      cfg.ManifestURIPrefix,
		},
		now: time.Now,
	}
}

// SetAuthorizer wires the policy re-check used by RefreshToken.
func (s *Service) SetAuthorizer(a Authorizer) { s.authorizer = a }

// decisionRow is the authz_decisions record MintToken authorizes against.
type decisionRow struct {
	DecisionID string
	TaskID     string
	Capability string
	Targets    []string
	RoeID      string
	RoeVersion uint64
	RiskClass  string
	Decision   string
}

func (s *Service) loadDecision(ctx context.Context, decisionID string) (*decisionRow, error) {
	var d decisionRow
	var targetsJSON string
	var taskID, risk *string
	var roeVersion *int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT decision_id, task_id, capability, targets, roe_id, roe_version, risk_class, decision
		FROM authz_decisions WHERE decision_id = $1`, decisionID).
		Scan(&d.DecisionID, &taskID, &d.Capability, &targetsJSON, &d.RoeID, &roeVersion, &risk, &d.Decision)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("token: decision %s not found — no token without a DecisionEvent grant (doc 11 §2.2)", decisionID)
		}
		return nil, fmt.Errorf("token: load decision: %w", err)
	}
	if taskID != nil {
		d.TaskID = *taskID
	}
	if roeVersion != nil {
		d.RoeVersion = uint64(*roeVersion)
	}
	if risk != nil {
		d.RiskClass = *risk
	}
	if err := json.Unmarshal([]byte(targetsJSON), &d.Targets); err != nil {
		return nil, fmt.Errorf("token: decision targets: %w", err)
	}
	return &d, nil
}

// MintToken mints a Scope Token against an existing ALLOW decision.
func (s *Service) MintToken(ctx context.Context, req *gatekeeperv1.MintTokenRequest) (*gatekeeperv1.MintTokenResponse, error) {
	if req.GetDecisionId() == "" || req.GetTaskId() == "" || req.GetSubject() == "" {
		return nil, errors.New("token: decision_id, task_id and subject are required")
	}
	d, err := s.loadDecision(ctx, req.GetDecisionId())
	if err != nil {
		return nil, err
	}
	if d.Decision != "allow" {
		return nil, fmt.Errorf("token: decision %s is not an allow grant", d.DecisionID)
	}
	if d.TaskID != req.GetTaskId() {
		return nil, fmt.Errorf("token: decision %s is bound to task %s, not %s", d.DecisionID, d.TaskID, req.GetTaskId())
	}
	risk, err := capreg.ParseRiskClass(d.RiskClass)
	if err != nil {
		return nil, fmt.Errorf("token: decision has no usable risk class: %w", err)
	}
	if risk == platformv1.RiskClass_RISK_CLASS_R0 {
		return nil, errors.New("token: R0 work needs no Scope Token (doc 11 §1)")
	}
	capabilities := []string{d.Capability}
	if req.GetScopeBound() {
		if risk != platformv1.RiskClass_RISK_CLASS_R1 ||
			(d.Capability != "monitor.watch" && d.Capability != "monitor.rescan") {
			return nil, fmt.Errorf("token: scope-bound watch tokens are valid ONLY for R1 monitor.watch/monitor.rescan, not %s %s (Ruling A)",
				d.RiskClass, d.Capability)
		}
	} else {
		if !sameTargetSet(d.Targets, req.GetTargets()) {
			return nil, fmt.Errorf("token: requested targets must equal the decision's authorized target set")
		}
	}
	roeRec, err := s.roes.LoadROE(ctx, d.RoeID, 0)
	if err != nil {
		return nil, fmt.Errorf("token: RoE re-check failed (fail-closed): %w", err)
	}
	if roeRec.GetStatus() != gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE {
		return nil, fmt.Errorf("token: RoE %s is %s — mint denied", d.RoeID, roeRec.GetStatus())
	}
	now := s.now().UTC()
	if !now.Before(roeRec.GetValidUntil().AsTime()) {
		return nil, fmt.Errorf("token: RoE %s window closed — mint denied", d.RoeID)
	}

	// Approval binding: mandatory for R3 / required R2 stress.* (policy
	// already enforced it; mint re-checks fail-closed and binds approval_id).
	approvalID, err := s.resolveApproval(ctx, roeRec, risk, d.Capability, d.Targets)
	if err != nil {
		return nil, err
	}

	// Rate caps embedded in the token (self-contained PEP enforcement).
	rateCaps := tokenRateCaps(roeRec, risk, d.Capability)

	m := &mintSpec{
		sub: req.GetSubject(), taskID: req.GetTaskId(), roe: roeRec,
		risk: d.RiskClass, capabilities: capabilities, approvalID: approvalID,
		rateCaps: rateCaps, scopeBound: req.GetScopeBound(), targets: d.Targets,
		decisionID: d.DecisionID,
	}
	if req.GetScopeBound() {
		m.targets = nil // scope manifest instead
	}
	return s.mint(ctx, m, 0)
}

// resolveApproval returns the approval_id to bind, enforcing presence where
// required (fail-closed mirror of pipeline step 7).
func (s *Service) resolveApproval(ctx context.Context, roeRec *gatekeeperv1.RulesOfEngagement, risk platformv1.RiskClass, capability string, targets []string) (string, error) {
	required := risk == platformv1.RiskClass_RISK_CLASS_R3
	if risk == platformv1.RiskClass_RISK_CLASS_R2 && strings.HasPrefix(capability, "stress.") {
		for _, b := range roeRec.GetConstraints().GetRequiresApprovalFor() {
			if b == "R2:stress.*:production" {
				required = true
				break
			}
		}
	}
	a, err := s.approvals.FindValidApproval(ctx, roeRec.GetRoeId(), roeRec.GetVersion(), capability, targets)
	if err != nil {
		return "", fmt.Errorf("token: approval lookup failed (fail-closed): %w", err)
	}
	if a == nil {
		if required {
			return "", fmt.Errorf("token: %s %s requires a valid four-eyes approval — none covers the targets (APPROVAL_MISSING)",
				capreg.RiskClassString(risk), capability)
		}
		return "", nil
	}
	return a.GetApprovalId(), nil
}

// tokenRateCaps maps the RoE's rate_caps onto the token claim (max_rps ≡
// rps); R1 falls back to doc 01 §5.3's default 100 rps.
func tokenRateCaps(roeRec *gatekeeperv1.RulesOfEngagement, risk platformv1.RiskClass, capability string) *rateCapsJSON {
	caps := roeRec.GetConstraints().GetRateCaps()
	best := ""
	var entry *gatekeeperv1.RateCapEntry
	for pattern, e := range caps {
		if pattern == capability {
			entry, best = e, pattern
			break
		}
		if strings.HasSuffix(pattern, ".*") && strings.HasPrefix(capability, strings.TrimSuffix(pattern, "*")) && len(pattern) > len(best) {
			entry, best = e, pattern
		}
	}
	out := &rateCapsJSON{}
	if entry != nil {
		out.MaxRPS = entry.GetRps()
		out.MaxConcurrent = entry.GetMaxConcurrent()
	}
	if out.MaxRPS == 0 && risk == platformv1.RiskClass_RISK_CLASS_R1 {
		out.MaxRPS = 100 // doc 01 §5.3 default R1 cap
	}
	if out.MaxRPS == 0 && out.MaxConcurrent == 0 {
		return nil
	}
	return out
}

// mintSpec is everything needed to mint + register one token.
type mintSpec struct {
	sub, taskID  string
	roe          *gatekeeperv1.RulesOfEngagement
	risk         string
	capabilities []string
	approvalID   string
	rateCaps     *rateCapsJSON
	scopeBound   bool
	targets      []string // exact form; nil for scope-bound
	decisionID   string
}

// mint builds the manifest, signs the JWT, registers the token and audits
// the mint. expCap optionally caps the lifetime (exchange path: successor
// may not outlive its parent).
func (s *Service) mint(ctx context.Context, m *mintSpec, expCapUnix int64) (*gatekeeperv1.MintTokenResponse, error) {
	now := s.now().UTC()
	iat := now.Unix()
	exp := now.Add(s.cfg.ttl).Unix()
	if expCapUnix > 0 && exp > expCapUnix {
		exp = expCapUnix
	}
	if exp-iat > int64(config.MaxTokenTTL/time.Second) {
		return nil, fmt.Errorf("token: TTL exceeds the Ruling C5 15-minute cap")
	}
	jti := ids.New("tok")

	claims := &claimsJSON{
		Iss: s.cfg.issuer, Aud: s.cfg.audience, Jti: jti, Sub: m.sub,
		TaskID: m.taskID, RoeID: m.roe.GetRoeId(), RoeVersion: m.roe.GetVersion(),
		RiskClass: m.risk, Capabilities: m.capabilities, ScopeBound: m.scopeBound,
		RateCaps: m.rateCaps, ApprovalID: m.approvalID,
		Iat: iat, Nbf: iat, Exp: exp,
	}

	var objectKey string
	var manifest any
	if m.scopeBound {
		sm := ScopeManifest{
			RoeID:      m.roe.GetRoeId(),
			RoeVersion: m.roe.GetVersion(),
			ResolvedAt: now.Format(time.RFC3339),
		}
		sc := m.roe.GetScope()
		sm.Scope.Domains = orEmpty(sc.GetDomains())
		sm.Scope.CIDRs = orEmpty(sc.GetCidrs())
		sm.Scope.ExplicitExcludes = orEmpty(sc.GetExplicitExcludes())
		sm.Scope.AssetGroupIds = orEmpty(sc.GetAssetGroupIds())
		sm.Scope.CloudAccounts = orEmpty(sc.GetCloudAccounts())
		manifest = sm
		objectKey = "tokens/" + jti + "/scope.json"
	} else {
		if len(m.targets) == 0 {
			return nil, errors.New("token: exact-enumerated manifest requires targets")
		}
		manifest = ExactManifest{Jti: jti, TaskID: m.taskID, Targets: m.targets}
		objectKey = "tokens/" + jti + "/targets.json"
	}
	sha, _, err := putManifest(ctx, s.objects, s.cfg.manifestBucket, objectKey, manifest)
	if err != nil {
		return nil, fmt.Errorf("token: manifest upload failed (fail-closed): %w", err)
	}
	claims.Targets = manifestRefJSON{
		HashAlg:        "sha256",
		ManifestURI:    s.cfg.uriPrefix + objectKey,
		ManifestSHA256: sha,
	}
	if !m.scopeBound {
		claims.Targets.Count = uint32(len(m.targets))
	}

	raw, err := signJWT(s.key.KID, s.key.Private(), claims)
	if err != nil {
		return nil, err
	}
	if err := s.register(ctx, claims, m.decisionID); err != nil {
		return nil, err
	}
	s.auditMint(ctx, claims)
	return &gatekeeperv1.MintTokenResponse{Token: raw, Claims: claimsToProto(claims)}, nil
}

// register inserts the issued-token registry row (DB CHECK constraints
// re-enforce TTL and the Ruling A scope-bound restriction).
func (s *Service) register(ctx context.Context, c *claimsJSON, decisionID string) error {
	capsJSON, _ := json.Marshal(c.Capabilities)
	var rcJSON any
	if c.RateCaps != nil {
		raw, _ := json.Marshal(c.RateCaps)
		rcJSON = string(raw)
	} else {
		rcJSON = "{}"
	}
	var targetCount *int
	if !c.ScopeBound {
		n := int(c.Targets.Count)
		targetCount = &n
	}
	var approvalID *string
	if c.ApprovalID != "" {
		approvalID = &c.ApprovalID
	}
	_, err := s.db.Pool.Exec(ctx, `
		INSERT INTO issued_tokens
		  (jti, sub, task_id, roe_id, roe_version, risk_class, capabilities, scope_bound,
		   manifest_uri, manifest_sha256, target_count, rate_caps, approval_id, decision_id,
		   kid, not_before, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,$9,$10,$11,$12::jsonb,$13,$14,$15,$16,$17)`,
		c.Jti, c.Sub, c.TaskID, c.RoeID, int(c.RoeVersion), c.RiskClass, string(capsJSON),
		c.ScopeBound, c.Targets.ManifestURI, c.Targets.ManifestSHA256, targetCount, rcJSON,
		approvalID, decisionID, s.key.KID,
		time.Unix(c.Nbf, 0).UTC(), time.Unix(c.Exp, 0).UTC())
	if err != nil {
		return fmt.Errorf("token: register: %w", err)
	}
	return nil
}

func (s *Service) auditMint(ctx context.Context, c *claimsJSON) {
	// Token mints are control-plane events chained best-effort (the mint
	// itself was already audit-gated at decision time, step 11).
	if _, err := s.aud.Record(ctx, audit.Input{
		Kind:    audit.KindTokenMinted,
		Actor:   map[string]any{"kind": "service", "id": c.Sub},
		Subject: map[string]any{"task_id": c.TaskID, "roe_id": c.RoeID},
		Payload: map[string]any{
			"jti":             c.Jti,
			"task_id":         c.TaskID,
			"roe_id":          c.RoeID,
			"roe_version":     c.RoeVersion,
			"risk_class":      c.RiskClass,
			"capabilities":    c.Capabilities,
			"scope_bound":     c.ScopeBound,
			"manifest_sha256": c.Targets.ManifestSHA256,
			"kid":             s.key.KID,
			"exp":             c.Exp,
		},
	}); err != nil {
		fmt.Printf("token: WARNING audit mint %s failed: %v\n", c.Jti, err)
	}
}

// ExchangeToken implements Ruling C9: narrowed worker tokens. Fail-closed on
// any verification failure.
func (s *Service) ExchangeToken(ctx context.Context, req *gatekeeperv1.ExchangeTokenRequest) (*gatekeeperv1.ExchangeTokenResponse, error) {
	if req.GetParentToken() == "" || req.GetWorkerTaskId() == "" || req.GetWorkerSubject() == "" {
		return nil, errors.New("token: parent_token, worker_task_id and worker_subject are required")
	}
	parent, parentRow, err := s.verifyAndLoad(ctx, req.GetParentToken(), false)
	if err != nil {
		return nil, err
	}
	if len(req.GetNarrowedTargets()) == 0 {
		return nil, errors.New("token: narrowed_targets must be non-empty")
	}
	if parent.Claims.ScopeBound {
		// Narrowing a watch token: every narrowed target must be in-scope
		// under the embedded canonical scope.
		raw, err := fetchManifest(ctx, s.objects, s.cfg.manifestBucket,
			parent.Claims.Targets.ManifestURI, parent.Claims.Targets.ManifestSHA256)
		if err != nil {
			return nil, err
		}
		var sm ScopeManifest
		if err := json.Unmarshal(raw, &sm); err != nil {
			return nil, fmt.Errorf("token: parent scope manifest: %w", err)
		}
		includes := append(append(append([]string{}, sm.Scope.Domains...), sm.Scope.CIDRs...), sm.Scope.AssetGroupIds...)
		for _, t := range req.GetNarrowedTargets() {
			inScope, excluded := scopecanon.Evaluate(includes, sm.Scope.ExplicitExcludes, t)
			if excluded || !inScope {
				return nil, fmt.Errorf("token: narrowed target %q outside parent scope (fail-closed)", t)
			}
		}
	} else {
		raw, err := fetchManifest(ctx, s.objects, s.cfg.manifestBucket,
			parent.Claims.Targets.ManifestURI, parent.Claims.Targets.ManifestSHA256)
		if err != nil {
			return nil, err
		}
		var em ExactManifest
		if err := json.Unmarshal(raw, &em); err != nil {
			return nil, fmt.Errorf("token: parent manifest: %w", err)
		}
		for _, t := range req.GetNarrowedTargets() {
			if !inTargetSet(em.Targets, t) {
				return nil, fmt.Errorf("token: narrowed target %q not in parent manifest (fail-closed)", t)
			}
		}
	}
	roeRec, err := s.roes.LoadROE(ctx, parent.Claims.RoeID, 0)
	if err != nil {
		return nil, fmt.Errorf("token: RoE re-check failed (fail-closed): %w", err)
	}
	if roeRec.GetStatus() != gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE {
		return nil, fmt.Errorf("token: RoE %s is %s — exchange denied", roeRec.GetRoeId(), roeRec.GetStatus())
	}
	risk, err := capreg.ParseRiskClass(parent.Claims.RiskClass)
	if err != nil {
		return nil, err
	}
	approvalID, err := s.resolveApproval(ctx, roeRec, risk, parent.Claims.Capabilities[0], req.GetNarrowedTargets())
	if err != nil {
		return nil, err
	}
	m := &mintSpec{
		sub: req.GetWorkerSubject(), taskID: req.GetWorkerTaskId(), roe: roeRec,
		risk: parent.Claims.RiskClass, capabilities: parent.Claims.Capabilities,
		approvalID: approvalID, rateCaps: parent.Claims.RateCaps,
		targets: req.GetNarrowedTargets(), decisionID: parentRow.decisionID,
	}
	// Successor may not outlive its parent (doc 06's non-renewable spirit).
	resp, err := s.mint(ctx, m, parent.Claims.Exp)
	if err != nil {
		return nil, err
	}
	return &gatekeeperv1.ExchangeTokenResponse{Token: resp.GetToken(), Claims: resp.GetClaims()}, nil
}

// RefreshToken is mid-run re-authorization: re-runs policy, then mints a
// successor for the same task (doc 11 §3.2). Denial → empty token; the agent
// halts when its current token expires.
func (s *Service) RefreshToken(ctx context.Context, req *gatekeeperv1.RefreshTokenRequest) (*gatekeeperv1.RefreshTokenResponse, error) {
	if req.GetCurrentToken() == "" {
		return nil, errors.New("token: current_token is required")
	}
	if s.authorizer == nil {
		return nil, errors.New("token: policy re-check unavailable (fail-closed)")
	}
	// Allow refresh of tokens expired within one TTL (agents racing the clock);
	// anything older is dead.
	cur, _, err := s.verifyAndLoad(ctx, req.GetCurrentToken(), true)
	if err != nil {
		return nil, err
	}
	if s.now().After(time.Unix(cur.Claims.Exp, 0).Add(config.MaxTokenTTL)) {
		return nil, errors.New("token: token expired beyond the refresh grace window")
	}
	targets, err := s.manifestTargets(ctx, cur.Claims)
	if err != nil {
		return nil, err
	}
	authzReq := &gatekeeperv1.AuthorizeRequest{Request: &gatekeeperv1.AuthorizationRequest{
		RequestId:   ids.New("req"),
		Principal:   &gatekeeperv1.Principal{Kind: "service", Id: cur.Claims.Sub},
		Task:        &gatekeeperv1.TaskContext{TaskId: cur.Claims.TaskID},
		Capability:  cur.Claims.Capabilities[0],
		Targets:     targets,
		RoeId:       cur.Claims.RoeID,
		RoeVersion:  cur.Claims.RoeVersion,
		RequestedAt: timestamppb.New(s.now().UTC()),
	}}
	resp, err := s.authorizer.Authorize(ctx, authzReq)
	if err != nil {
		return nil, fmt.Errorf("token: re-authorization failed (fail-closed): %w", err)
	}
	if resp.GetDecision().GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
		return &gatekeeperv1.RefreshTokenResponse{}, nil
	}
	roeRec, err := s.roes.LoadROE(ctx, cur.Claims.RoeID, 0)
	if err != nil {
		return nil, fmt.Errorf("token: RoE re-check failed (fail-closed): %w", err)
	}
	m := &mintSpec{
		sub: cur.Claims.Sub, taskID: cur.Claims.TaskID, roe: roeRec,
		risk: cur.Claims.RiskClass, capabilities: cur.Claims.Capabilities,
		approvalID: cur.Claims.ApprovalID, rateCaps: cur.Claims.RateCaps,
		scopeBound: cur.Claims.ScopeBound, decisionID: resp.GetDecision().GetDecisionId(),
	}
	if !cur.Claims.ScopeBound {
		m.targets = targets
	}
	out, err := s.mint(ctx, m, 0)
	if err != nil {
		return nil, err
	}
	return &gatekeeperv1.RefreshTokenResponse{Token: out.GetToken(), Claims: out.GetClaims()}, nil
}

// RevokeToken revokes by jti and broadcasts on tasks.revocations.v1.
func (s *Service) RevokeToken(ctx context.Context, req *gatekeeperv1.RevokeTokenRequest) (*gatekeeperv1.RevokeTokenResponse, error) {
	if req.GetJti() == "" {
		return nil, errors.New("token: jti is required")
	}
	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE issued_tokens SET revoked_at = now() WHERE jti = $1 AND revoked_at IS NULL`, req.GetJti())
	if err != nil {
		return nil, fmt.Errorf("token: revoke: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return &gatekeeperv1.RevokeTokenResponse{Revoked: false}, nil
	}
	if s.revokes != nil {
		if _, err := s.revokes.Issue(ctx, "token", req.GetJti(), "gatekeeper.token-service", req.GetReason(), time.Time{}); err != nil {
			fmt.Printf("token: WARNING revocation broadcast %s failed: %v\n", req.GetJti(), err)
		}
	}
	if _, err := s.aud.Record(ctx, audit.Input{
		Kind:    audit.KindTokenRevoked,
		Actor:   map[string]any{"kind": "service", "id": "gatekeeper.token-service"},
		Payload: map[string]any{"jti": req.GetJti(), "reason": req.GetReason()},
	}); err != nil {
		fmt.Printf("token: WARNING audit revoke %s failed: %v\n", req.GetJti(), err)
	}
	return &gatekeeperv1.RevokeTokenResponse{Revoked: true}, nil
}

// GetJWKS returns the active verification keys.
func (s *Service) GetJWKS(ctx context.Context, req *gatekeeperv1.GetJWKSRequest) (*gatekeeperv1.GetJWKSResponse, error) {
	jwk := s.key.JWK()
	if req.GetKid() != "" && req.GetKid() != jwk["kid"] {
		return &gatekeeperv1.GetJWKSResponse{}, nil
	}
	return &gatekeeperv1.GetJWKSResponse{Keys: []*gatekeeperv1.JsonWebKey{{
		Kty: jwk["kty"], Crv: jwk["crv"], Kid: jwk["kid"],
		Alg: jwk["alg"], Use: jwk["use"], X: jwk["x"],
	}}}, nil
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type issuedRow struct {
	decisionID string
}

// verifyAndLoad cryptographically verifies a token and confirms it is
// registered and unrevoked (revoked-token use is an anomaly vector, doc 11 §7).
func (s *Service) verifyAndLoad(ctx context.Context, raw string, allowExpired bool) (*ParsedToken, *issuedRow, error) {
	pt, err := s.Verify(raw, allowExpired)
	if err != nil {
		return nil, nil, err
	}
	var row issuedRow
	var revokedAt *time.Time
	err = s.db.Pool.QueryRow(ctx,
		`SELECT decision_id, revoked_at FROM issued_tokens WHERE jti = $1`, pt.Claims.Jti).
		Scan(&row.decisionID, &revokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil, fmt.Errorf("token: %s is not in the issued-token registry", pt.Claims.Jti)
		}
		return nil, nil, fmt.Errorf("token: registry lookup: %w", err)
	}
	if revokedAt != nil {
		return nil, nil, fmt.Errorf("token: %s was revoked at %s", pt.Claims.Jti, revokedAt.UTC().Format(time.RFC3339))
	}
	return pt, &row, nil
}

// Verify cryptographically verifies a token against the service key
// (iss/aud/exp/nbf, 60 s leeway, 120 s skew bound).
func (s *Service) Verify(raw string, allowExpired bool) (*ParsedToken, error) {
	return Verify(raw, s.Resolver(), VerifyOptions{
		Issuer: s.cfg.issuer, Audience: s.cfg.audience, Now: s.now(),
		RequireExp: true, AllowExpired: allowExpired,
	})
}

// Resolver resolves kids to public keys (single active key at MVP-A).
func (s *Service) Resolver() KeyResolver {
	pub := s.key.Public()
	kid := s.key.KID
	return func(k string) (ed25519.PublicKey, error) {
		if k != kid {
			return nil, fmt.Errorf("unknown kid %q", k)
		}
		return pub, nil
	}
}

// manifestTargets resolves the authorized target set from a token's manifest
// (exact form only; scope-bound refresh re-derives targets from the request).
func (s *Service) manifestTargets(ctx context.Context, c *claimsJSON) ([]string, error) {
	if c.ScopeBound {
		// Watch-token refresh re-authorizes at capability level; targets are
		// re-evaluated per probe against the embedded scope by the SDK. The
		// policy re-check uses the canonical scope string as the target value
		// (doc 03 §4.3's audit form).
		return []string{"scope:sha256:" + c.Targets.ManifestSHA256}, nil
	}
	raw, err := fetchManifest(ctx, s.objects, s.cfg.manifestBucket, c.Targets.ManifestURI, c.Targets.ManifestSHA256)
	if err != nil {
		return nil, err
	}
	var em ExactManifest
	if err := json.Unmarshal(raw, &em); err != nil {
		return nil, fmt.Errorf("token: manifest parse: %w", err)
	}
	return em.Targets, nil
}

// claimsToProto renders claims as the proto ScopeTokenClaims for RPC replies.
func claimsToProto(c *claimsJSON) *gatekeeperv1.ScopeTokenClaims {
	rc, _ := capreg.ParseRiskClass(c.RiskClass)
	out := &gatekeeperv1.ScopeTokenClaims{
		Iss: c.Iss, Aud: c.Aud, Jti: c.Jti, Sub: c.Sub, TaskId: c.TaskID,
		RoeId: c.RoeID, RoeVersion: c.RoeVersion, RiskClass: rc,
		Capabilities: c.Capabilities,
		Targets: &gatekeeperv1.TargetManifestRef{
			HashAlg:        c.Targets.HashAlg,
			ManifestUri:    c.Targets.ManifestURI,
			ManifestSha256: c.Targets.ManifestSHA256,
			Count:          c.Targets.Count,
		},
		ScopeBound: c.ScopeBound,
		ApprovalId: c.ApprovalID,
		Iat:        c.Iat, Nbf: c.Nbf, Exp: c.Exp,
	}
	if c.RateCaps != nil {
		out.RateCaps = &gatekeeperv1.TokenRateCaps{
			MaxRps:        c.RateCaps.MaxRPS,
			MaxConcurrent: c.RateCaps.MaxConcurrent,
		}
	}
	return out
}

// sameTargetSet compares two target sets order-insensitively on canonical forms.
func sameTargetSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	set := map[string]int{}
	for _, t := range a {
		ct, _ := scopecanon.Canonical(t)
		set[ct]++
	}
	for _, t := range b {
		ct, _ := scopecanon.Canonical(t)
		set[ct]--
		if set[ct] < 0 {
			return false
		}
	}
	return true
}

func inTargetSet(set []string, target string) bool {
	ct, _ := scopecanon.Canonical(target)
	for _, t := range set {
		tt, _ := scopecanon.Canonical(t)
		if tt == ct {
			return true
		}
	}
	return false
}

func orEmpty(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// ensure roe import is referenced (ROEReader is satisfied by roe.Service).
var _ ROEReader = (*roe.Service)(nil)
