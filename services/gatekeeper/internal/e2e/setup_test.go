// Package e2e contains gatekeeper integration tests. They run against a real
// Postgres + NATS + MinIO (deploy/docker-compose.yml infra profile) and skip
// when the infra is unreachable, so plain `go test ./...` stays green on a
// bare machine.
package e2e

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/approval"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/capreg"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/config"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/keys"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/policy"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ratelimit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/rbac"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/revocation"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/roe"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/token"
)

const (
	testDSN   = "postgres://aegisbastion:aegisbastion-dev@localhost:5432/aegisbastion?sslmode=disable"
	testNATS  = "nats://localhost:4222"
	testS3EP  = "localhost:9000"
	testS3Key = "aegisbastion"
	testS3Sec = "aegisbastion-dev-secret"
)

// env bundles the wired services for the tests.
type env struct {
	db       *store.DB
	bus      *bus.Bus
	objects  *token.S3Store
	key      *keys.Keypair
	cfg      *config.Config
	audit    *audit.Service
	rbac     *rbac.Service
	revoke   *revocation.Service
	roe      *roe.Service
	approval *approval.Service
	policy   *policy.Service
	token    *token.Service
	registry *capreg.Registry
}

func newEnv(t *testing.T) *env {
	t.Helper()
	if os.Getenv("GATEKEEPER_E2E") == "0" {
		t.Skip("GATEKEEPER_E2E=0")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	db, err := store.Connect(ctx, envOr("GATEKEEPER_TEST_DSN", testDSN), "gatekeeper")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — start deploy infra profile", err)
	}
	t.Cleanup(db.Close)

	b, err := bus.Connect(ctx, envOr("GATEKEEPER_TEST_NATS", testNATS))
	if err != nil {
		t.Skipf("NATS unavailable (%v) — start deploy infra profile", err)
	}
	t.Cleanup(b.Close)

	objects, err := token.NewS3Store(envOr("GATEKEEPER_TEST_S3", testS3EP), testS3Key, testS3Sec, false)
	if err != nil {
		t.Skipf("minio client: %v", err)
	}
	if err := objects.EnsureBucket(ctx, "token-manifests"); err != nil {
		t.Skipf("minio unavailable (%v) — start deploy infra profile", err)
	}

	key, err := keys.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		TokenIssuer:       "gatekeeper.platform",
		TokenAudience:     "aegisbastion.modules",
		TokenTTL:          15 * time.Minute,
		ManifestBucket:    "token-manifests",
		ManifestURIPrefix: "blob://",
	}
	auditSvc := audit.New(db)
	rbacSvc := rbac.New(db)
	revSvc := revocation.New(db, rbacSvc, auditSvc, b)
	roeSvc := roe.New(db, key, rbacSvc, auditSvc, b, revSvc)
	apprSvc := approval.New(db, rbacSvc, auditSvc, b, roeSvc)
	registry := capreg.Default()
	polSvc := policy.New(db, roeSvc, apprSvc, revSvc, rbacSvc, registry, ratelimit.New(), auditSvc, b, nil)
	tokSvc := token.New(db, key, objects, roeSvc, apprSvc, revSvc, auditSvc, cfg)
	tokSvc.SetAuthorizer(polSvc)

	e := &env{
		db: db, bus: b, objects: objects, key: key, cfg: cfg,
		audit: auditSvc, rbac: rbacSvc, revoke: revSvc, roe: roeSvc,
		approval: apprSvc, policy: polSvc, token: tokSvc, registry: registry,
	}
	// Test hygiene: revocations are global and the contract has no lift RPC,
	// so reruns would otherwise see stale kills. The tests own a scratch DB.
	if _, err := db.Pool.Exec(context.Background(),
		`UPDATE revocations SET lifted_at = now() WHERE lifted_at IS NULL`); err != nil {
		t.Fatal(err)
	}
	return e
}

func envOr(k, fb string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fb
}

// actors are per-test identities (unique per test via the org id).
type actors struct {
	org       string
	author    string
	grc       string
	operator  string
	commander string
	approver1 string
	approver2 string
	requester string
}

// seedActors creates an org + RBAC grants for the standard cast.
func (e *env) seedActors(t *testing.T, org string) *actors {
	t.Helper()
	a := &actors{
		org:       org,
		author:    "user_author@" + org,
		grc:       "user_grc@" + org,
		operator:  "user_ops@" + org,
		commander: "svc-hexstrike-commander",
		approver1: "user_appr1@" + org,
		approver2: "user_appr2@" + org,
		requester: "user_req@" + org,
	}
	grants := []rbac.Binding{
		{OrgID: org, Principal: a.author, PrincipalKind: "human", Role: rbac.RoleROEAuthor, GrantedBy: "platform-admin"},
		{OrgID: org, Principal: a.grc, PrincipalKind: "human", Role: rbac.RoleGRCVerifier, GrantedBy: "platform-admin"},
		{OrgID: org, Principal: a.operator, PrincipalKind: "human", Role: rbac.RoleOperator, GrantedBy: "platform-admin"},
		{OrgID: org, Principal: a.approver1, PrincipalKind: "human", Role: rbac.RoleOffensiveApprover, GrantedBy: "platform-admin"},
		{OrgID: org, Principal: a.approver2, PrincipalKind: "human", Role: rbac.RoleOffensiveApprover, GrantedBy: "platform-admin"},
		{OrgID: org, Principal: a.commander, PrincipalKind: "service", Role: rbac.RoleCommanderSvc, GrantedBy: "platform-admin"},
	}
	for _, g := range grants {
		if _, err := e.rbac.Grant(context.Background(), g); err != nil {
			t.Fatalf("grant %s→%s: %v", g.Role, g.Principal, err)
		}
	}
	return a
}

// roeParams describes a test RoE.
type roeParams struct {
	maxRisk       platformv1.RiskClass
	capabilities  []string
	domains       []string
	cidrs         []string
	excludes      []string
	rateCaps      map[string]*gatekeeperv1.RateCapEntry
	jurisdictions []string
	dataClasses   []string
	approvalFor   []string
	azureID       string
	blackout      []*gatekeeperv1.BlackoutWindow
	validFrom     time.Time
	validUntil    time.Time
	withLegal     bool
}

// createROE drafts + activates an RoE and returns it.
func (e *env) createROE(t *testing.T, a *actors, p roeParams) *gatekeeperv1.RulesOfEngagement {
	t.Helper()
	if p.validFrom.IsZero() {
		p.validFrom = time.Now().Add(-time.Hour)
	}
	if p.validUntil.IsZero() {
		p.validUntil = time.Now().Add(24 * time.Hour)
	}
	r := &gatekeeperv1.RulesOfEngagement{
		OrgId:     a.org,
		Name:      "e2e engagement " + a.org,
		CreatedBy: a.author,
		AuthorizedBy: &gatekeeperv1.Attestation{
			Identity: "ciso@" + a.org, Role: "customer_authorizer", At: timestamppb.Now(),
		},
		Scope: &gatekeeperv1.Scope{
			Domains:          p.domains,
			Cidrs:            p.cidrs,
			ExplicitExcludes: p.excludes,
		},
		Constraints: &gatekeeperv1.Constraints{
			MaxRiskClass:               p.maxRisk,
			AllowedCapabilities:        p.capabilities,
			RateCaps:                   p.rateCaps,
			BlackoutWindows:            p.blackout,
			JurisdictionsAllowed:       p.jurisdictions,
			DataClasses:                p.dataClasses,
			RequiresApprovalFor:        p.approvalFor,
			AzurePentestNotificationId: p.azureID,
		},
		ValidFrom:  timestamppb.New(p.validFrom),
		ValidUntil: timestamppb.New(p.validUntil),
	}
	if p.withLegal || p.maxRisk == platformv1.RiskClass_RISK_CLASS_R2 || p.maxRisk == platformv1.RiskClass_RISK_CLASS_R3 {
		r.LegalArtifact = &gatekeeperv1.LegalArtifact{
			Kind:           "signed_loa",
			DocumentSha256: "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
			StorageUri:     "blob://legal-artifacts/" + a.org + "/loa.pdf",
			Signers:        []string{"ciso@" + a.org},
			VerifiedBy:     a.grc,
			VerifiedAt:     timestamppb.Now(),
		}
		r.ApprovedByOperator = &gatekeeperv1.Attestation{
			Identity: a.operator, Role: "operator", At: timestamppb.Now(),
		}
	}
	ctx := context.Background()
	resp, err := e.roe.CreateROE(ctx, &gatekeeperv1.CreateROERequest{Roe: r})
	if err != nil {
		t.Fatalf("CreateROE: %v", err)
	}
	act, err := e.roe.ActivateROE(ctx, &gatekeeperv1.ActivateROERequest{
		RoeId: resp.GetRoe().GetRoeId(), Version: resp.GetRoe().GetVersion(),
	})
	if err != nil {
		t.Fatalf("ActivateROE: %v", err)
	}
	return act.GetRoe()
}

// authorize calls the PDP with the standard commander identity.
func (e *env) authorize(t *testing.T, a *actors, taskID, capability string, targets []string, roeID string, evctx *gatekeeperv1.EvaluationContext) *gatekeeperv1.DecisionEvent {
	t.Helper()
	resp, err := e.policy.Authorize(context.Background(), &gatekeeperv1.AuthorizeRequest{Request: &gatekeeperv1.AuthorizationRequest{
		RequestId: ids.New("req"),
		Principal: &gatekeeperv1.Principal{
			Kind: "service", Id: a.commander, SpiffeId: "spiffe://platform/hexstrike",
		},
		Task:        &gatekeeperv1.TaskContext{TaskId: taskID, ParentPlanId: "plan_" + taskID, Commander: "hexstrike"},
		Capability:  capability,
		Targets:     targets,
		RoeId:       roeID,
		RequestedAt: timestamppb.Now(),
		Context:     evctx,
	}})
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	return resp.GetDecision()
}

// badPool returns a store whose operations always fail (dependency-failure
// tests). pgxpool creation is lazy, so no connection is attempted here.
func badPool(t *testing.T) *store.DB {
	t.Helper()
	cfg, err := pgxpool.ParseConfig("postgres://aegisbastion:aegisbastion-dev@127.0.0.1:1/aegisbastion?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &store.DB{Pool: pool}
}

// auditNewForTest builds an audit service on an alternate store.
func auditNewForTest(db *store.DB) *audit.Service { return audit.New(db) }

// policyNewForTest builds a policy service with a swapped audit dependency
// (dependency-failure tests) and a quiet publisher.
func policyNewForTest(e *env, aud *audit.Service) *policy.Service {
	return policy.New(e.db, e.roe, e.approval, e.revoke, e.rbac, e.registry,
		ratelimit.New(), aud, bus.NopPublisher{}, nil)
}
