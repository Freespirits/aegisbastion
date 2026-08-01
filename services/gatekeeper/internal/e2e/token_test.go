package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/rbac"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/token"
)

// mintR2 is a helper: R2 RoE + allow decision + mint.
func mintR2(t *testing.T, e *env, targets []string) (*gatekeeperv1.MintTokenResponse, *gatekeeperv1.RulesOfEngagement, string) {
	t.Helper()
	a := e.seedActors(t, orgID(t))
	r := e.createROE(t, a, roeParams{
		maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
		domains: []string{"acme.com", "*.acme.com"}, cidrs: []string{"203.0.113.0/24"},
	})
	taskID := ids.New("task")
	dec := e.authorize(t, a, taskID, "detect.scan", targets, r.GetRoeId(), nil)
	if dec.GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
		t.Fatalf("expected allow, got %v", dec.GetReasons())
	}
	resp, err := e.token.MintToken(context.Background(), &gatekeeperv1.MintTokenRequest{
		DecisionId: dec.GetDecisionId(), TaskId: taskID, Subject: "agent_" + ids.New("w"),
		Targets: targets,
	})
	if err != nil {
		t.Fatalf("MintToken: %v", err)
	}
	return resp, r, taskID
}

// TestTokenMintVerifyJWKS exercises the full mint → JWKS → local-verify
// round trip (the Phase-0 watch-token exit gate path).
func TestTokenMintVerifyJWKS(t *testing.T) {
	e := newEnv(t)
	targets := []string{"https://shop.acme.com", "203.0.113.10"}
	resp, r, taskID := mintR2(t, e, targets)

	claims := resp.GetClaims()
	if claims.GetAud() != "aegisbastion.modules" || claims.GetIss() != "gatekeeper.platform" {
		t.Fatalf("bad iss/aud: %s %s", claims.GetIss(), claims.GetAud())
	}
	if claims.GetExp()-claims.GetIat() > 900 {
		t.Fatalf("TTL %ds exceeds the Ruling C5 cap", claims.GetExp()-claims.GetIat())
	}
	if claims.GetTaskId() != taskID || !strings.HasPrefix(claims.GetJti(), "tok_") {
		t.Fatalf("bad binding: task=%s jti=%s", claims.GetTaskId(), claims.GetJti())
	}
	if claims.GetRoeId() != r.GetRoeId() || claims.GetRoeVersion() != r.GetVersion() {
		t.Fatal("RoE binding mismatch")
	}
	if claims.GetScopeBound() {
		t.Fatal("R2 token must be exact-enumerated, not scope-bound")
	}
	if claims.GetTargets().GetCount() != 2 || claims.GetTargets().GetManifestSha256() == "" {
		t.Fatalf("bad manifest ref: %+v", claims.GetTargets())
	}

	// JWKS round trip: a consumer fetches the JWKS and verifies locally.
	jwks, err := e.token.GetJWKS(context.Background(), &gatekeeperv1.GetJWKSRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(jwks.GetKeys()) != 1 {
		t.Fatalf("expected 1 active key, got %d", len(jwks.GetKeys()))
	}
	jwk := jwks.GetKeys()[0]
	if jwk.GetKty() != "OKP" || jwk.GetCrv() != "Ed25519" || jwk.GetAlg() != "EdDSA" || jwk.GetUse() != "sig" {
		t.Fatalf("bad JWK: %+v", jwk)
	}
	pubRaw, err := base64.RawURLEncoding.DecodeString(jwk.GetX())
	if err != nil {
		t.Fatal(err)
	}
	pub := ed25519.PublicKey(pubRaw)
	resolver := func(kid string) (ed25519.PublicKey, error) {
		if kid != jwk.GetKid() {
			return nil, errStringE2E("unknown kid")
		}
		return pub, nil
	}
	pt, err := token.Verify(resp.GetToken(), resolver, token.VerifyOptions{
		Issuer: "gatekeeper.platform", Audience: "aegisbastion.modules", RequireExp: true,
	})
	if err != nil {
		t.Fatalf("JWKS-based local verification failed: %v", err)
	}
	if pt.Claims.Jti != claims.GetJti() {
		t.Fatal("verified claims mismatch")
	}

	// The manifest is retrievable from MinIO and its hash matches the claim.
	raw, err := e.objects.Get(context.Background(), "token-manifests", "tokens/"+claims.GetJti()+"/targets.json")
	if err != nil {
		t.Fatalf("manifest fetch: %v", err)
	}
	var man struct {
		Jti     string   `json:"jti"`
		TaskID  string   `json:"task_id"`
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatal(err)
	}
	if man.TaskID != taskID || len(man.Targets) != 2 {
		t.Fatalf("bad manifest: %s", raw)
	}
	sum := sha256Hex(raw)
	if sum != claims.GetTargets().GetManifestSha256() {
		t.Fatalf("manifest hash mismatch: %s != %s", sum, claims.GetTargets().GetManifestSha256())
	}

	// Task-bound: mint for a DIFFERENT task against the same decision fails.
	if _, err := e.token.MintToken(context.Background(), &gatekeeperv1.MintTokenRequest{
		DecisionId: claims.GetJti(), TaskId: ids.New("task"), Subject: "agent_x", Targets: targets,
	}); err == nil {
		t.Fatal("mint against a jti-as-decision must fail")
	}
}

type errStringE2E string

func (e errStringE2E) Error() string { return string(e) }

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestScopeBoundWatchToken covers the Ruling A extension: mint is restricted
// to R1 monitor.watch/monitor.rescan, and the manifest IS the canonical scope.
func TestScopeBoundWatchToken(t *testing.T) {
	e := newEnv(t)
	a := e.seedActors(t, orgID(t))
	r := e.createROE(t, a, roeParams{
		maxRisk: platformv1.RiskClass_RISK_CLASS_R1, capabilities: []string{"monitor.watch"},
		domains: []string{"acme.com", "*.acme.com"}, cidrs: []string{"203.0.113.0/24"},
		excludes: []string{"legacy.acme.com"},
	})
	taskID := ids.New("task")
	// Watch authorize: the standing task is capability-level; the SDK
	// evaluates each probe target against the embedded scope (Ruling A).
	dec := e.authorize(t, a, taskID, "monitor.watch", []string{"acme.com"}, r.GetRoeId(), nil)
	if dec.GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
		t.Fatalf("watch authorize failed: %v", dec.GetReasons())
	}
	resp, err := e.token.MintToken(context.Background(), &gatekeeperv1.MintTokenRequest{
		DecisionId: dec.GetDecisionId(), TaskId: taskID, Subject: "agent_" + ids.New("mon"),
		ScopeBound: true,
	})
	if err != nil {
		t.Fatalf("scope-bound mint: %v", err)
	}
	claims := resp.GetClaims()
	if !claims.GetScopeBound() || claims.GetRiskClass() != platformv1.RiskClass_RISK_CLASS_R1 {
		t.Fatalf("bad scope-bound claims: %+v", claims)
	}
	if claims.GetExp()-claims.GetIat() > 900 {
		t.Fatal("scope-bound TTL must stay 15 min (Ruling A.2)")
	}
	// Manifest = canonical scope document; hash IS the scope:sha256 audit value.
	raw, err := e.objects.Get(context.Background(), "token-manifests", "tokens/"+claims.GetJti()+"/scope.json")
	if err != nil {
		t.Fatalf("scope manifest fetch: %v", err)
	}
	if sha256Hex(raw) != claims.GetTargets().GetManifestSha256() {
		t.Fatal("scope manifest hash mismatch — audit value broken")
	}
	var sm map[string]any
	if err := json.Unmarshal(raw, &sm); err != nil {
		t.Fatal(err)
	}
	if sm["roe_id"] != r.GetRoeId() {
		t.Fatalf("scope manifest missing roe binding: %s", raw)
	}
	scope, _ := sm["scope"].(map[string]any)
	if scope == nil || scope["explicit_excludes"] == nil || scope["domains"] == nil {
		t.Fatalf("scope manifest missing canonical scope: %s", raw)
	}

	// Ruling A.1: scope_bound for an R2 capability is rejected by the mint
	// (and independently by the issued_tokens DB CHECK constraint).
	r2targets := []string{"203.0.113.10"}
	a2 := e.seedActors(t, orgID(t))
	r2 := e.createROE(t, a2, roeParams{
		maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
		cidrs: []string{"203.0.113.0/24"},
	})
	task2 := ids.New("task")
	dec2 := e.authorize(t, a2, task2, "detect.scan", r2targets, r2.GetRoeId(), nil)
	if dec2.GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
		t.Fatalf("R2 authorize failed: %v", dec2.GetReasons())
	}
	if _, err := e.token.MintToken(context.Background(), &gatekeeperv1.MintTokenRequest{
		DecisionId: dec2.GetDecisionId(), TaskId: task2, Subject: "agent_x", ScopeBound: true,
	}); err == nil {
		t.Fatal("scope_bound token for R2 capability must be rejected (Ruling A)")
	}
}

// TestTokenRefreshRevokeExchange covers mid-run re-authorization, revocation
// propagation and Ruling C9 exchange.
func TestTokenRefreshRevokeExchange(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()

	// Refresh requires the subject to hold task:execute — the SDK refreshes
	// as the module's service account, so mint with a module-svc subject.
	a := e.seedActors(t, orgID(t))
	if _, err := e.rbac.Grant(ctx, rbacBinding(a.org, "svc-detect-"+a.org, "service", "module-svc")); err != nil {
		t.Fatal(err)
	}
	r := e.createROE(t, a, roeParams{
		maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
		cidrs: []string{"203.0.113.0/24"},
	})
	targets := []string{"203.0.113.10", "203.0.113.11"}
	taskID := ids.New("task")
	dec := e.authorize(t, a, taskID, "detect.scan", targets, r.GetRoeId(), nil)
	if dec.GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
		t.Fatalf("allow expected: %v", dec.GetReasons())
	}
	mint, err := e.token.MintToken(ctx, &gatekeeperv1.MintTokenRequest{
		DecisionId: dec.GetDecisionId(), TaskId: taskID, Subject: "svc-detect-" + a.org, Targets: targets,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Refresh: policy re-check passes → successor token, same task, new jti.
	ref, err := e.token.RefreshToken(ctx, &gatekeeperv1.RefreshTokenRequest{CurrentToken: mint.GetToken()})
	if err != nil {
		t.Fatalf("RefreshToken: %v", err)
	}
	if ref.GetToken() == "" || ref.GetClaims().GetJti() == mint.GetClaims().GetJti() {
		t.Fatal("refresh must mint a successor token")
	}
	if ref.GetClaims().GetTaskId() != taskID {
		t.Fatal("successor must stay task-bound")
	}

	// Exchange (Ruling C9): narrowed worker token.
	x, err := e.token.ExchangeToken(ctx, &gatekeeperv1.ExchangeTokenRequest{
		ParentToken: mint.GetToken(), NarrowedTargets: []string{"203.0.113.10"},
		WorkerTaskId: ids.New("job"), WorkerSubject: "agent_worker_" + ids.New("x"),
	})
	if err != nil {
		t.Fatalf("ExchangeToken: %v", err)
	}
	if x.GetClaims().GetTargets().GetCount() != 1 {
		t.Fatal("worker token must carry the narrowed set")
	}
	if x.GetClaims().GetExp() > mint.GetClaims().GetExp() {
		t.Fatal("worker token must not outlive its parent")
	}
	// Exchange outside the manifest fails closed.
	if _, err := e.token.ExchangeToken(ctx, &gatekeeperv1.ExchangeTokenRequest{
		ParentToken: mint.GetToken(), NarrowedTargets: []string{"203.0.113.99"},
		WorkerTaskId: ids.New("job"), WorkerSubject: "agent_worker",
	}); err == nil {
		t.Fatal("exchange outside parent manifest must fail")
	}

	// Revoke: the token dies for refresh AND a revocation hits the bus.
	revSub, err := e.bus.NC.SubscribeSync("tasks.revocations.v1")
	if err != nil {
		t.Fatal(err)
	}
	defer revSub.Unsubscribe()
	revResp, err := e.token.RevokeToken(ctx, &gatekeeperv1.RevokeTokenRequest{
		Jti: mint.GetClaims().GetJti(), Reason: "e2e revoked token",
	})
	if err != nil || !revResp.GetRevoked() {
		t.Fatalf("RevokeToken: %v %+v", err, revResp)
	}
	if _, err := revSub.NextMsg(5 * time.Second); err != nil {
		t.Fatalf("no revocation broadcast: %v", err)
	}
	if _, err := e.token.RefreshToken(ctx, &gatekeeperv1.RefreshTokenRequest{CurrentToken: mint.GetToken()}); err == nil {
		t.Fatal("revoked token must not refresh")
	}
}

// TestRefreshDeniedAfterROERevoke proves mid-run re-authorization bites:
// RoE revoked → refresh returns NO successor (agent halts at expiry).
func TestRefreshDeniedAfterROERevoke(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.seedActors(t, orgID(t))
	if _, err := e.rbac.Grant(ctx, rbacBinding(a.org, "svc-detect-"+a.org, "service", "module-svc")); err != nil {
		t.Fatal(err)
	}
	r := e.createROE(t, a, roeParams{
		maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
		cidrs: []string{"203.0.113.0/24"},
	})
	taskID := ids.New("task")
	dec := e.authorize(t, a, taskID, "detect.scan", []string{"203.0.113.10"}, r.GetRoeId(), nil)
	mint, err := e.token.MintToken(ctx, &gatekeeperv1.MintTokenRequest{
		DecisionId: dec.GetDecisionId(), TaskId: taskID, Subject: "svc-detect-" + a.org,
		Targets: []string{"203.0.113.10"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.roe.RevokeROE(ctx, &gatekeeperv1.RevokeROERequest{
		RoeId: r.GetRoeId(), Reason: "e2e mid-run revoke",
	}); err != nil {
		t.Fatal(err)
	}
	ref, err := e.token.RefreshToken(ctx, &gatekeeperv1.RefreshTokenRequest{CurrentToken: mint.GetToken()})
	if err != nil {
		t.Fatal(err)
	}
	if ref.GetToken() != "" {
		t.Fatal("re-authorization after RoE revoke must return no successor token")
	}
}

func rbacBinding(org, principal, kind, role string) rbac.Binding {
	return rbac.Binding{OrgID: org, Principal: principal, PrincipalKind: kind, Role: role, GrantedBy: "platform-admin"}
}

// TestTokenRejectsUnknownDecision proves the doc 11 §2.2 invariant: no token
// without a DecisionEvent grant.
func TestTokenRejectsUnknownDecision(t *testing.T) {
	e := newEnv(t)
	_, err := e.token.MintToken(context.Background(), &gatekeeperv1.MintTokenRequest{
		DecisionId: "dec_nonexistent", TaskId: ids.New("task"), Subject: "agent_x",
		Targets: []string{"a.acme.com"},
	})
	if err == nil {
		t.Fatal("mint without a decision grant must fail")
	}
}
