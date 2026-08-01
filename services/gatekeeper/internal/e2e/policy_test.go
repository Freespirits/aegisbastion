package e2e

import (
	"context"
	"strconv"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
)

func orgID(t *testing.T) string { return ids.New("org") }

// TestPolicyAllowPath covers the full happy path: R2 RoE → allow → decision
// on the bus → token mint.
func TestPolicyAllowPath(t *testing.T) {
	e := newEnv(t)
	a := e.seedActors(t, orgID(t))
	r := e.createROE(t, a, roeParams{
		maxRisk:      platformv1.RiskClass_RISK_CLASS_R2,
		capabilities: []string{"detect.scan"},
		domains:      []string{"acme.com", "*.acme.com"},
		cidrs:        []string{"203.0.113.0/24"},
		excludes:     []string{"legacy.acme.com", "203.0.113.50"},
	})

	// Subscribe (core NATS sees live JetStream publishes) to prove the
	// DecisionEvent is emitted on authz.decisions.v1.
	sub, err := e.bus.NC.SubscribeSync(bus.SubjectDecisions)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Unsubscribe()

	dec := e.authorize(t, a, ids.New("task"), "detect.scan",
		[]string{"https://shop.acme.com", "203.0.113.10"}, r.GetRoeId(), nil)
	if dec.GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
		t.Fatalf("expected allow, got %v: %v", dec.GetDecision(), dec.GetReasons())
	}
	if dec.GetRiskClass() != platformv1.RiskClass_RISK_CLASS_R2 {
		t.Fatalf("risk class should be R2, got %v", dec.GetRiskClass())
	}
	if dec.GetRoeVersion() != r.GetVersion() {
		t.Fatalf("decision should pin RoE v%d, got v%d", r.GetVersion(), dec.GetRoeVersion())
	}

	msg, err := sub.NextMsg(5 * time.Second)
	if err != nil {
		t.Fatalf("no DecisionEvent on %s: %v", bus.SubjectDecisions, err)
	}
	var env platformv1.Envelope
	if err := proto.Unmarshal(msg.Data, &env); err != nil {
		t.Fatal(err)
	}
	var busDec gatekeeperv1.DecisionEvent
	if err := env.GetPayload().UnmarshalTo(&busDec); err != nil {
		t.Fatal(err)
	}
	if busDec.GetDecisionId() != dec.GetDecisionId() {
		t.Fatalf("bus decision %s != RPC decision %s", busDec.GetDecisionId(), dec.GetDecisionId())
	}
}

// TestPolicyDenyPaths runs the required denial matrix (doc 11 §3.3).
func TestPolicyDenyPaths(t *testing.T) {
	e := newEnv(t)

	expectDeny := func(t *testing.T, dec *gatekeeperv1.DecisionEvent, code gatekeeperv1.DenyReason, label string) {
		t.Helper()
		if dec.GetDecision() != gatekeeperv1.Decision_DECISION_DENY {
			t.Fatalf("%s: expected deny, got allow", label)
		}
		if len(dec.GetReasons()) == 0 || dec.GetReasons()[0].GetCode() != code {
			t.Fatalf("%s: expected %v, got %v", label, code, dec.GetReasons())
		}
	}

	t.Run("TargetNotInScope", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"}, excludes: []string{"legacy.acme.com"},
		})
		dec := e.authorize(t, a, ids.New("task"), "detect.scan", []string{"evil.org"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_TARGET_NOT_IN_SCOPE, "out of scope")
	})

	t.Run("TargetExcluded", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"}, excludes: []string{"legacy.acme.com"},
		})
		dec := e.authorize(t, a, ids.New("task"), "detect.scan", []string{"https://legacy.acme.com"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_TARGET_EXCLUDED, "exclusions always win")
	})

	t.Run("ExpiredROE", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains:   []string{"*.acme.com"},
			validFrom: time.Now().Add(-2 * time.Hour), validUntil: time.Now().Add(2 * time.Second),
		})
		time.Sleep(3 * time.Second) // let the window close
		dec := e.authorize(t, a, ids.New("task"), "detect.scan", []string{"a.acme.com"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_ROE_EXPIRED, "expired RoE")
	})

	t.Run("ROENotFound", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		dec := e.authorize(t, a, ids.New("task"), "detect.scan", []string{"a.acme.com"}, "roe_does_not_exist", nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_ROE_NOT_ACTIVE, "missing RoE")
	})

	t.Run("RevokedTarget", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		target := "198.51.100.77"
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			cidrs: []string{"198.51.100.0/24"},
		})
		if _, err := e.revoke.Revoke(context.Background(), &gatekeeperv1.RevokeRequest{
			Scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_TARGET,
			Key:   target, IssuedBy: a.operator, Reason: "e2e",
		}); err != nil {
			t.Fatal(err)
		}
		dec := e.authorize(t, a, ids.New("task"), "detect.scan", []string{target}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_REVOKED_TARGET, "revoked target")
	})

	t.Run("RevokedROE", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"},
		})
		if _, err := e.revoke.Revoke(context.Background(), &gatekeeperv1.RevokeRequest{
			Scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE,
			Key:   r.GetRoeId(), IssuedBy: a.operator, Reason: "e2e",
		}); err != nil {
			t.Fatal(err)
		}
		dec := e.authorize(t, a, ids.New("task"), "detect.scan", []string{"a.acme.com"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_REVOKED_ROE, "revoked RoE")
	})

	t.Run("RevokedCapability", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"stress.http_flood"},
			domains: []string{"*.acme.com"}, azureID: "az-pen-e2e",
		})
		if _, err := e.revoke.Revoke(context.Background(), &gatekeeperv1.RevokeRequest{
			Scope: gatekeeperv1.RevocationScope_REVOCATION_SCOPE_CAPABILITY,
			Key:   "stress.http_flood", IssuedBy: a.operator, Reason: "e2e",
		}); err != nil {
			t.Fatal(err)
		}
		dec := e.authorize(t, a, ids.New("task"), "stress.http_flood", []string{"a.acme.com"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_REVOKED_CAPABILITY, "revoked capability")
	})

	t.Run("R3WithoutFourEyes", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R3, capabilities: []string{"redteam.api_probe"},
			domains: []string{"*.acme.com"},
		})
		dec := e.authorize(t, a, ids.New("task"), "redteam.api_probe", []string{"api.acme.com"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_APPROVAL_MISSING, "R3 without four-eyes approval")
	})

	t.Run("CapabilityNotAllowed", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"},
		})
		dec := e.authorize(t, a, ids.New("task"), "vuln.validate", []string{"a.acme.com"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_CAPABILITY_NOT_ALLOWED, "capability not in allowlist")
	})

	t.Run("RiskClassExceeded", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk:      platformv1.RiskClass_RISK_CLASS_R2,
			capabilities: []string{"detect.scan", "redteam.api_probe"}, // allowed but R3 > max R2
			domains:      []string{"*.acme.com"},
		})
		dec := e.authorize(t, a, ids.New("task"), "redteam.api_probe", []string{"a.acme.com"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_RISK_CLASS_EXCEEDED, "R3 over max R2")
	})

	t.Run("BlackoutWindow", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		hour := time.Now().UTC().Hour()
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"},
			blackout: []*gatekeeperv1.BlackoutWindow{
				{Rrule: "FREQ=DAILY;BYHOUR=" + strconv.Itoa(hour), Tz: "UTC"},
			},
		})
		dec := e.authorize(t, a, ids.New("task"), "detect.scan", []string{"a.acme.com"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_BLACKOUT_WINDOW, "inside blackout")
	})

	t.Run("JurisdictionDenied", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"}, jurisdictions: []string{"EU"},
		})
		dec := e.authorize(t, a, ids.New("task"), "detect.scan", []string{"a.acme.com"}, r.GetRoeId(),
			&gatekeeperv1.EvaluationContext{SourceRegion: "US"})
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_JURISDICTION_DENIED, "region not allowed")
	})

	t.Run("DataClassDenied", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"}, dataClasses: []string{"PII"},
		})
		dec := e.authorize(t, a, ids.New("task"), "detect.scan", []string{"a.acme.com"}, r.GetRoeId(),
			&gatekeeperv1.EvaluationContext{DataClassesTouched: []string{"HIPAA"}})
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_DATA_CLASS_DENIED, "data class not allowed")
	})

	t.Run("RateLimited", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains:  []string{"*.acme.com"},
			rateCaps: map[string]*gatekeeperv1.RateCapEntry{"detect.scan": {Rps: 1}},
		})
		// Drain the bucket (capacity 1), then expect a denial with retry_after_ms.
		task := ids.New("task")
		d1 := e.authorize(t, a, task, "detect.scan", []string{"a.acme.com"}, r.GetRoeId(), nil)
		d2 := e.authorize(t, a, task, "detect.scan", []string{"a.acme.com"}, r.GetRoeId(), nil)
		if d1.GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW &&
			d2.GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
			t.Fatalf("first decision should fit the bucket: %v %v", d1.GetReasons(), d2.GetReasons())
		}
		dec := e.authorize(t, a, task, "detect.scan", []string{"a.acme.com"}, r.GetRoeId(), nil)
		expectDeny(t, dec, gatekeeperv1.DenyReason_DENY_REASON_RATE_LIMITED, "over the rate cap")
		if dec.GetRetryAfterMs() == 0 {
			t.Fatal("RATE_LIMITED denials must carry retry_after_ms (doc 11 §4)")
		}
	})

	t.Run("Unauthenticated", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"},
		})
		// Commander mismatch: CAI principal submitting for a hexstrike task.
		resp, err := e.policy.Authorize(context.Background(), &gatekeeperv1.AuthorizeRequest{Request: &gatekeeperv1.AuthorizationRequest{
			RequestId:  ids.New("req"),
			Principal:  &gatekeeperv1.Principal{Kind: "service", Id: "svc-cai-commander", SpiffeId: "spiffe://platform/cai"},
			Task:       &gatekeeperv1.TaskContext{TaskId: ids.New("task"), Commander: "hexstrike"},
			Capability: "detect.scan", Targets: []string{"a.acme.com"}, RoeId: r.GetRoeId(),
		}})
		if err != nil {
			t.Fatal(err)
		}
		expectDeny(t, resp.GetDecision(), gatekeeperv1.DenyReason_DENY_REASON_UNAUTHENTICATED, "commander identity mismatch")
	})

	t.Run("ForbiddenRole", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"},
		})
		resp, err := e.policy.Authorize(context.Background(), &gatekeeperv1.AuthorizeRequest{Request: &gatekeeperv1.AuthorizationRequest{
			RequestId:  ids.New("req"),
			Principal:  &gatekeeperv1.Principal{Kind: "service", Id: "svc-nobody"},
			Task:       &gatekeeperv1.TaskContext{TaskId: ids.New("task")},
			Capability: "detect.scan", Targets: []string{"a.acme.com"}, RoeId: r.GetRoeId(),
		}})
		if err != nil {
			t.Fatal(err)
		}
		expectDeny(t, resp.GetDecision(), gatekeeperv1.DenyReason_DENY_REASON_FORBIDDEN_ROLE, "no roles")
	})

	t.Run("AuditUnavailable", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"},
		})
		// Policy instance whose audit ingest is down (bad pool) must deny
		// R1+ with AUDIT_UNAVAILABLE (doc 11 §7 fail-closed).
		badAudit := auditNewForTest(badPool(t))
		pol := policyNewForTest(e, badAudit)
		resp, err := pol.Authorize(context.Background(), &gatekeeperv1.AuthorizeRequest{Request: &gatekeeperv1.AuthorizationRequest{
			RequestId:  ids.New("req"),
			Principal:  &gatekeeperv1.Principal{Kind: "service", Id: a.commander, SpiffeId: "spiffe://platform/hexstrike"},
			Task:       &gatekeeperv1.TaskContext{TaskId: ids.New("task"), Commander: "hexstrike"},
			Capability: "detect.scan", Targets: []string{"a.acme.com"}, RoeId: r.GetRoeId(),
		}})
		if err != nil {
			t.Fatal(err)
		}
		expectDeny(t, resp.GetDecision(), gatekeeperv1.DenyReason_DENY_REASON_AUDIT_UNAVAILABLE, "audit ingest down")
	})

	t.Run("DryRunHasNoSideEffects", func(t *testing.T) {
		a := e.seedActors(t, orgID(t))
		r := e.createROE(t, a, roeParams{
			maxRisk: platformv1.RiskClass_RISK_CLASS_R2, capabilities: []string{"detect.scan"},
			domains: []string{"*.acme.com"},
		})
		resp, err := e.policy.Authorize(context.Background(), &gatekeeperv1.AuthorizeRequest{Request: &gatekeeperv1.AuthorizationRequest{
			RequestId:  ids.New("req"),
			Principal:  &gatekeeperv1.Principal{Kind: "service", Id: a.commander, SpiffeId: "spiffe://platform/hexstrike"},
			Task:       &gatekeeperv1.TaskContext{TaskId: ids.New("task"), Commander: "hexstrike"},
			Capability: "detect.scan", Targets: []string{"a.acme.com"}, RoeId: r.GetRoeId(),
			DryRun: true,
		}})
		if err != nil {
			t.Fatal(err)
		}
		if resp.GetDecision().GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
			t.Fatalf("dry-run should allow: %v", resp.GetDecision().GetReasons())
		}
		// No decision persisted → mint against it must fail (no grant).
		_, err = e.token.MintToken(context.Background(), &gatekeeperv1.MintTokenRequest{
			DecisionId: resp.GetDecision().GetDecisionId(),
			TaskId:     ids.New("task"), Subject: "agent_x",
			Targets: []string{"a.acme.com"},
		})
		if err == nil {
			t.Fatal("mint against a dry-run decision must fail (no durable grant)")
		}
	})
}
