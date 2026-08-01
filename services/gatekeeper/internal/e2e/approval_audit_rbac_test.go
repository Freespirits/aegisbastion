package e2e

import (
	"context"
	"strings"
	"testing"
	"time"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/rbac"
)

// TestFourEyesApproval exercises the full four-eyes flow: request → one vote
// (still pending → policy denies) → SoD rejections → second distinct vote →
// granted → policy allows → mint binds approval_id.
func TestFourEyesApproval(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	a := e.seedActors(t, orgID(t))
	r := e.createROE(t, a, roeParams{
		maxRisk: platformv1.RiskClass_RISK_CLASS_R3, capabilities: []string{"redteam.api_probe"},
		domains: []string{"*.acme.com"},
	})
	targets := []string{"api.acme.com"}

	req, err := e.approval.RequestApproval(ctx, &gatekeeperv1.RequestApprovalRequest{
		RoeId: r.GetRoeId(), RoeVersion: r.GetVersion(), Capability: "redteam.api_probe",
		RiskClass: platformv1.RiskClass_RISK_CLASS_R3, Targets: targets, Requester: a.requester,
	})
	if err != nil {
		t.Fatal(err)
	}
	appr := req.GetApproval()
	if appr.GetState() != gatekeeperv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Fatalf("new approval must be pending, got %v", appr.GetState())
	}
	if appr.GetExpiresAt().AsTime().Sub(appr.GetCreatedAt().AsTime()) != 72*time.Hour {
		t.Fatal("approvals expire after 72 h (doc 11 §3.3)")
	}

	// Policy still denies while pending.
	dec := e.authorize(t, a, ids.New("task"), "redteam.api_probe", targets, r.GetRoeId(), nil)
	if code := firstCode(dec); code != gatekeeperv1.DenyReason_DENY_REASON_APPROVAL_MISSING {
		t.Fatalf("pending approval must still deny APPROVAL_MISSING, got %v", code)
	}

	// SoD: requester cannot approve.
	if _, err := e.approval.RecordApprovalDecision(ctx, &gatekeeperv1.RecordApprovalDecisionRequest{
		ApprovalId: appr.GetApprovalId(),
		Decision:   &gatekeeperv1.ApproverDecision{Approver: a.requester, Approved: true},
	}); err == nil || !strings.Contains(err.Error(), "requester") {
		t.Fatalf("requester approval must fail SoD, got %v", err)
	}
	// SoD: RoE author cannot approve.
	if _, err := e.approval.RecordApprovalDecision(ctx, &gatekeeperv1.RecordApprovalDecisionRequest{
		ApprovalId: appr.GetApprovalId(),
		Decision:   &gatekeeperv1.ApproverDecision{Approver: a.author, Approved: true},
	}); err == nil || !strings.Contains(err.Error(), "RoE author") {
		t.Fatalf("RoE author approval must fail SoD, got %v", err)
	}
	// RBAC: approver must hold offensive-approver.
	if _, err := e.approval.RecordApprovalDecision(ctx, &gatekeeperv1.RecordApprovalDecisionRequest{
		ApprovalId: appr.GetApprovalId(),
		Decision:   &gatekeeperv1.ApproverDecision{Approver: "user_random@" + a.org, Approved: true},
	}); err == nil || !strings.Contains(err.Error(), "offensive-approver") {
		t.Fatalf("approval without the role must fail, got %v", err)
	}

	// First valid vote → still pending.
	v1, err := e.approval.RecordApprovalDecision(ctx, &gatekeeperv1.RecordApprovalDecisionRequest{
		ApprovalId: appr.GetApprovalId(),
		Decision:   &gatekeeperv1.ApproverDecision{Approver: a.approver1, Approved: true, Note: "lgtm"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v1.GetApproval().GetState() != gatekeeperv1.ApprovalState_APPROVAL_STATE_PENDING {
		t.Fatalf("one vote must stay pending (four-eyes), got %v", v1.GetApproval().GetState())
	}
	// Same approver again → duplicate rejected.
	if _, err := e.approval.RecordApprovalDecision(ctx, &gatekeeperv1.RecordApprovalDecisionRequest{
		ApprovalId: appr.GetApprovalId(),
		Decision:   &gatekeeperv1.ApproverDecision{Approver: a.approver1, Approved: true},
	}); err == nil {
		t.Fatal("duplicate approver must be rejected (distinct approvers)")
	}
	// Second distinct vote → granted.
	v2, err := e.approval.RecordApprovalDecision(ctx, &gatekeeperv1.RecordApprovalDecisionRequest{
		ApprovalId: appr.GetApprovalId(),
		Decision:   &gatekeeperv1.ApproverDecision{Approver: a.approver2, Approved: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if v2.GetApproval().GetState() != gatekeeperv1.ApprovalState_APPROVAL_STATE_GRANTED {
		t.Fatalf("two distinct votes must grant, got %v", v2.GetApproval().GetState())
	}

	// Policy now allows, and mint binds the approval_id.
	taskID := ids.New("task")
	dec = e.authorize(t, a, taskID, "redteam.api_probe", targets, r.GetRoeId(), nil)
	if dec.GetDecision() != gatekeeperv1.Decision_DECISION_ALLOW {
		t.Fatalf("granted approval must allow, got %v", dec.GetReasons())
	}
	mint, err := e.token.MintToken(ctx, &gatekeeperv1.MintTokenRequest{
		DecisionId: dec.GetDecisionId(), TaskId: taskID, Subject: "agent_" + ids.New("rt"), Targets: targets,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mint.GetClaims().GetApprovalId() != appr.GetApprovalId() {
		t.Fatalf("R3 token must bind approval_id %s, got %q", appr.GetApprovalId(), mint.GetClaims().GetApprovalId())
	}

	// Targets outside the approved set are denied (targets ⊆ approved set).
	dec2 := e.authorize(t, a, ids.New("task"), "redteam.api_probe",
		[]string{"other.acme.com"}, r.GetRoeId(), nil)
	if code := firstCode(dec2); code != gatekeeperv1.DenyReason_DENY_REASON_APPROVAL_MISSING &&
		code != gatekeeperv1.DenyReason_DENY_REASON_APPROVAL_MISMATCH {
		t.Fatalf("out-of-approval targets must deny, got %v", code)
	}
}

func firstCode(dec *gatekeeperv1.DecisionEvent) gatekeeperv1.DenyReason {
	if len(dec.GetReasons()) == 0 {
		return gatekeeperv1.DenyReason_DENY_REASON_UNSPECIFIED
	}
	return dec.GetReasons()[0].GetCode()
}

// TestRBACSegregationOfDuties covers the doc 11 §3.5 SoD rules.
func TestRBACSegregationOfDuties(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	org := orgID(t)

	// roe-author + offensive-approver for the same human = SoD violation.
	if _, err := e.rbac.Grant(ctx, rbac.Binding{OrgID: org, Principal: "user_dual@" + org, PrincipalKind: "human", Role: rbac.RoleROEAuthor, GrantedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rbac.Grant(ctx, rbac.Binding{OrgID: org, Principal: "user_dual@" + org, PrincipalKind: "human", Role: rbac.RoleOffensiveApprover, GrantedBy: "admin"}); err == nil {
		t.Fatal("roe-author + offensive-approver must fail SoD")
	}
	// Service accounts cannot hold approval/verification roles.
	if _, err := e.rbac.Grant(ctx, rbac.Binding{OrgID: org, Principal: "svc-bot", PrincipalKind: "service", Role: rbac.RoleOffensiveApprover, GrantedBy: "admin"}); err == nil {
		t.Fatal("service account with offensive-approver must fail SoD")
	}
	// auditor cannot combine with write roles.
	if _, err := e.rbac.Grant(ctx, rbac.Binding{OrgID: org, Principal: "user_aud@" + org, PrincipalKind: "human", Role: rbac.RoleAuditor, GrantedBy: "admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := e.rbac.Grant(ctx, rbac.Binding{OrgID: org, Principal: "user_aud@" + org, PrincipalKind: "human", Role: rbac.RoleROEAuthor, GrantedBy: "admin"}); err == nil {
		t.Fatal("auditor + write role must fail SoD")
	}
	// Grants are time-boxed (default 90 days).
	g, err := e.rbac.Grant(ctx, rbac.Binding{OrgID: org, Principal: "user_tb@" + org, PrincipalKind: "human", Role: rbac.RoleOperator, GrantedBy: "admin"})
	if err != nil {
		t.Fatal(err)
	}
	if d := g.ExpiresAt.Sub(g.GrantedAt); d < 89*24*time.Hour || d > 91*24*time.Hour {
		t.Fatalf("default grant TTL must be ~90 days, got %v", d)
	}
	// Revoke works.
	if err := e.rbac.Revoke(ctx, org, "user_tb@"+org, rbac.RoleOperator); err != nil {
		t.Fatal(err)
	}
	ok, err := e.rbac.HasRole(ctx, org, "user_tb@"+org, rbac.RoleOperator)
	if err != nil || ok {
		t.Fatalf("revoked role must not be active: ok=%v err=%v", ok, err)
	}
}

// TestAuditChainAgainstRealDB records events and verifies the chain end to
// end (the doc 00 Phase-0 audit-gating exit gate).
func TestAuditChainAgainstRealDB(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	org := orgID(t)

	var first, last uint64
	for i := 0; i < 10; i++ {
		ev, err := e.audit.Record(ctx, auditInput(org, i))
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = ev.Seq
			if ev.PrevHash != "" {
				t.Fatal("genesis event of a new partition must have empty prev_hash")
			}
		}
		if ev.EventHash == "" || len(ev.EventHash) != 64 {
			t.Fatalf("bad event hash %q", ev.EventHash)
		}
		last = ev.Seq
	}
	valid, gaps, err := e.audit.VerifyRange(ctx, org, first, last)
	if err != nil {
		t.Fatal(err)
	}
	if !valid || len(gaps) != 0 {
		t.Fatalf("chain must verify: valid=%v gaps=%v", valid, gaps)
	}
	// A range covering a missing seq reports the gap.
	valid, gaps, err = e.audit.VerifyRange(ctx, org, last+1, last+3)
	if err != nil {
		t.Fatal(err)
	}
	if valid || len(gaps) != 3 {
		t.Fatalf("missing seqs must be reported as gaps: valid=%v gaps=%v", valid, gaps)
	}
	// gRPC surface agrees.
	resp, err := e.audit.VerifyChain(ctx, &gatekeeperv1.VerifyChainRequest{OrgId: org, FromSeq: first, ToSeq: last})
	if err != nil || !resp.GetValid() {
		t.Fatalf("VerifyChain RPC: %v %+v", err, resp)
	}
}

func auditInput(org string, i int) audit.Input {
	return audit.Input{
		OrgID: org,
		Kind:  "admin.action",
		Actor: map[string]any{"kind": "user", "id": "user_tester@" + org},
		Payload: map[string]any{
			"action": "e2e-test", "i": i,
		},
	}
}

// TestAuditBusIngest proves audit.events → chain (module-forwarded events).
func TestAuditBusIngest(t *testing.T) {
	e := newEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = e.audit.RunConsumer(ctx, e.bus) }()
	time.Sleep(500 * time.Millisecond) // let the durable attach

	evt := &platformv1.AuditEvent{
		EventId: ids.New("aud"),
		Type:    platformv1.AuditEventType_AUDIT_EVENT_TYPE_TARGET_TOUCHED,
		Actor:   &platformv1.AuditActor{Kind: "agent", Id: "agent_e2e"},
		Subject: &platformv1.AuditSubject{TaskId: ids.New("task")},
	}
	if err := e.bus.Publish(ctx, "audit.events", evt); err != nil {
		t.Fatal(err)
	}
	// The consumer chains it into the platform partition.
	deadline := time.Now().Add(10 * time.Second)
	for {
		var n int
		if err := e.db.Pool.QueryRow(ctx,
			`SELECT count(*) FROM audit_events WHERE event_id = $1`, evt.GetEventId()).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n == 1 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("bus-ingested audit event never landed in the chain")
		}
		time.Sleep(200 * time.Millisecond)
	}
}
