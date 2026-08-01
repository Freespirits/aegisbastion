// Package approval implements approval-service (doc 11 §2.1.8): four-eyes
// approvals for R3 and for R2 stress.* on production targets. Two DISTINCT
// human approvers holding offensive-approver; segregation of duties
// (approver ≠ RoE author ≠ requester) enforced at decision time; 72-h expiry;
// executed targets must be a subset of the approved set (pipeline step 7).
package approval

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/capreg"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/rbac"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
)

// TTL is the doc 11 §3.3 step-7 approval expiry (also the DB default).
const TTL = 72 * time.Hour

// RoeLoader lets approval-service check the RoE author for SoD without a
// hard dependency on roe-service internals.
type RoeLoader interface {
	LoadROE(ctx context.Context, roeID string, version uint64) (*gatekeeperv1.RulesOfEngagement, error)
}

// Service implements gatekeeper.v1.ApprovalService.
type Service struct {
	gatekeeperv1.UnimplementedApprovalServiceServer
	db   *store.DB
	rbac *rbac.Service
	aud  *audit.Service
	pub  bus.Publisher
	roes RoeLoader
	now  func() time.Time
}

// New builds the service. roes may be nil (SoD author check then degrades to
// requester-vs-approver only — wiring provides it in production).
func New(db *store.DB, rbacSvc *rbac.Service, auditSvc *audit.Service, pub bus.Publisher, roes RoeLoader) *Service {
	return &Service{db: db, rbac: rbacSvc, aud: auditSvc, pub: pub, roes: roes, now: time.Now}
}

var stateToProto = map[string]gatekeeperv1.ApprovalState{
	"pending":  gatekeeperv1.ApprovalState_APPROVAL_STATE_PENDING,
	"granted":  gatekeeperv1.ApprovalState_APPROVAL_STATE_GRANTED,
	"rejected": gatekeeperv1.ApprovalState_APPROVAL_STATE_REJECTED,
	"expired":  gatekeeperv1.ApprovalState_APPROVAL_STATE_EXPIRED,
}

// RequestApproval opens a four-eyes approval request.
func (s *Service) RequestApproval(ctx context.Context, req *gatekeeperv1.RequestApprovalRequest) (*gatekeeperv1.RequestApprovalResponse, error) {
	if req.GetRoeId() == "" || req.GetRoeVersion() == 0 || req.GetCapability() == "" ||
		len(req.GetTargets()) == 0 || req.GetRequester() == "" {
		return nil, errors.New("approval: roe_id, roe_version, capability, targets and requester are required")
	}
	rc := req.GetRiskClass()
	if rc != platformv1.RiskClass_RISK_CLASS_R2 && rc != platformv1.RiskClass_RISK_CLASS_R3 {
		return nil, fmt.Errorf("approval: risk_class must be R2 or R3, got %s", capreg.RiskClassString(rc))
	}
	// The RoE version must exist (FK enforces too).
	var orgID, status string
	err := s.db.Pool.QueryRow(ctx,
		`SELECT org_id, status FROM roe_records WHERE roe_id = $1 AND version = $2`,
		req.GetRoeId(), int(req.GetRoeVersion())).Scan(&orgID, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("approval: RoE %s v%d not found", req.GetRoeId(), req.GetRoeVersion())
		}
		return nil, fmt.Errorf("approval: load RoE: %w", err)
	}
	a := &gatekeeperv1.Approval{
		ApprovalId: ids.New("appr"),
		RoeId:      req.GetRoeId(),
		RoeVersion: req.GetRoeVersion(),
		Capability: req.GetCapability(),
		RiskClass:  rc,
		Targets:    req.GetTargets(),
		Requester:  req.GetRequester(),
		State:      gatekeeperv1.ApprovalState_APPROVAL_STATE_PENDING,
		CreatedAt:  timestamppb.New(s.now().UTC()),
		ExpiresAt:  timestamppb.New(s.now().UTC().Add(TTL)),
	}
	targetsJSON, _ := json.Marshal(a.GetTargets())
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO approvals (approval_id, org_id, roe_id, roe_version, capability, risk_class,
		                       targets, requester, status, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8,'pending',$9,$10)`,
		a.GetApprovalId(), orgID, a.GetRoeId(), int(a.GetRoeVersion()), a.GetCapability(),
		capreg.RiskClassString(rc), string(targetsJSON), a.GetRequester(),
		a.GetCreatedAt().AsTime(), a.GetExpiresAt().AsTime()); err != nil {
		return nil, fmt.Errorf("approval: insert: %w", err)
	}
	s.record(ctx, orgID, audit.KindApprovalRequested, a, nil)
	s.publish(ctx, a)
	return &gatekeeperv1.RequestApprovalResponse{Approval: a}, nil
}

// RecordApprovalDecision adds one approver vote with SoD enforcement.
func (s *Service) RecordApprovalDecision(ctx context.Context, req *gatekeeperv1.RecordApprovalDecisionRequest) (*gatekeeperv1.RecordApprovalDecisionResponse, error) {
	vote := req.GetDecision()
	if vote == nil || vote.GetApprover() == "" {
		return nil, errors.New("approval: decision.approver is required")
	}
	a, orgID, err := s.loadWithOrg(ctx, req.GetApprovalId())
	if err != nil {
		return nil, err
	}
	if a.GetState() != gatekeeperv1.ApprovalState_APPROVAL_STATE_PENDING {
		return nil, fmt.Errorf("approval: %s is %s — not decidable", a.GetApprovalId(), a.GetState())
	}
	if !s.now().Before(a.GetExpiresAt().AsTime()) {
		if err := s.setState(ctx, a.GetApprovalId(), "expired"); err != nil {
			return nil, err
		}
		a.State = gatekeeperv1.ApprovalState_APPROVAL_STATE_EXPIRED
		return &gatekeeperv1.RecordApprovalDecisionResponse{Approval: a}, nil
	}
	// SoD first (doc 11 §2.1.8): approver ≠ requester, approver ≠ RoE author —
	// these hold even for principals that also carry the approver role.
	if vote.GetApprover() == a.GetRequester() {
		return nil, fmt.Errorf("approval: segregation of duties — approver %q is the requester", vote.GetApprover())
	}
	if s.roes != nil {
		roe, err := s.roes.LoadROE(ctx, a.GetRoeId(), a.GetRoeVersion())
		if err != nil {
			return nil, fmt.Errorf("approval: load RoE for SoD check: %w", err)
		}
		if vote.GetApprover() == roe.GetCreatedBy() {
			return nil, fmt.Errorf("approval: segregation of duties — approver %q is the RoE author", vote.GetApprover())
		}
	}
	// RBAC: approver must hold offensive-approver in the RoE's org.
	ok, err := s.rbac.HasRole(ctx, orgID, vote.GetApprover(), rbac.RoleOffensiveApprover)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("approval: %q does not hold role offensive-approver in %s", vote.GetApprover(), orgID)
	}
	decision := "approve"
	if !vote.GetApproved() {
		decision = "reject"
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO approval_votes (approval_id, approver, decision, note, decided_at)
		VALUES ($1,$2,$3,$4,$5)`,
		a.GetApprovalId(), vote.GetApprover(), decision, vote.GetNote(), s.now().UTC()); err != nil {
		return nil, fmt.Errorf("approval: record vote (duplicate approver?): %w", err)
	}
	a.Decisions = append(a.GetDecisions(), &gatekeeperv1.ApproverDecision{
		Approver: vote.GetApprover(),
		Approved: vote.GetApproved(),
		At:       timestamppb.New(s.now().UTC()),
		Note:     vote.GetNote(),
	})

	switch {
	case !vote.GetApproved():
		// Any reject closes the approval.
		if err := s.setState(ctx, a.GetApprovalId(), "rejected"); err != nil {
			return nil, err
		}
		a.State = gatekeeperv1.ApprovalState_APPROVAL_STATE_REJECTED
		s.record(ctx, orgID, audit.KindApprovalRejected, a, map[string]any{"approver": vote.GetApprover()})
	default:
		if countApproves(a.GetDecisions()) >= 2 {
			if err := s.setState(ctx, a.GetApprovalId(), "granted"); err != nil {
				return nil, err
			}
			a.State = gatekeeperv1.ApprovalState_APPROVAL_STATE_GRANTED
			s.record(ctx, orgID, audit.KindApprovalGranted, a, nil)
		}
	}
	s.publish(ctx, a)
	return &gatekeeperv1.RecordApprovalDecisionResponse{Approval: a}, nil
}

func countApproves(votes []*gatekeeperv1.ApproverDecision) int {
	n := 0
	for _, v := range votes {
		if v.GetApproved() {
			n++
		}
	}
	return n
}

// GetApproval fetches an approval (lazily expired).
func (s *Service) GetApproval(ctx context.Context, req *gatekeeperv1.GetApprovalRequest) (*gatekeeperv1.GetApprovalResponse, error) {
	a, _, err := s.loadWithOrg(ctx, req.GetApprovalId())
	if err != nil {
		return nil, err
	}
	if a, err = s.lazyExpire(ctx, a); err != nil {
		return nil, err
	}
	return &gatekeeperv1.GetApprovalResponse{Approval: a}, nil
}

// ListApprovals filters approvals (operator queue).
func (s *Service) ListApprovals(ctx context.Context, req *gatekeeperv1.ListApprovalsRequest) (*gatekeeperv1.ListApprovalsResponse, error) {
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	offset := 0
	if req.GetPageToken() != "" {
		if _, err := fmt.Sscanf(req.GetPageToken(), "%d", &offset); err != nil {
			return nil, fmt.Errorf("approval: invalid page_token")
		}
	}
	q := `
		SELECT a.approval_id, a.roe_id, a.roe_version, a.capability, a.risk_class,
		       a.targets, a.requester, a.status, a.created_at, a.expires_at
		FROM approvals a WHERE true`
	args := []any{}
	if req.GetRoeId() != "" {
		args = append(args, req.GetRoeId())
		q += fmt.Sprintf(` AND a.roe_id = $%d`, len(args))
	}
	if st := req.GetState(); st != gatekeeperv1.ApprovalState_APPROVAL_STATE_UNSPECIFIED {
		for dbState, ps := range stateToProto {
			if ps == st {
				args = append(args, dbState)
				q += fmt.Sprintf(` AND a.status = $%d`, len(args))
			}
		}
	}
	q += fmt.Sprintf(` ORDER BY a.created_at DESC LIMIT $%d OFFSET $%d`, len(args)+1, len(args)+2)
	args = append(args, pageSize+1, offset)
	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("approval: list: %w", err)
	}
	defer rows.Close()
	var out []*gatekeeperv1.Approval
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	resp := &gatekeeperv1.ListApprovalsResponse{}
	if len(out) > pageSize {
		out = out[:pageSize]
		resp.NextPageToken = fmt.Sprint(offset + pageSize)
	}
	for _, a := range out {
		if a, err = s.lazyExpire(ctx, a); err != nil {
			return nil, err
		}
	}
	resp.Approvals = out
	return resp, nil
}

// FindValidApproval returns the granted, unexpired approval for
// (roe_id, roe_version, capability) whose approved target set covers targets
// (pipeline step 7). Returns nil, nil when none qualifies.
func (s *Service) FindValidApproval(ctx context.Context, roeID string, roeVersion uint64, capability string, targets []string) (*gatekeeperv1.Approval, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT approval_id, roe_id, roe_version, capability, risk_class, targets, requester,
		       status, created_at, expires_at
		FROM approvals
		WHERE roe_id = $1 AND roe_version = $2 AND capability = $3 AND status = 'granted'
		ORDER BY created_at DESC`,
		roeID, int(roeVersion), capability)
	if err != nil {
		return nil, fmt.Errorf("approval: find: %w", err)
	}
	defer rows.Close()
	now := s.now().UTC()
	for rows.Next() {
		a, err := scanApproval(rows)
		if err != nil {
			return nil, err
		}
		if !now.Before(a.GetExpiresAt().AsTime()) {
			continue
		}
		if subsetOf(targets, a.GetTargets()) {
			return a, nil
		}
	}
	return nil, rows.Err()
}

// subsetOf reports whether every element of sub is in sup (exact string
// match — approval target sets use the same canonical form as requests).
func subsetOf(sub, sup []string) bool {
	set := map[string]bool{}
	for _, s := range sup {
		set[s] = true
	}
	for _, s := range sub {
		if !set[s] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

func (s *Service) loadWithOrg(ctx context.Context, approvalID string) (*gatekeeperv1.Approval, string, error) {
	if approvalID == "" {
		return nil, "", errors.New("approval: approval_id is required")
	}
	rows, err := s.db.Pool.Query(ctx, `
		SELECT approval_id, roe_id, roe_version, capability, risk_class, targets, requester,
		       status, created_at, expires_at, org_id
		FROM approvals WHERE approval_id = $1`, approvalID)
	if err != nil {
		return nil, "", fmt.Errorf("approval: load: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, "", err
		}
		return nil, "", pgx.ErrNoRows
	}
	var orgID string
	var a gatekeeperv1.Approval
	var version int
	var targetsJSON, status, riskClass string
	var createdAt, expiresAt time.Time
	if err := rows.Scan(&a.ApprovalId, &a.RoeId, &version, &a.Capability, &riskClass,
		&targetsJSON, &a.Requester, &status, &createdAt, &expiresAt, &orgID); err != nil {
		return nil, "", fmt.Errorf("approval: scan: %w", err)
	}
	rows.Close()
	a.RoeVersion = uint64(version)
	rc, _ := capreg.ParseRiskClass(riskClass)
	a.RiskClass = rc
	a.State = stateToProto[status]
	a.CreatedAt = timestamppb.New(createdAt)
	a.ExpiresAt = timestamppb.New(expiresAt)
	_ = json.Unmarshal([]byte(targetsJSON), &a.Targets)
	votes, err := s.loadVotes(ctx, approvalID)
	if err != nil {
		return nil, "", err
	}
	a.Decisions = votes
	return &a, orgID, nil
}

func (s *Service) loadVotes(ctx context.Context, approvalID string) ([]*gatekeeperv1.ApproverDecision, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT approver, decision, note, decided_at FROM approval_votes
		WHERE approval_id = $1 ORDER BY decided_at`, approvalID)
	if err != nil {
		return nil, fmt.Errorf("approval: votes: %w", err)
	}
	defer rows.Close()
	var out []*gatekeeperv1.ApproverDecision
	for rows.Next() {
		var approver, decision, note string
		var at time.Time
		if err := rows.Scan(&approver, &decision, &note, &at); err != nil {
			return nil, err
		}
		out = append(out, &gatekeeperv1.ApproverDecision{
			Approver: approver,
			Approved: decision == "approve",
			At:       timestamppb.New(at),
			Note:     note,
		})
	}
	return out, rows.Err()
}

type approvalScanner interface{ Scan(dest ...any) error }

func scanApproval(rows approvalScanner) (*gatekeeperv1.Approval, error) {
	var a gatekeeperv1.Approval
	var version int
	var targetsJSON, status, riskClass string
	var createdAt, expiresAt time.Time
	if err := rows.Scan(&a.ApprovalId, &a.RoeId, &version, &a.Capability, &riskClass,
		&targetsJSON, &a.Requester, &status, &createdAt, &expiresAt); err != nil {
		return nil, fmt.Errorf("approval: scan: %w", err)
	}
	a.RoeVersion = uint64(version)
	rc, _ := capreg.ParseRiskClass(riskClass)
	a.RiskClass = rc
	a.State = stateToProto[status]
	a.CreatedAt = timestamppb.New(createdAt)
	a.ExpiresAt = timestamppb.New(expiresAt)
	_ = json.Unmarshal([]byte(targetsJSON), &a.Targets)
	return &a, nil
}

func (s *Service) lazyExpire(ctx context.Context, a *gatekeeperv1.Approval) (*gatekeeperv1.Approval, error) {
	if a.GetState() == gatekeeperv1.ApprovalState_APPROVAL_STATE_PENDING &&
		!s.now().UTC().Before(a.GetExpiresAt().AsTime()) {
		if err := s.setState(ctx, a.GetApprovalId(), "expired"); err != nil {
			return nil, err
		}
		a.State = gatekeeperv1.ApprovalState_APPROVAL_STATE_EXPIRED
		s.publish(ctx, a)
	}
	return a, nil
}

func (s *Service) setState(ctx context.Context, approvalID, state string) error {
	_, err := s.db.Pool.Exec(ctx,
		`UPDATE approvals SET status = $2, decided_at = now() WHERE approval_id = $1`,
		approvalID, state)
	if err != nil {
		return fmt.Errorf("approval: set state %s: %w", state, err)
	}
	return nil
}

func (s *Service) record(ctx context.Context, orgID, kind string, a *gatekeeperv1.Approval, extra map[string]any) {
	payload := map[string]any{
		"approval_id": a.GetApprovalId(),
		"roe_id":      a.GetRoeId(),
		"roe_version": a.GetRoeVersion(),
		"capability":  a.GetCapability(),
		"risk_class":  capreg.RiskClassString(a.GetRiskClass()),
		"requester":   a.GetRequester(),
		"state":       a.GetState().String(),
	}
	for k, v := range extra {
		payload[k] = v
	}
	// Approval events are control-plane (R0-class): best-effort audit, never
	// block the workflow (audit-gating applies to R1–R3 execution decisions).
	if _, err := s.aud.Record(ctx, audit.Input{
		OrgID:   orgID,
		Kind:    kind,
		Actor:   map[string]any{"kind": "user", "id": a.GetRequester()},
		Subject: map[string]any{"roe_id": a.GetRoeId()},
		Payload: payload,
	}); err != nil {
		fmt.Printf("approval: WARNING audit record %s for %s failed: %v\n", kind, a.GetApprovalId(), err)
	}
}

func (s *Service) publish(ctx context.Context, a *gatekeeperv1.Approval) {
	if err := s.pub.Publish(ctx, bus.SubjectApprovals, a); err != nil {
		fmt.Printf("approval: WARNING publish %s failed: %v\n", a.GetApprovalId(), err)
	}
}
