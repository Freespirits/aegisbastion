// Package roe implements roe-service (doc 11 §2.1.1/§3.1, doc 01 §5.4): the
// store of record for Rules-of-Engagement. Records are immutable — edits
// create a new version; only status may change in place (enforced doubly by
// the migration 000002 trigger). Every RoE is Ed25519-signed over its JCS
// (RFC 8785) canonical form (doc 01 §10.2).
package roe

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/jsonx"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/keys"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/rbac"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
)

// MaxValidity is the doc 11 §3.1 hard cap: valid_until ≤ 90 days from
// valid_from (renewal = new version; also a DB CHECK constraint).
const MaxValidity = 90 * 24 * time.Hour

// Status strings as stored in roe_records.
const (
	statusDraft           = "draft"
	statusPendingApproval = "pending_approval"
	statusActive          = "active"
	statusSuspended       = "suspended"
	statusExpired         = "expired"
	statusRevoked         = "revoked"
)

var statusFromProto = map[gatekeeperv1.ROEStatus]string{
	gatekeeperv1.ROEStatus_ROE_STATUS_DRAFT:            statusDraft,
	gatekeeperv1.ROEStatus_ROE_STATUS_PENDING_APPROVAL: statusPendingApproval,
	gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE:           statusActive,
	gatekeeperv1.ROEStatus_ROE_STATUS_SUSPENDED:        statusSuspended,
	gatekeeperv1.ROEStatus_ROE_STATUS_EXPIRED:          statusExpired,
	gatekeeperv1.ROEStatus_ROE_STATUS_REVOKED:          statusRevoked,
}

var statusToProto = map[string]gatekeeperv1.ROEStatus{
	statusDraft:           gatekeeperv1.ROEStatus_ROE_STATUS_DRAFT,
	statusPendingApproval: gatekeeperv1.ROEStatus_ROE_STATUS_PENDING_APPROVAL,
	statusActive:          gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE,
	statusSuspended:       gatekeeperv1.ROEStatus_ROE_STATUS_SUSPENDED,
	statusExpired:         gatekeeperv1.ROEStatus_ROE_STATUS_EXPIRED,
	statusRevoked:         gatekeeperv1.ROEStatus_ROE_STATUS_REVOKED,
}

// RevocationIssuer publishes a revocation when an RoE is revoked
// (wired to revocation-service in main; keeps roe free of a hard dependency).
type RevocationIssuer interface {
	IssueROERevocation(ctx context.Context, roeID, issuedBy, reason string) error
}

// Service implements gatekeeper.v1.ROEService.
type Service struct {
	gatekeeperv1.UnimplementedROEServiceServer
	db     *store.DB
	key    *keys.Keypair
	rbac   *rbac.Service
	audit  *audit.Service
	pub    bus.Publisher
	revoke RevocationIssuer // optional; RevokeROE still works without it
	now    func() time.Time
}

// New builds the service. revoke may be nil (no revocation broadcast).
func New(db *store.DB, key *keys.Keypair, rbacSvc *rbac.Service, auditSvc *audit.Service, pub bus.Publisher, revoke RevocationIssuer) *Service {
	return &Service{db: db, key: key, rbac: rbacSvc, audit: auditSvc, pub: pub, revoke: revoke, now: time.Now}
}

var protoNames = protojson.MarshalOptions{UseProtoNames: true}

// sign produces the RoE signature: base64url(Ed25519_sign(JCS(protojson(roe))))
// with the signature field cleared (doc 01 §10.2: JCS / RFC 8785).
func (s *Service) sign(r *gatekeeperv1.RulesOfEngagement) (string, error) {
	clone := proto.Clone(r).(*gatekeeperv1.RulesOfEngagement)
	clone.Signature = ""
	raw, err := protoNames.Marshal(clone)
	if err != nil {
		return "", fmt.Errorf("roe: marshal for signature: %w", err)
	}
	canon, err := jsonx.CanonicalRaw(raw)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(s.key.Sign(canon)), nil
}

// validateHardRules enforces doc 11 §3.1 validation that must hold at write
// time (create/update): validity window cap, scope sanity, R2/R3 legal
// artifact + verified_by, Azure stress notification.
func validateHardRules(r *gatekeeperv1.RulesOfEngagement) error {
	if r.GetOrgId() == "" || r.GetName() == "" || r.GetCreatedBy() == "" {
		return errors.New("roe: org_id, name and created_by are required")
	}
	vf, vu := r.GetValidFrom().AsTime(), r.GetValidUntil().AsTime()
	if vf.IsZero() || vu.IsZero() || !vu.After(vf) {
		return errors.New("roe: valid_from/valid_until must define a positive window")
	}
	if vu.Sub(vf) > MaxValidity {
		return fmt.Errorf("roe: validity window %v exceeds the 90-day cap (doc 11 §3.1)", vu.Sub(vf))
	}
	sc := r.GetScope()
	if sc == nil || (len(sc.GetDomains()) == 0 && len(sc.GetCidrs()) == 0 &&
		len(sc.GetAssetGroupIds()) == 0 && len(sc.GetCloudAccounts()) == 0) {
		return errors.New("roe: scope must include at least one include form (domains/cidrs/asset groups/cloud accounts)")
	}
	c := r.GetConstraints()
	maxRC := c.GetMaxRiskClass()
	if maxRC == platformv1.RiskClass_RISK_CLASS_UNSPECIFIED {
		return errors.New("roe: constraints.max_risk_class is required")
	}
	if maxRC == platformv1.RiskClass_RISK_CLASS_R2 || maxRC == platformv1.RiskClass_RISK_CLASS_R3 {
		la := r.GetLegalArtifact()
		if la == nil || la.GetDocumentSha256() == "" || la.GetStorageUri() == "" {
			return errors.New("roe: legal_artifact (hash + immutable storage URI) is mandatory for max_risk_class R2/R3 (doc 11 §3.1)")
		}
		if la.GetVerifiedBy() == "" || la.GetVerifiedAt() == nil {
			return errors.New("roe: legal_artifact must be verified (verified_by + verified_at) for R2/R3")
		}
		if r.GetApprovedByOperator() == nil || r.GetApprovedByOperator().GetIdentity() == "" {
			return errors.New("roe: approved_by_operator attestation is required for R2/R3 (doc 01 §5.4)")
		}
	}
	// Azure stress: notification id mandatory when stress.* capabilities are allowed.
	for _, cap := range c.GetAllowedCapabilities() {
		if cap == "stress.*" || strings.HasPrefix(cap, "stress.") {
			if c.GetAzurePentestNotificationId() == "" {
				return fmt.Errorf("roe: azure_pentest_notification_id is mandatory for stress.* capability %q (doc 11 §3.1)", cap)
			}
			break
		}
	}
	return nil
}

// verifyGRC checks the legal artifact's verified_by holds grc-verifier.
func (s *Service) verifyGRC(ctx context.Context, r *gatekeeperv1.RulesOfEngagement) error {
	vb := r.GetLegalArtifact().GetVerifiedBy()
	if vb == "" {
		return nil
	}
	ok, err := s.rbac.HasRole(ctx, r.GetOrgId(), vb, rbac.RoleGRCVerifier)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("roe: legal_artifact.verified_by %q does not hold role grc-verifier (doc 11 §3.1)", vb)
	}
	return nil
}

// CreateROE drafts a new RoE (RBAC: roe:create).
func (s *Service) CreateROE(ctx context.Context, req *gatekeeperv1.CreateROERequest) (*gatekeeperv1.CreateROEResponse, error) {
	r := req.GetRoe()
	if r == nil {
		return nil, errors.New("roe: roe is required")
	}
	if err := s.rbac.RequirePermission(ctx, r.GetOrgId(), r.GetCreatedBy(), "roe:create"); err != nil {
		return nil, err
	}
	if err := validateHardRules(r); err != nil {
		return nil, err
	}
	if err := s.verifyGRC(ctx, r); err != nil {
		return nil, err
	}
	r.RoeId = ids.New("roe")
	r.Version = 1
	r.Status = gatekeeperv1.ROEStatus_ROE_STATUS_DRAFT
	r.UpdatedAt = timestamppb.New(s.now().UTC())
	sig, err := s.sign(r)
	if err != nil {
		return nil, err
	}
	r.Signature = sig
	if err := s.insert(ctx, r); err != nil {
		return nil, err
	}
	s.recordEvent(ctx, r, audit.KindROECreated, map[string]any{"version": r.Version})
	s.publishEvent(ctx, "ROE_CREATED", r)
	return &gatekeeperv1.CreateROEResponse{Roe: r}, nil
}

// LoadROE fetches a record (latest or specific version) with lazy expiry —
// the read path used by policy-service, approval-service and token-service.
func (s *Service) LoadROE(ctx context.Context, roeID string, version uint64) (*gatekeeperv1.RulesOfEngagement, error) {
	r, err := s.load(ctx, roeID, version)
	if err != nil {
		return nil, err
	}
	return s.lazyExpire(ctx, r)
}

// GetROE fetches a record (latest or specific version). An active RoE whose
// window has closed is lazily transitioned to expired (doc 11 §7: expiry
// never silently extends).
func (s *Service) GetROE(ctx context.Context, req *gatekeeperv1.GetROERequest) (*gatekeeperv1.GetROEResponse, error) {
	r, err := s.load(ctx, req.GetRoeId(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	if r, err = s.lazyExpire(ctx, r); err != nil {
		return nil, err
	}
	return &gatekeeperv1.GetROEResponse{Roe: r}, nil
}

// ListROEs lists an org's latest-version records, optionally status-filtered.
func (s *Service) ListROEs(ctx context.Context, req *gatekeeperv1.ListROEsRequest) (*gatekeeperv1.ListROEsResponse, error) {
	if req.GetOrgId() == "" {
		return nil, errors.New("roe: org_id is required (tenancy boundary)")
	}
	pageSize := int(req.GetPageSize())
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	offset := 0
	if req.GetPageToken() != "" {
		if _, err := fmt.Sscanf(req.GetPageToken(), "%d", &offset); err != nil {
			return nil, fmt.Errorf("roe: invalid page_token")
		}
	}
	q := `
		SELECT DISTINCT ON (roe_id) roe_id, version, org_id, name, status, created_by,
		       legal_artifact, authorized_by, approved_by, scope, constraints,
		       valid_from, valid_until, signature, updated_at
		FROM roe_records
		WHERE org_id = $1`
	args := []any{req.GetOrgId()}
	if st, ok := statusFromProto[req.GetStatus()]; ok {
		q += ` AND status = $2`
		args = append(args, st)
	}
	q += ` ORDER BY roe_id, version DESC LIMIT $` + fmt.Sprint(len(args)+1) + ` OFFSET $` + fmt.Sprint(len(args)+2)
	args = append(args, pageSize+1, offset)
	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("roe: list: %w", err)
	}
	defer rows.Close()
	var out []*gatekeeperv1.RulesOfEngagement
	for rows.Next() {
		r, err := scanROE(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	resp := &gatekeeperv1.ListROEsResponse{}
	if len(out) > pageSize {
		out = out[:pageSize]
		resp.NextPageToken = fmt.Sprint(offset + pageSize)
	}
	resp.Roes = out
	return resp, nil
}

// UpdateROE creates a new immutable version (status back to draft).
func (s *Service) UpdateROE(ctx context.Context, req *gatekeeperv1.UpdateROERequest) (*gatekeeperv1.UpdateROEResponse, error) {
	r := req.GetRoe()
	if r == nil {
		return nil, errors.New("roe: roe is required")
	}
	latest, err := s.load(ctx, req.GetRoeId(), 0)
	if err != nil {
		return nil, err
	}
	if latest.Status == gatekeeperv1.ROEStatus_ROE_STATUS_REVOKED {
		return nil, errors.New("roe: revoked records are terminal; create a new RoE")
	}
	if err := s.rbac.RequirePermission(ctx, latest.GetOrgId(), r.GetCreatedBy(), "roe:update"); err != nil {
		return nil, err
	}
	r.RoeId = latest.GetRoeId()
	r.OrgId = latest.GetOrgId() // tenancy immutable
	if err := validateHardRules(r); err != nil {
		return nil, err
	}
	if err := s.verifyGRC(ctx, r); err != nil {
		return nil, err
	}
	r.Version = latest.GetVersion() + 1
	r.Status = gatekeeperv1.ROEStatus_ROE_STATUS_DRAFT
	r.UpdatedAt = timestamppb.New(s.now().UTC())
	sig, err := s.sign(r)
	if err != nil {
		return nil, err
	}
	r.Signature = sig
	if err := s.insert(ctx, r); err != nil {
		return nil, err
	}
	s.recordEvent(ctx, r, audit.KindROEUpdated, map[string]any{"version": r.Version})
	s.publishEvent(ctx, "ROE_UPDATED", r)
	return &gatekeeperv1.UpdateROEResponse{Roe: r}, nil
}

// ActivateROE transitions draft/pending → active and computes the resolved,
// versioned effective target list (doc 11 §3.1). Caller needs roe:activate.
func (s *Service) ActivateROE(ctx context.Context, req *gatekeeperv1.ActivateROERequest) (*gatekeeperv1.ActivateROEResponse, error) {
	r, err := s.load(ctx, req.GetRoeId(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	switch r.GetStatus() {
	case gatekeeperv1.ROEStatus_ROE_STATUS_DRAFT, gatekeeperv1.ROEStatus_ROE_STATUS_PENDING_APPROVAL,
		gatekeeperv1.ROEStatus_ROE_STATUS_SUSPENDED:
	default:
		return nil, fmt.Errorf("roe: cannot activate from status %s", statusFromProto[r.GetStatus()])
	}
	if err := validateHardRules(r); err != nil {
		return nil, err
	}
	if err := s.verifyGRC(ctx, r); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if now.Before(r.GetValidFrom().AsTime()) {
		return nil, errors.New("roe: validity window has not opened yet")
	}
	if !now.Before(r.GetValidUntil().AsTime()) {
		return nil, errors.New("roe: validity window has closed; create a new version to renew")
	}
	if err := s.setStatus(ctx, r, statusActive); err != nil {
		return nil, err
	}
	if err := s.resolveTargets(ctx, r); err != nil {
		return nil, err
	}
	s.recordEvent(ctx, r, audit.KindROEActivated, nil)
	s.publishEvent(ctx, "ROE_ACTIVATED", r)
	return &gatekeeperv1.ActivateROEResponse{Roe: r}, nil
}

// SuspendROE halts an active RoE (operator/GRC).
func (s *Service) SuspendROE(ctx context.Context, req *gatekeeperv1.SuspendROERequest) (*gatekeeperv1.SuspendROEResponse, error) {
	r, err := s.load(ctx, req.GetRoeId(), 0)
	if err != nil {
		return nil, err
	}
	if r.GetStatus() != gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE {
		return nil, fmt.Errorf("roe: only active records can be suspended (status %s)", statusFromProto[r.GetStatus()])
	}
	if err := s.setStatus(ctx, r, statusSuspended); err != nil {
		return nil, err
	}
	s.recordEvent(ctx, r, audit.KindROESuspended, map[string]any{"reason": req.GetReason()})
	s.publishEvent(ctx, "ROE_SUSPENDED", r)
	return &gatekeeperv1.SuspendROEResponse{Roe: r}, nil
}

// RevokeROE permanently revokes an RoE and issues a RoE-scoped revocation
// (kills in-flight tasks under it — doc 01 §10.5, doc 11 §2.3).
func (s *Service) RevokeROE(ctx context.Context, req *gatekeeperv1.RevokeROERequest) (*gatekeeperv1.RevokeROEResponse, error) {
	r, err := s.load(ctx, req.GetRoeId(), 0)
	if err != nil {
		return nil, err
	}
	if r.GetStatus() == gatekeeperv1.ROEStatus_ROE_STATUS_REVOKED {
		return &gatekeeperv1.RevokeROEResponse{Roe: r}, nil // idempotent
	}
	if err := s.setStatus(ctx, r, statusRevoked); err != nil {
		return nil, err
	}
	s.recordEvent(ctx, r, audit.KindROERevoked, map[string]any{"reason": req.GetReason()})
	s.publishEvent(ctx, "ROE_REVOKED", r)
	if s.revoke != nil {
		if err := s.revoke.IssueROERevocation(ctx, r.GetRoeId(), "gatekeeper.roe-service", req.GetReason()); err != nil {
			// The status change is durable; log-and-continue keeps revoke
			// non-blocking — policy also denies on status alone (step 3).
			fmt.Printf("roe: WARNING revocation broadcast for %s failed: %v\n", r.GetRoeId(), err)
		}
	}
	return &gatekeeperv1.RevokeROEResponse{Roe: r}, nil
}

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------

func (s *Service) insert(ctx context.Context, r *gatekeeperv1.RulesOfEngagement) error {
	la, err := protoNames.Marshal(r.GetLegalArtifact())
	if err != nil {
		return err
	}
	ab, err := protoNames.Marshal(r.GetAuthorizedBy())
	if err != nil {
		return err
	}
	var ap []byte
	if r.GetApprovedByOperator() != nil {
		if ap, err = protoNames.Marshal(r.GetApprovedByOperator()); err != nil {
			return err
		}
	}
	sc, err := protoNames.Marshal(r.GetScope())
	if err != nil {
		return err
	}
	cs, err := protoNames.Marshal(r.GetConstraints())
	if err != nil {
		return err
	}
	_, err = s.db.Pool.Exec(ctx, `
		INSERT INTO roe_records
		  (roe_id, version, org_id, name, status, created_by, legal_artifact, authorized_by,
		   approved_by, scope, constraints, valid_from, valid_until, signature, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10::jsonb,$11::jsonb,$12,$13,$14,$15)`,
		r.GetRoeId(), int(r.GetVersion()), r.GetOrgId(), r.GetName(),
		statusFromProto[r.GetStatus()], r.GetCreatedBy(),
		nullIfEmptyJSON(la), string(ab), nullIfEmptyJSON(ap), string(sc), string(cs),
		r.GetValidFrom().AsTime(), r.GetValidUntil().AsTime(), r.GetSignature(), r.GetUpdatedAt().AsTime())
	if err != nil {
		return fmt.Errorf("roe: insert: %w", err)
	}
	return nil
}

func nullIfEmptyJSON(b []byte) any {
	if len(b) == 0 || string(b) == "null" {
		return nil
	}
	return string(b)
}

// load fetches version (0 = latest).
func (s *Service) load(ctx context.Context, roeID string, version uint64) (*gatekeeperv1.RulesOfEngagement, error) {
	if roeID == "" {
		return nil, errors.New("roe: roe_id is required")
	}
	q := `
		SELECT roe_id, version, org_id, name, status, created_by,
		       legal_artifact, authorized_by, approved_by, scope, constraints,
		       valid_from, valid_until, signature, updated_at
		FROM roe_records WHERE roe_id = $1`
	args := []any{roeID}
	if version > 0 {
		q += ` AND version = $2`
		args = append(args, int(version))
	}
	q += ` ORDER BY version DESC LIMIT 1`
	rows, err := s.db.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("roe: load: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return nil, err
		}
		return nil, pgx.ErrNoRows
	}
	return scanROE(rows)
}

type rowScanner interface{ Scan(dest ...any) error }

func scanROE(rows rowScanner) (*gatekeeperv1.RulesOfEngagement, error) {
	var (
		r                            gatekeeperv1.RulesOfEngagement
		version                      int
		status, sig                  string
		la, ab, ap, sc, cs           []byte
		validFrom, validUntil, updAt time.Time
	)
	err := rows.Scan(&r.RoeId, &version, &r.OrgId, &r.Name, &status, &r.CreatedBy,
		&la, &ab, &ap, &sc, &cs, &validFrom, &validUntil, &sig, &updAt)
	if err != nil {
		return nil, fmt.Errorf("roe: scan: %w", err)
	}
	r.Version = uint64(version)
	r.Status = statusToProto[status]
	r.Signature = sig
	r.ValidFrom = timestamppb.New(validFrom)
	r.ValidUntil = timestamppb.New(validUntil)
	r.UpdatedAt = timestamppb.New(updAt)
	if len(la) > 0 {
		r.LegalArtifact = &gatekeeperv1.LegalArtifact{}
		if err := protojson.Unmarshal(la, r.LegalArtifact); err != nil {
			return nil, fmt.Errorf("roe: legal_artifact: %w", err)
		}
	}
	if len(ab) > 0 {
		r.AuthorizedBy = &gatekeeperv1.Attestation{}
		if err := protojson.Unmarshal(ab, r.AuthorizedBy); err != nil {
			return nil, fmt.Errorf("roe: authorized_by: %w", err)
		}
	}
	if len(ap) > 0 {
		r.ApprovedByOperator = &gatekeeperv1.Attestation{}
		if err := protojson.Unmarshal(ap, r.ApprovedByOperator); err != nil {
			return nil, fmt.Errorf("roe: approved_by: %w", err)
		}
	}
	r.Scope = &gatekeeperv1.Scope{}
	if err := protojson.Unmarshal(sc, r.Scope); err != nil {
		return nil, fmt.Errorf("roe: scope: %w", err)
	}
	r.Constraints = &gatekeeperv1.Constraints{}
	if len(cs) > 0 {
		if err := protojson.Unmarshal(cs, r.Constraints); err != nil {
			return nil, fmt.Errorf("roe: constraints: %w", err)
		}
	}
	return &r, nil
}

func (s *Service) setStatus(ctx context.Context, r *gatekeeperv1.RulesOfEngagement, status string) error {
	tag, err := s.db.Pool.Exec(ctx,
		`UPDATE roe_records SET status = $3 WHERE roe_id = $1 AND version = $2`,
		r.GetRoeId(), int(r.GetVersion()), status)
	if err != nil {
		return fmt.Errorf("roe: set status %s: %w", status, err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	r.Status = statusToProto[status]
	r.UpdatedAt = timestamppb.New(s.now().UTC())
	return nil
}

// lazyExpire transitions an active RoE past its window to expired.
func (s *Service) lazyExpire(ctx context.Context, r *gatekeeperv1.RulesOfEngagement) (*gatekeeperv1.RulesOfEngagement, error) {
	if r.GetStatus() == gatekeeperv1.ROEStatus_ROE_STATUS_ACTIVE &&
		!s.now().UTC().Before(r.GetValidUntil().AsTime()) {
		if err := s.setStatus(ctx, r, statusExpired); err != nil {
			return nil, err
		}
		s.recordEvent(ctx, r, "roe.expired", nil)
		s.publishEvent(ctx, "ROE_EXPIRED", r)
	}
	return r, nil
}

// ExpireDue transitions every active RoE whose window has closed to expired,
// publishing roe.events.v1 (background sweep; reads also expire lazily).
// Returns the number expired.
func (s *Service) ExpireDue(ctx context.Context) (int, error) {
	rows, err := s.db.Pool.Query(ctx,
		`SELECT roe_id FROM roe_records WHERE status = 'active' AND valid_until <= now()`)
	if err != nil {
		return 0, fmt.Errorf("roe: expiry sweep: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return 0, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, id := range ids {
		if _, err := s.GetROE(ctx, &gatekeeperv1.GetROERequest{RoeId: id}); err != nil {
			return n, fmt.Errorf("roe: expire %s: %w", id, err)
		}
		n++
	}
	return n, nil
}

// resolveTargets writes the resolved effective target list for the activated
// version (doc 11 §3.1). At Phase 0, domains/CIDRs/excludes are expanded
// directly from the declared scope; asset-group expansion against module
// 09's inventory lands when data-platform does (asset_group rows keep the
// reference until then).
func (s *Service) resolveTargets(ctx context.Context, r *gatekeeperv1.RulesOfEngagement) error {
	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx,
		`DELETE FROM roe_effective_targets WHERE roe_id = $1 AND roe_version = $2`,
		r.GetRoeId(), int(r.GetVersion())); err != nil {
		return fmt.Errorf("roe: clear targets: %w", err)
	}
	type row struct{ target, kind string }
	var rows []row
	sc := r.GetScope()
	for _, d := range sc.GetDomains() {
		rows = append(rows, row{d, "domain"})
	}
	for _, c := range sc.GetCidrs() {
		rows = append(rows, row{c, "cidr"})
	}
	for _, g := range sc.GetAssetGroupIds() {
		rows = append(rows, row{g, "asset_group"})
	}
	for _, c := range sc.GetCloudAccounts() {
		rows = append(rows, row{c, "cloud_account"})
	}
	for _, rr := range rows {
		if _, err := tx.Exec(ctx, `
			INSERT INTO roe_effective_targets (roe_id, roe_version, target, target_kind, excluded)
			VALUES ($1,$2,$3,$4,false)
			ON CONFLICT (roe_id, roe_version, target) DO NOTHING`,
			r.GetRoeId(), int(r.GetVersion()), rr.target, rr.kind); err != nil {
			return fmt.Errorf("roe: insert target: %w", err)
		}
	}
	for _, ex := range sc.GetExplicitExcludes() {
		kind := "host"
		if strings.Contains(ex, "/") {
			kind = "cidr"
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO roe_effective_targets (roe_id, roe_version, target, target_kind, excluded)
			VALUES ($1,$2,$3,$4,true)
			ON CONFLICT (roe_id, roe_version, target) DO UPDATE SET excluded = true`,
			r.GetRoeId(), int(r.GetVersion()), ex, kind); err != nil {
			return fmt.Errorf("roe: insert exclude: %w", err)
		}
	}
	return tx.Commit(ctx)
}

// EffectiveTargets returns the resolved include/exclude lists for a version.
func (s *Service) EffectiveTargets(ctx context.Context, roeID string, version uint64) (includes, excludes []string, err error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT target, excluded FROM roe_effective_targets
		WHERE roe_id = $1 AND roe_version = $2`, roeID, int(version))
	if err != nil {
		return nil, nil, fmt.Errorf("roe: effective targets: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var t string
		var ex bool
		if err := rows.Scan(&t, &ex); err != nil {
			return nil, nil, err
		}
		if ex {
			excludes = append(excludes, t)
		} else {
			includes = append(includes, t)
		}
	}
	return includes, excludes, rows.Err()
}

func (s *Service) recordEvent(ctx context.Context, r *gatekeeperv1.RulesOfEngagement, kind string, extra map[string]any) {
	payload := map[string]any{
		"roe_id":   r.GetRoeId(),
		"version":  r.GetVersion(),
		"org_id":   r.GetOrgId(),
		"name":     r.GetName(),
		"status":   statusFromProto[r.GetStatus()],
		"max_risk": r.GetConstraints().GetMaxRiskClass().String(),
	}
	for k, v := range extra {
		payload[k] = v
	}
	// RoE lifecycle events are R0-class control-plane events: record
	// best-effort, never block the operation on audit lag (doc 11 §2.2:
	// audit-gating applies to R1–R3 execution decisions).
	if _, err := s.audit.Record(ctx, audit.Input{
		OrgID:   r.GetOrgId(),
		Kind:    kind,
		Actor:   map[string]any{"kind": "user", "id": r.GetCreatedBy()},
		Subject: map[string]any{"roe_id": r.GetRoeId()},
		Payload: payload,
	}); err != nil {
		fmt.Printf("roe: WARNING audit record %s for %s failed: %v\n", kind, r.GetRoeId(), err)
	}
}

func (s *Service) publishEvent(ctx context.Context, event string, r *gatekeeperv1.RulesOfEngagement) {
	// roe.events.v1 carries the full RoE record (all modules consume it via
	// PEP caches, doc 11 §2.3); the bus Envelope type names the payload.
	if err := s.pub.Publish(ctx, bus.SubjectROEEvents, r); err != nil {
		fmt.Printf("roe: WARNING publish %s for %s failed: %v\n", event, r.GetRoeId(), err)
	}
}
