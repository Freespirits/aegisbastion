// Package rbac implements rbac-service (doc 11 §3.5): the fixed v1 role set
// (seeded by migration 000002), time-boxed grants, and segregation-of-duties
// enforcement. There is no gRPC surface in gatekeeper.v1 for RBAC — it is an
// internal service consumed by the other gatekeeper services, plus admin REST
// endpoints for grant management.
package rbac

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
)

// The fixed v1 role set (migration 000002 seeds these; doc 11 §3.5).
const (
	RolePlatformAdmin     = "platform-admin"
	RoleGRCVerifier       = "grc-verifier"
	RoleROEAuthor         = "roe-author"
	RoleOffensiveApprover = "offensive-approver"
	RoleCommanderSvc      = "commander-svc"
	RoleModuleSvc         = "module-svc"
	RoleAuditor           = "auditor"
	RoleOperator          = "operator"
)

// writeRoles is every role carrying any write permission (for the auditor
// exclusivity rule).
var writeRoles = map[string]bool{
	RolePlatformAdmin:     true,
	RoleGRCVerifier:       true, // legal:verify is a write action
	RoleROEAuthor:         true,
	RoleOffensiveApprover: true,
	RoleCommanderSvc:      true,
	RoleModuleSvc:         true,
	RoleOperator:          true,
}

// approvalRoles grant approval/verification permissions — service accounts
// may never hold these (doc 11 §3.5).
var approvalRoles = map[string]bool{
	RoleGRCVerifier:       true,
	RoleOffensiveApprover: true,
}

// ErrSoD marks segregation-of-duties violations.
var ErrSoD = errors.New("rbac: segregation-of-duties violation")

// Binding is one role grant.
type Binding struct {
	GrantID       string
	OrgID         string
	Principal     string
	PrincipalKind string // "human" | "service"
	Role          string
	GrantedBy     string
	GrantedAt     time.Time
	ExpiresAt     time.Time
	RevokedAt     *time.Time
}

// Service enforces RBAC against gatekeeper.rbac_roles / rbac_bindings.
type Service struct {
	db  *store.DB
	now func() time.Time
}

// New builds the service.
func New(db *store.DB) *Service { return &Service{db: db, now: time.Now} }

// HasRole reports whether principal holds an active (unexpired, unrevoked)
// grant of role in org. Platform-wide check when org is "".
func (s *Service) HasRole(ctx context.Context, org, principal, role string) (bool, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT count(*) FROM rbac_bindings
		WHERE principal = $1 AND role = $2 AND revoked_at IS NULL AND expires_at > now()
		  AND ($3 = '' OR org_id = $3)`,
		principal, role, org).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("rbac: has-role: %w", err)
	}
	return n > 0, nil
}

// HasPermission reports whether principal holds any active role carrying the
// resource:action permission (or *:*).
func (s *Service) HasPermission(ctx context.Context, org, principal, permission string) (bool, error) {
	var n int
	err := s.db.Pool.QueryRow(ctx, `
		SELECT count(*) FROM rbac_bindings b
		JOIN rbac_roles r ON r.role = b.role
		WHERE b.principal = $1 AND b.revoked_at IS NULL AND b.expires_at > now()
		  AND ($2 = '' OR b.org_id = $2)
		  AND ($3 = ANY(r.permissions) OR '*:*' = ANY(r.permissions))`,
		principal, org, permission).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("rbac: has-permission: %w", err)
	}
	return n > 0, nil
}

// RolesOf lists principal's active roles in org.
func (s *Service) RolesOf(ctx context.Context, org, principal string) ([]string, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT DISTINCT role FROM rbac_bindings
		WHERE principal = $1 AND revoked_at IS NULL AND expires_at > now()
		  AND ($2 = '' OR org_id = $2)`, principal, org)
	if err != nil {
		return nil, fmt.Errorf("rbac: roles-of: %w", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// Grant assigns a role with SoD enforcement (doc 11 §3.5):
//   - no human may hold both roe-author and offensive-approver for the same org
//   - service accounts cannot hold approval/verification roles
//   - auditor is strictly read-only and cannot combine with any write role
//
// Grants are time-boxed (default 90 days, auto-expire).
func (s *Service) Grant(ctx context.Context, b Binding) (*Binding, error) {
	if b.Principal == "" || b.Role == "" || b.OrgID == "" {
		return nil, fmt.Errorf("rbac: org, principal and role are required")
	}
	if b.PrincipalKind == "" {
		b.PrincipalKind = "human"
	}
	if b.PrincipalKind != "human" && b.PrincipalKind != "service" {
		return nil, fmt.Errorf("rbac: principal_kind must be human|service")
	}
	if b.GrantedBy == "" {
		return nil, fmt.Errorf("rbac: granted_by is required (grants are audited)")
	}
	if b.ExpiresAt.IsZero() {
		b.ExpiresAt = s.now().Add(90 * 24 * time.Hour)
	}
	if err := s.checkSoD(ctx, b.OrgID, b.Principal, b.PrincipalKind, b.Role); err != nil {
		return nil, err
	}
	err := s.db.Pool.QueryRow(ctx, `
		INSERT INTO rbac_bindings (org_id, principal, principal_kind, role, granted_by, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (org_id, principal, role) DO UPDATE
		  SET revoked_at = NULL, granted_by = EXCLUDED.granted_by,
		      granted_at = now(), expires_at = EXCLUDED.expires_at,
		      principal_kind = EXCLUDED.principal_kind
		RETURNING grant_id, granted_at`,
		b.OrgID, b.Principal, b.PrincipalKind, b.Role, b.GrantedBy, b.ExpiresAt).
		Scan(&b.GrantID, &b.GrantedAt)
	if err != nil {
		return nil, fmt.Errorf("rbac: grant: %w", err)
	}
	return &b, nil
}

// Revoke ends a grant.
func (s *Service) Revoke(ctx context.Context, org, principal, role string) error {
	tag, err := s.db.Pool.Exec(ctx, `
		UPDATE rbac_bindings SET revoked_at = now()
		WHERE org_id = $1 AND principal = $2 AND role = $3 AND revoked_at IS NULL`,
		org, principal, role)
	if err != nil {
		return fmt.Errorf("rbac: revoke: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	return nil
}

// List returns bindings for an org (active only unless includeRevoked).
func (s *Service) List(ctx context.Context, org string, includeRevoked bool) ([]Binding, error) {
	q := `
		SELECT grant_id, org_id, principal, principal_kind, role, granted_by, granted_at, expires_at, revoked_at
		FROM rbac_bindings WHERE org_id = $1`
	if !includeRevoked {
		q += ` AND revoked_at IS NULL AND expires_at > now()`
	}
	q += ` ORDER BY principal, role`
	rows, err := s.db.Pool.Query(ctx, q, org)
	if err != nil {
		return nil, fmt.Errorf("rbac: list: %w", err)
	}
	defer rows.Close()
	var out []Binding
	for rows.Next() {
		var b Binding
		if err := rows.Scan(&b.GrantID, &b.OrgID, &b.Principal, &b.PrincipalKind, &b.Role,
			&b.GrantedBy, &b.GrantedAt, &b.ExpiresAt, &b.RevokedAt); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// checkSoD applies the doc 11 §3.5 constraints for a prospective grant.
func (s *Service) checkSoD(ctx context.Context, org, principal, kind, role string) error {
	// Service accounts cannot hold approval/verification permissions.
	if kind == "service" && approvalRoles[role] {
		return fmt.Errorf("%w: service accounts cannot hold %s", ErrSoD, role)
	}
	active, err := s.RolesOf(ctx, org, principal)
	if err != nil {
		return err
	}
	has := func(r string) bool {
		for _, a := range active {
			if a == r {
				return true
			}
		}
		return false
	}
	// No human may hold both roe-author and offensive-approver for the same org.
	if kind == "human" {
		if role == RoleOffensiveApprover && has(RoleROEAuthor) {
			return fmt.Errorf("%w: %s already holds %s in %s", ErrSoD, principal, RoleROEAuthor, org)
		}
		if role == RoleROEAuthor && has(RoleOffensiveApprover) {
			return fmt.Errorf("%w: %s already holds %s in %s", ErrSoD, principal, RoleOffensiveApprover, org)
		}
	}
	// auditor is strictly read-only and cannot be combined with any write role.
	if role == RoleAuditor {
		for _, a := range active {
			if writeRoles[a] {
				return fmt.Errorf("%w: auditor cannot combine with write role %s", ErrSoD, a)
			}
		}
	}
	if writeRoles[role] && has(RoleAuditor) {
		return fmt.Errorf("%w: %s holds auditor (read-only); cannot add %s", ErrSoD, principal, role)
	}
	return nil
}

// RequirePermission returns nil when principal holds permission, else a
// descriptive error (callers map this to FORBIDDEN_ROLE / PermissionDenied).
func (s *Service) RequirePermission(ctx context.Context, org, principal, permission string) error {
	ok, err := s.HasPermission(ctx, org, principal, permission)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("rbac: %s lacks permission %q", principal, permission)
	}
	return nil
}

// PrincipalKindOf returns "human"/"service" for known principals, defaulting
// by id shape: ids with an "@" or "user_" prefix are human; "svc-"/"agent_"
// prefixes are service.
func PrincipalKindOf(id string) string {
	if strings.Contains(id, "@") || strings.HasPrefix(id, "user_") {
		return "human"
	}
	return "service"
}
