// Package revocation implements revocation-service (doc 11 §2.1.7/§7, Ruling
// C11): the platform kill switch. Scopes: global / RoE / target / capability
// (token-scope revocation is token-service's RevokeToken, which also lands in
// this set). Every revocation is broadcast on tasks.revocations.v1 — PEPs
// must ACK and halt in-flight work ≤ 5 s.
package revocation

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/rbac"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
)

var scopeToProto = map[string]gatekeeperv1.RevocationScope{
	"global":     gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL,
	"roe":        gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE,
	"target":     gatekeeperv1.RevocationScope_REVOCATION_SCOPE_TARGET,
	"capability": gatekeeperv1.RevocationScope_REVOCATION_SCOPE_CAPABILITY,
}

var scopeFromProto = map[gatekeeperv1.RevocationScope]string{
	gatekeeperv1.RevocationScope_REVOCATION_SCOPE_GLOBAL:     "global",
	gatekeeperv1.RevocationScope_REVOCATION_SCOPE_ROE:        "roe",
	gatekeeperv1.RevocationScope_REVOCATION_SCOPE_TARGET:     "target",
	gatekeeperv1.RevocationScope_REVOCATION_SCOPE_CAPABILITY: "capability",
}

// Record is one active revocation (internal view; includes the token/agent
// scopes the DB CHECK allows beyond the gRPC enum).
type Record struct {
	RevocationID string
	Scope        string // global|roe|target|capability|token|agent
	ScopeValue   string
	IssuedBy     string
	Reason       string
	IssuedAt     time.Time
	ExpiresAt    *time.Time
}

// Service implements gatekeeper.v1.RevocationService and the revocation-set
// view consulted by policy-service (pipeline step 2).
type Service struct {
	gatekeeperv1.UnimplementedRevocationServiceServer
	db   *store.DB
	rbac *rbac.Service
	aud  *audit.Service
	pub  bus.Publisher
	now  func() time.Time

	// expiries tracks the proto's optional expires_at. Migration 000002 has no
	// expiry column (db/ is owned by the migrations task), so expiry is
	// held in-process: after a restart a previously-expiring revocation is
	// treated as permanent-until-lifted — the FAIL-SAFE direction for a kill
	// switch. Documented deviation.
	mu       sync.RWMutex
	expiries map[string]time.Time
}

// New builds the service.
func New(db *store.DB, rbacSvc *rbac.Service, auditSvc *audit.Service, pub bus.Publisher) *Service {
	return &Service{db: db, rbac: rbacSvc, aud: auditSvc, pub: pub, now: time.Now, expiries: map[string]time.Time{}}
}

// Revoke issues a revocation (RBAC: revocation:issue) and broadcasts it on
// tasks.revocations.v1. BreakGlass is human-only — commanders cannot freeze
// the fleet (Ruling C11), so service principals are rejected here.
func (s *Service) Revoke(ctx context.Context, req *gatekeeperv1.RevokeRequest) (*gatekeeperv1.RevokeResponse, error) {
	scope, ok := scopeFromProto[req.GetScope()]
	if !ok {
		return nil, fmt.Errorf("revocation: scope must be global|roe|target|capability")
	}
	if scope != "global" && req.GetKey() == "" {
		return nil, fmt.Errorf("revocation: key is required for %s scope", scope)
	}
	if req.GetIssuedBy() == "" {
		return nil, errors.New("revocation: issued_by is required")
	}
	if rbac.PrincipalKindOf(req.GetIssuedBy()) != "human" {
		return nil, fmt.Errorf("revocation: kill switch is human-only (Ruling C11); %q is a service principal", req.GetIssuedBy())
	}
	if err := s.rbac.RequirePermission(ctx, "", req.GetIssuedBy(), "revocation:issue"); err != nil {
		return nil, err
	}
	var expiresAt time.Time
	if ts := req.GetExpiresAt(); ts != nil {
		expiresAt = ts.AsTime() // nil-safe: nil.AsTime() would be 1970, not unset
	}
	rec, err := s.Issue(ctx, scope, req.GetKey(), req.GetIssuedBy(), req.GetReason(), expiresAt)
	if err != nil {
		return nil, err
	}
	return &gatekeeperv1.RevokeResponse{Revocation: rec.toProto()}, nil
}

// Issue records + broadcasts a revocation without an RBAC check (internal
// callers: token-service RevokeToken, roe-service RevokeROE).
func (s *Service) Issue(ctx context.Context, scope, key, issuedBy, reason string, expiresAt time.Time) (*Record, error) {
	rec := &Record{
		RevocationID: ids.New("rev"),
		Scope:        scope,
		ScopeValue:   key,
		IssuedBy:     issuedBy,
		Reason:       reason,
		IssuedAt:     s.now().UTC(),
	}
	// expiresAt zero (or already past at issue time) means "until lifted".
	if !expiresAt.IsZero() && expiresAt.After(rec.IssuedAt) {
		t := expiresAt.UTC()
		rec.ExpiresAt = &t
	}
	if _, err := s.db.Pool.Exec(ctx, `
		INSERT INTO revocations (revocation_id, scope, scope_value, issued_by, reason, issued_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		rec.RevocationID, rec.Scope, rec.ScopeValue, rec.IssuedBy, rec.Reason, rec.IssuedAt); err != nil {
		return nil, fmt.Errorf("revocation: insert: %w", err)
	}
	if rec.ExpiresAt != nil {
		s.mu.Lock()
		s.expiries[rec.RevocationID] = *rec.ExpiresAt
		s.mu.Unlock()
	}
	// Audit is part of the kill-switch contract (revocation.issued) but must
	// not delay propagation: broadcast first, then record.
	if err := s.pub.Publish(ctx, bus.SubjectRevocations, &gatekeeperv1.RevocationEvent{
		Revocation: rec.toProto(),
		Ts:         timestamppb.New(s.now().UTC()),
	}); err != nil {
		// The DB row is the set of record consulted by policy (step 2), so a
		// publish failure degrades PEP propagation, not correctness at the PDP.
		fmt.Printf("revocation: WARNING broadcast %s failed: %v\n", rec.RevocationID, err)
	}
	if _, err := s.aud.Record(ctx, audit.Input{
		Kind:  audit.KindRevocationIssued,
		Actor: map[string]any{"kind": "user", "id": issuedBy},
		Payload: map[string]any{
			"revocation_id": rec.RevocationID,
			"scope":         rec.Scope,
			"scope_value":   rec.ScopeValue,
			"reason":        rec.Reason,
		},
	}); err != nil {
		fmt.Printf("revocation: WARNING audit record %s failed: %v\n", rec.RevocationID, err)
	}
	return rec, nil
}

// IssueROERevocation implements roe.RevocationIssuer.
func (s *Service) IssueROERevocation(ctx context.Context, roeID, issuedBy, reason string) error {
	_, err := s.Issue(ctx, "roe", roeID, issuedBy, reason, time.Time{})
	return err
}

// ListRevocations returns the active set (optionally filtered).
func (s *Service) ListRevocations(ctx context.Context, req *gatekeeperv1.ListRevocationsRequest) (*gatekeeperv1.ListRevocationsResponse, error) {
	recs, err := s.Active(ctx)
	if err != nil {
		return nil, err
	}
	resp := &gatekeeperv1.ListRevocationsResponse{}
	for _, r := range recs {
		if req.GetScope() != gatekeeperv1.RevocationScope_REVOCATION_SCOPE_UNSPECIFIED &&
			scopeFromProto[req.GetScope()] != r.Scope {
			continue
		}
		if req.GetKey() != "" && req.GetKey() != r.ScopeValue {
			continue
		}
		if p := r.toProto(); p != nil {
			resp.Revocations = append(resp.Revocations, p)
		}
	}
	return resp, nil
}

// Active returns the current revocation set (lifted and in-process-expired
// entries excluded).
func (s *Service) Active(ctx context.Context) ([]*Record, error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT revocation_id, scope, scope_value, issued_by, reason, issued_at
		FROM revocations WHERE lifted_at IS NULL ORDER BY issued_at`)
	if err != nil {
		return nil, fmt.Errorf("revocation: active set: %w", err)
	}
	defer rows.Close()
	var out []*Record
	for rows.Next() {
		var r Record
		if err := rows.Scan(&r.RevocationID, &r.Scope, &r.ScopeValue, &r.IssuedBy, &r.Reason, &r.IssuedAt); err != nil {
			return nil, err
		}
		out = append(out, &r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := s.now().UTC()
	filtered := out[:0]
	for _, r := range out {
		if exp, ok := s.expiries[r.RevocationID]; ok {
			if !now.Before(exp) {
				continue // expired in-process
			}
			e := exp
			r.ExpiresAt = &e
		}
		filtered = append(filtered, r)
	}
	return filtered, nil
}

// IsRevoked reports whether (scope, value) is actively revoked. Scope ""
// matches any scope with the given value.
func (s *Service) IsRevoked(ctx context.Context, scope, value string) (bool, error) {
	recs, err := s.Active(ctx)
	if err != nil {
		return false, err
	}
	for _, r := range recs {
		if (scope == "" || r.Scope == scope) && r.ScopeValue == value {
			return true, nil
		}
	}
	return false, nil
}

// IsGloballyRevoked reports whether a global revocation is active.
func (s *Service) IsGloballyRevoked(ctx context.Context) (bool, error) {
	return s.IsRevoked(ctx, "global", "")
}

func (r *Record) toProto() *gatekeeperv1.Revocation {
	scope, ok := scopeToProto[r.Scope]
	if !ok {
		return nil // token/agent scopes are not on the gRPC enum
	}
	p := &gatekeeperv1.Revocation{
		RevocationId: r.RevocationID,
		Scope:        scope,
		Key:          r.ScopeValue,
		IssuedBy:     r.IssuedBy,
		IssuedAt:     timestamppb.New(r.IssuedAt),
		Reason:       r.Reason,
	}
	if r.ExpiresAt != nil {
		p.ExpiresAt = timestamppb.New(*r.ExpiresAt)
	}
	return p
}
