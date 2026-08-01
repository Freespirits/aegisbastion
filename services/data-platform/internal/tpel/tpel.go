// Package tpel is the Tenancy & Policy Enforcement Layer (doc 09 §2.1/§2.3):
// tenant resolution from the caller's credential (NEVER from the payload),
// context injection, and the fail-closed guarantee that every query and
// write carries exactly one resolved tenant_id. Cross-tenant access is
// structurally impossible (doc 09 §9.6), not policy-dependent.
//
// MVP credential model (mirrors platform-core's X-Operator-Id shim): the
// caller presents its principal via the X-DP-Principal header; TPEL resolves
// the tenant set from tenancy.grants. A principal with grants in exactly one
// tenant is bound to it; with several, the caller must select one it holds
// via the X-DP-Tenant header. Everything else is rejected. Real caller
// authentication (OIDC/mTLS) is the dashboard/edge PEP's concern (doc 10,
// doc 12); dp grants govern dp data access only (doc 09 §4.3).
package tpel

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/problem"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
)

// Headers of the MVP credential shim.
const (
	// PrincipalHeader carries the caller identity (service name, user sub,
	// commander id) — matched against tenancy.grants.principal.
	PrincipalHeader = "X-DP-Principal"
	// TenantHeader selects among a principal's several tenant grants.
	TenantHeader = "X-DP-Tenant"
)

// Identity is the resolved caller context injected by TPEL.
type Identity struct {
	Principal string
	TenantID  string
	Role      string
}

// Actor renders the identity as a data-access audit actor (doc 09 §4.4).
func (id Identity) Actor() store.Actor {
	kind := "service"
	switch id.Role {
	case "admin", "analyst", "viewer":
		kind = "human"
	case "commander":
		kind = "commander"
	}
	return store.Actor{Type: kind, ID: id.Principal}
}

type ctxKey struct{}

// WithIdentity attaches the resolved identity.
func WithIdentity(ctx context.Context, id Identity) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the resolved identity (fail-closed when absent).
func FromContext(ctx context.Context) (Identity, bool) {
	id, ok := ctx.Value(ctxKey{}).(Identity)
	return id, ok
}

// GrantStore is the tenancy lookup the resolver needs.
type GrantStore interface {
	GrantsForPrincipal(ctx context.Context, principal string) ([]*store.Grant, error)
}

// Resolver turns request credentials into a tenant-bound Identity.
type Resolver struct {
	grants GrantStore
}

// NewResolver builds a Resolver.
func NewResolver(g GrantStore) *Resolver { return &Resolver{grants: g} }

// Resolve maps (principal, tenantHint) → Identity. Fail-closed:
//   - unknown principal            → GRANT_REQUIRED
//   - several tenants, no hint     → TENANT_MISMATCH (selection required)
//   - hint not among grants        → TENANT_MISMATCH
func (r *Resolver) Resolve(ctx context.Context, principal, tenantHint string) (Identity, *problem.Problem) {
	if principal == "" {
		return Identity{}, problem.NoGrant("missing " + PrincipalHeader + " header")
	}
	grants, err := r.grants.GrantsForPrincipal(ctx, principal)
	if err != nil {
		return Identity{}, problem.Internal("grant lookup: " + err.Error())
	}
	if len(grants) == 0 {
		return Identity{}, problem.NoGrant(fmt.Sprintf("principal %q holds no data-platform grant", principal))
	}
	if tenantHint != "" {
		for _, g := range grants {
			if g.TenantID == tenantHint {
				return Identity{Principal: principal, TenantID: g.TenantID, Role: g.Role}, nil
			}
		}
		return Identity{}, problem.Mismatch(fmt.Sprintf(
			"principal %q holds no grant for tenant %s", principal, tenantHint))
	}
	// No hint: single tenant binds implicitly; otherwise selection required.
	tenant := grants[0].TenantID
	role := grants[0].Role
	for _, g := range grants[1:] {
		if g.TenantID != tenant {
			return Identity{}, problem.Mismatch(fmt.Sprintf(
				"principal %q holds grants in several tenants; select one via %s", principal, TenantHeader))
		}
		if g.Role == "admin" {
			role = g.Role // strongest role within the same tenant wins
		}
	}
	return Identity{Principal: principal, TenantID: tenant, Role: role}, nil
}

// Middleware resolves TPEL identity for every request and injects it into
// the context. next receives only requests with a valid identity.
func (r *Resolver) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		id, prob := r.Resolve(req.Context(), req.Header.Get(PrincipalHeader), req.Header.Get(TenantHeader))
		if prob != nil {
			problem.Write(w, prob)
			return
		}
		next.ServeHTTP(w, req.WithContext(WithIdentity(req.Context(), id)))
	})
}

// ErrNoIdentity is returned when a resolver runs without TPEL context
// (defense in depth below the middleware).
var ErrNoIdentity = errors.New("tpel: no tenant identity in context (fail-closed)")

// MustIdentity extracts the identity or panics-free error for resolvers.
func MustIdentity(ctx context.Context) (Identity, error) {
	id, ok := FromContext(ctx)
	if !ok || id.TenantID == "" {
		return Identity{}, ErrNoIdentity
	}
	return id, nil
}
