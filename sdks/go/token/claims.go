package token

import (
	"fmt"
	"time"
)

// Claims is the Authorization Token v1.1 claim set (doc 01 §5.5 as amended by
// Ruling A, converged with doc 11 §3.2). JSON tags are the exact JWT claim
// names — the same names as schemas/gatekeeper/v1/scope-token-claims.schema.json
// and proto aegisbastion.gatekeeper.v1.ScopeTokenClaims.
type Claims struct {
	Issuer       string            `json:"iss"`
	Audience     string            `json:"aud"`
	ID           string            `json:"jti"` // "tok_…"; AlertEvent v1 authorization_token_id
	Subject      string            `json:"sub"` // executing agent/workload
	TaskID       string            `json:"task_id"`
	ROEID        string            `json:"roe_id"`
	ROEVersion   uint64            `json:"roe_version"`
	RiskClass    string            `json:"risk_class"` // "R1" | "R2" | "R3"
	Capabilities []string          `json:"capabilities"`
	Targets      TargetManifestRef `json:"targets"`
	ScopeBound   bool              `json:"scope_bound"`
	RateCaps     *RateCaps         `json:"rate_caps,omitempty"`
	ApprovalID   string            `json:"approval_id,omitempty"`
	IssuedAt     int64             `json:"iat"`
	NotBefore    int64             `json:"nbf"`
	ExpiresAt    int64             `json:"exp"`
}

// TargetManifestRef points at the hashed manifest holding the concrete targets
// (exact-enumerated form) or the canonical scope document (scope-bound form).
// For scope-bound watch tokens ManifestSHA256 IS the "scope:sha256:<hash>"
// audit value (Ruling A.3).
type TargetManifestRef struct {
	HashAlg        string `json:"hash_alg"`
	ManifestURI    string `json:"manifest_uri"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Count          uint32 `json:"count,omitempty"`
}

// RateCaps are the self-contained rate caps the PEP enforces per burst — the
// token is NOT a capability to bypass rate limits (doc 11 §3.2). max_rps
// (doc 01 spelling) ≡ rps (doc 11 spelling): one claim set.
type RateCaps struct {
	MaxRPS        uint32 `json:"max_rps,omitempty"`
	MaxConcurrent uint32 `json:"max_concurrent,omitempty"`
}

// Expiry returns the token expiry as a time.Time.
func (c *Claims) Expiry() time.Time { return time.Unix(c.ExpiresAt, 0).UTC() }

// ValidAt re-checks the time bounds of already-verified claims — used by the
// PEP before every target contact so an expiring token halts work even
// between verifications (doc 11 §7: modules halt when the token expires).
func (c *Claims) ValidAt(now time.Time) error {
	unix := now.Unix()
	if unix > c.ExpiresAt+int64(Leeway/time.Second) {
		return fmt.Errorf("%w: exp=%d now=%d", ErrExpired, c.ExpiresAt, unix)
	}
	if unix+int64(Leeway/time.Second) < c.NotBefore {
		return fmt.Errorf("%w: nbf=%d now=%d", ErrNotYetValid, c.NotBefore, unix)
	}
	return nil
}

// Permits reports whether the token authorizes the given capability.
func (c *Claims) Permits(capability string) bool {
	for _, cap := range c.Capabilities {
		if cap == capability {
			return true
		}
	}
	return false
}

// validateChecks runs the claim-level (post-signature) checks. now is
// injectable for tests.
func (c *Claims) validate(now time.Time) error {
	if c.Issuer != Issuer {
		return fmt.Errorf("%w: got %q", ErrIssuer, c.Issuer)
	}
	if c.Audience != Audience {
		return fmt.Errorf("%w: got %q", ErrAudience, c.Audience)
	}
	for name, ok := range map[string]bool{
		"jti":     c.ID != "",
		"sub":     c.Subject != "",
		"task_id": c.TaskID != "",
		"roe_id":  c.ROEID != "",
	} {
		if !ok {
			return fmt.Errorf("%w: %s", ErrMissingClaim, name)
		}
	}
	if c.ROEVersion < 1 {
		return fmt.Errorf("%w: roe_version must be >= 1", ErrMissingClaim)
	}
	if len(c.Capabilities) == 0 {
		return fmt.Errorf("%w: capabilities", ErrMissingClaim)
	}
	switch c.RiskClass {
	case "R1", "R2", "R3":
	default:
		return fmt.Errorf("%w: got %q", ErrRiskClass, c.RiskClass)
	}
	if c.Targets.HashAlg != "sha256" {
		return fmt.Errorf("%w: targets.hash_alg must be sha256, got %q", ErrMissingClaim, c.Targets.HashAlg)
	}
	if c.Targets.ManifestURI == "" || c.Targets.ManifestSHA256 == "" {
		return fmt.Errorf("%w: targets.manifest_uri / targets.manifest_sha256", ErrMissingClaim)
	}
	if c.ExpiresAt <= c.IssuedAt {
		return fmt.Errorf("%w: exp must be after iat", ErrMalformed)
	}
	if c.ExpiresAt-c.IssuedAt > MaxTTLSecs {
		return fmt.Errorf("%w: exp-iat=%d s, max %d s", ErrTTL, c.ExpiresAt-c.IssuedAt, MaxTTLSecs)
	}
	if err := c.ValidAt(now); err != nil {
		return err
	}
	unix := now.Unix()
	if c.IssuedAt-unix > int64(MaxClockSkew/time.Second) {
		return fmt.Errorf("%w: iat=%d now=%d", ErrClockSkew, c.IssuedAt, unix)
	}
	if c.ScopeBound {
		if c.RiskClass != "R1" {
			return fmt.Errorf("%w: scope_bound requires R1, got %s", ErrScopeBound, c.RiskClass)
		}
		for _, cap := range c.Capabilities {
			ok := false
			for _, allowed := range ScopeBoundCapabilities {
				if cap == allowed {
					ok = true
					break
				}
			}
			if !ok {
				return fmt.Errorf("%w: capability %q is not monitor.watch/monitor.rescan", ErrScopeBound, cap)
			}
		}
	}
	if c.RiskClass == "R3" && c.ApprovalID == "" {
		return ErrApproval
	}
	return nil
}
