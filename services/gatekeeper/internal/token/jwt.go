// Package token implements token-service (doc 11 §2.1.2/§3.2, doc 01 §5.5):
// the Ed25519/EdDSA Scope Token — the platform's ONLY execution credential
// (Ruling C5). JWTs are hand-rolled over crypto/ed25519 (header.payload.sig)
// so the claim set is byte-exact against
// schemas/gatekeeper/v1/scope-token-claims.schema.json.
package token

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// claimsJSON is the exact JWT payload shape (schema: scope-token-claims).
type claimsJSON struct {
	Iss          string          `json:"iss"`
	Aud          string          `json:"aud"`
	Jti          string          `json:"jti"`
	Sub          string          `json:"sub"`
	TaskID       string          `json:"task_id"`
	RoeID        string          `json:"roe_id"`
	RoeVersion   uint64          `json:"roe_version"`
	RiskClass    string          `json:"risk_class"`
	Capabilities []string        `json:"capabilities"`
	Targets      manifestRefJSON `json:"targets"`
	ScopeBound   bool            `json:"scope_bound"`
	RateCaps     *rateCapsJSON   `json:"rate_caps,omitempty"`
	ApprovalID   string          `json:"approval_id,omitempty"`
	Iat          int64           `json:"iat"`
	Nbf          int64           `json:"nbf"`
	Exp          int64           `json:"exp"`
}

type manifestRefJSON struct {
	HashAlg        string `json:"hash_alg"`
	ManifestURI    string `json:"manifest_uri"`
	ManifestSHA256 string `json:"manifest_sha256"`
	Count          uint32 `json:"count,omitempty"`
}

type rateCapsJSON struct {
	MaxRPS        uint32 `json:"max_rps,omitempty"`
	MaxConcurrent uint32 `json:"max_concurrent,omitempty"`
}

// headerJSON is the JOSE header.
type headerJSON struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// signJWT produces a compact EdDSA JWT.
func signJWT(kid string, pvt ed25519.PrivateKey, claims *claimsJSON) (string, error) {
	hdr, err := json.Marshal(headerJSON{Alg: "EdDSA", Typ: "JWT", Kid: kid})
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	b64 := base64.RawURLEncoding
	signingInput := b64.EncodeToString(hdr) + "." + b64.EncodeToString(payload)
	sig := ed25519.Sign(pvt, []byte(signingInput))
	return signingInput + "." + b64.EncodeToString(sig), nil
}

// ParsedToken is a verified token.
type ParsedToken struct {
	Claims *claimsJSON
	Kid    string
	Raw    string
}

// parseJWT splits and decodes without verifying (internal).
func parseJWT(raw string) (*headerJSON, *claimsJSON, string, []byte, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, nil, "", nil, errors.New("token: malformed JWT (want 3 segments)")
	}
	b64 := base64.RawURLEncoding
	hdrRaw, err := b64.DecodeString(parts[0])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("token: header b64: %w", err)
	}
	var hdr headerJSON
	if err := json.Unmarshal(hdrRaw, &hdr); err != nil {
		return nil, nil, "", nil, fmt.Errorf("token: header json: %w", err)
	}
	payloadRaw, err := b64.DecodeString(parts[1])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("token: payload b64: %w", err)
	}
	var claims claimsJSON
	dec := json.NewDecoder(strings.NewReader(string(payloadRaw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil {
		return nil, nil, "", nil, fmt.Errorf("token: payload json: %w", err)
	}
	sig, err := b64.DecodeString(parts[2])
	if err != nil {
		return nil, nil, "", nil, fmt.Errorf("token: signature b64: %w", err)
	}
	return &hdr, &claims, parts[0] + "." + parts[1], sig, nil
}

// KeyResolver resolves a kid to its public key (JWKS-backed).
type KeyResolver func(kid string) (ed25519.PublicKey, error)

// VerifyOptions tunes verification.
type VerifyOptions struct {
	Issuer       string
	Audience     string
	Now          time.Time
	Leeway       time.Duration // nbf/exp leeway (doc 11 §7: 60 s)
	MaxSkew      time.Duration // reject iat this far in the future (doc 11 §7: 120 s)
	RequireExp   bool
	AllowExpired bool // refresh path: verify signature/claims but tolerate expiry
}

// Verify parses and cryptographically verifies a Scope Token against the
// resolver's keys, enforcing iss/aud/exp/nbf (60 s leeway; skew > 120 s
// rejected — doc 11 §7).
func Verify(raw string, resolve KeyResolver, opts VerifyOptions) (*ParsedToken, error) {
	hdr, claims, signingInput, sig, err := parseJWT(raw)
	if err != nil {
		return nil, err
	}
	if hdr.Alg != "EdDSA" || hdr.Typ != "JWT" {
		return nil, fmt.Errorf("token: unexpected header alg=%q typ=%q", hdr.Alg, hdr.Typ)
	}
	if hdr.Kid == "" {
		return nil, errors.New("token: missing kid")
	}
	pub, err := resolve(hdr.Kid)
	if err != nil {
		return nil, fmt.Errorf("token: unknown kid %q", hdr.Kid)
	}
	if !ed25519.Verify(pub, []byte(signingInput), sig) {
		return nil, errors.New("token: bad signature")
	}
	if claims.Iss != opts.Issuer {
		return nil, fmt.Errorf("token: iss %q != %q", claims.Iss, opts.Issuer)
	}
	if claims.Aud != opts.Audience {
		return nil, fmt.Errorf("token: aud %q != %q", claims.Aud, opts.Audience)
	}
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	leeway := opts.Leeway
	if leeway == 0 {
		leeway = 60 * time.Second
	}
	maxSkew := opts.MaxSkew
	if maxSkew == 0 {
		maxSkew = 120 * time.Second
	}
	iat := time.Unix(claims.Iat, 0)
	if iat.After(now.Add(maxSkew)) {
		return nil, fmt.Errorf("token: iat %s is > %v in the future (clock skew / replay?)", iat, maxSkew)
	}
	nbf := time.Unix(claims.Nbf, 0)
	if nbf.After(now.Add(leeway)) {
		return nil, fmt.Errorf("token: not valid before %s", nbf)
	}
	if !opts.AllowExpired && opts.RequireExp && !now.Before(time.Unix(claims.Exp, 0).Add(leeway)) {
		return nil, fmt.Errorf("token: expired at %s", time.Unix(claims.Exp, 0))
	}
	if claims.Exp-claims.Iat > 900 {
		return nil, fmt.Errorf("token: TTL %ds exceeds the 900s Ruling C5 cap", claims.Exp-claims.Iat)
	}
	if claims.TaskID == "" || claims.Jti == "" || claims.Sub == "" {
		return nil, errors.New("token: jti/sub/task_id are required")
	}
	return &ParsedToken{Claims: claims, Kid: hdr.Kid, Raw: raw}, nil
}
