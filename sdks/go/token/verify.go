package token

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// header is the JWT JOSE header. alg is always "EdDSA", kid selects the JWKS
// verification key (rotation via kid, two active keys max — doc 01 §10.2).
type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// Verifier verifies compact EdDSA Scope Token JWTs against the cached
// gatekeeper JWKS. It performs (fail-closed, in order): structure → header →
// key lookup (one forced JWKS refresh on kid miss) → Ed25519 signature →
// claim checks (iss/aud/required claims/risk class/manifest ref/TTL ≤ 15 min/
// nbf+exp with 60 s leeway/iat clock-skew ≤ 120 s/scope_bound applicability/
// R3 approval binding).
type Verifier struct {
	keys *KeyCache
	now  func() time.Time
}

// VerifierOption configures a Verifier.
type VerifierOption func(*Verifier)

// WithClock injects a clock (tests).
func WithClock(now func() time.Time) VerifierOption {
	return func(v *Verifier) { v.now = now }
}

// NewVerifier builds a Verifier over a JWKS cache.
func NewVerifier(keys *KeyCache, opts ...VerifierOption) *Verifier {
	v := &Verifier{keys: keys, now: time.Now}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify parses and fully verifies a compact Scope Token. Any failure is a
// typed error from this package — callers MUST treat every error as "refuse
// target contact" (doc 01 §15 acceptance test 2: forged token ⇒ SDK refuses).
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w: want 3 segments, got %d", ErrMalformed, len(parts))
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header not base64url: %v", ErrMalformed, err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload not base64url: %v", ErrMalformed, err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature not base64url: %v", ErrMalformed, err)
	}

	var h header
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("%w: header does not decode: %v", ErrMalformed, err)
	}
	if h.Alg != "EdDSA" {
		return nil, fmt.Errorf("%w: %q", ErrAlgorithm, h.Alg)
	}

	pub, err := v.keys.PublicKey(ctx, h.Kid)
	if err != nil {
		return nil, err
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	if !ed25519.Verify(pub, signingInput, sig) {
		return nil, ErrSignature
	}

	// Unknown claims are rejected (fail-closed; the schema sets
	// additionalProperties: false).
	var claims Claims
	dec := json.NewDecoder(bytes.NewReader(payloadBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&claims); err != nil {
		return nil, fmt.Errorf("%w: claims do not decode: %v", ErrMalformed, err)
	}
	if err := claims.validate(v.now()); err != nil {
		return nil, err
	}
	return &claims, nil
}
