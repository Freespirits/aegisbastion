package token

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
)

// JWK is one Ed25519 public key in JWK form (RFC 8037), as published at
// /.well-known/gatekeeper-jwks.json and returned by TokenService.GetJWKS
// (doc 11 §3.2: kid rotation, two active keys max).
type JWK struct {
	Kty string `json:"kty"` // always "OKP"
	Crv string `json:"crv"` // always "Ed25519"
	Kid string `json:"kid"`
	Alg string `json:"alg"` // always "EdDSA"
	Use string `json:"use"` // always "sig"
	X   string `json:"x"`   // base64url raw Ed25519 public key
}

// PublicKey decodes and validates the JWK into an ed25519.PublicKey.
func (j JWK) PublicKey() (ed25519.PublicKey, error) {
	if j.Kty != "OKP" || j.Crv != "Ed25519" {
		return nil, fmt.Errorf("token: unsupported JWK kty=%q crv=%q", j.Kty, j.Crv)
	}
	if j.Kid == "" {
		return nil, fmt.Errorf("token: JWK missing kid")
	}
	raw, err := base64.RawURLEncoding.DecodeString(j.X)
	if err != nil {
		return nil, fmt.Errorf("token: JWK %q x not base64url: %w", j.Kid, err)
	}
	if len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("token: JWK %q x is %d bytes, want %d", j.Kid, len(raw), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(raw), nil
}

// KeySource fetches the current JWKS document.
type KeySource interface {
	FetchKeys(ctx context.Context) ([]JWK, error)
}

// KeySourceFunc adapts a function to KeySource (handy in tests).
type KeySourceFunc func(ctx context.Context) ([]JWK, error)

// FetchKeys implements KeySource.
func (f KeySourceFunc) FetchKeys(ctx context.Context) ([]JWK, error) { return f(ctx) }

// HTTPKeySource fetches JWKS over HTTP(S) from the gatekeeper's
// /.well-known/gatekeeper-jwks.json endpoint (internal, mTLS in deployments —
// the transport credentials are the caller's http.Client concern).
type HTTPKeySource struct {
	url    string
	client *http.Client
}

// NewHTTPKeySource builds an HTTP JWKS source. client may be nil (a 10 s
// timeout default is used).
func NewHTTPKeySource(url string, client *http.Client) *HTTPKeySource {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &HTTPKeySource{url: url, client: client}
}

// FetchKeys implements KeySource.
func (s *HTTPKeySource) FetchKeys(ctx context.Context) ([]JWK, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token: JWKS endpoint returned %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc struct {
		Keys []JWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("token: JWKS document does not decode: %w", err)
	}
	return doc.Keys, nil
}

// GRPCKeysSource fetches JWKS via gatekeeper's TokenService.GetJWKS RPC.
type GRPCKeysSource struct {
	client gatekeeperv1.TokenServiceClient
}

// NewGRPCKeysSource builds a gRPC JWKS source.
func NewGRPCKeysSource(client gatekeeperv1.TokenServiceClient) *GRPCKeysSource {
	return &GRPCKeysSource{client: client}
}

// FetchKeys implements KeySource.
func (s *GRPCKeysSource) FetchKeys(ctx context.Context) ([]JWK, error) {
	resp, err := s.client.GetJWKS(ctx, &gatekeeperv1.GetJWKSRequest{})
	if err != nil {
		return nil, err
	}
	keys := make([]JWK, 0, len(resp.GetKeys()))
	for _, k := range resp.GetKeys() {
		keys = append(keys, JWK{
			Kty: k.GetKty(), Crv: k.GetCrv(), Kid: k.GetKid(),
			Alg: k.GetAlg(), Use: k.GetUse(), X: k.GetX(),
		})
	}
	return keys, nil
}

// KeyCache caches JWKS verification keys (doc 11 §6: fully local verification
// with a 5-minute refresh; doc 11 §7: a compromised key is out of all PEP
// caches within 5 minutes). A cache miss on kid forces one refresh before
// failing — this covers key rotation overlap (doc 01 §10.2).
type KeyCache struct {
	src KeySource
	ttl time.Duration
	now func() time.Time

	mu        sync.RWMutex
	keys      map[string]ed25519.PublicKey
	expiresAt time.Time
}

// KeyCacheOption configures a KeyCache.
type KeyCacheOption func(*KeyCache)

// WithCacheTTL overrides the JWKS cache TTL (must be <= JWKSTTL).
func WithCacheTTL(ttl time.Duration) KeyCacheOption {
	return func(c *KeyCache) {
		if ttl > 0 && ttl <= JWKSTTL {
			c.ttl = ttl
		}
	}
}

// WithCacheClock injects a clock (tests).
func WithCacheClock(now func() time.Time) KeyCacheOption {
	return func(c *KeyCache) { c.now = now }
}

// NewKeyCache builds a JWKS cache over src.
func NewKeyCache(src KeySource, opts ...KeyCacheOption) *KeyCache {
	c := &KeyCache{
		src:  src,
		ttl:  JWKSTTL,
		now:  time.Now,
		keys: map[string]ed25519.PublicKey{},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// PublicKey returns the verification key for kid, refreshing the cache once
// on a miss or when stale. Fail-closed: any fetch error is an error here.
func (c *KeyCache) PublicKey(ctx context.Context, kid string) (ed25519.PublicKey, error) {
	if kid == "" {
		return nil, fmt.Errorf("%w: empty kid", ErrUnknownKey)
	}
	if k, ok := c.get(kid); ok {
		return k, nil
	}
	if err := c.Refresh(ctx); err != nil {
		return nil, err
	}
	if k, ok := c.get(kid); ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownKey, kid)
}

// Refresh forces a JWKS reload, replacing the key set atomically.
func (c *KeyCache) Refresh(ctx context.Context) error {
	jwks, err := c.src.FetchKeys(ctx)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJWKS, err)
	}
	fresh := make(map[string]ed25519.PublicKey, len(jwks))
	for _, j := range jwks {
		pub, err := j.PublicKey()
		if err != nil {
			return fmt.Errorf("%w: %v", ErrJWKS, err)
		}
		fresh[j.Kid] = pub
	}
	c.mu.Lock()
	c.keys = fresh
	c.expiresAt = c.now().Add(c.ttl)
	c.mu.Unlock()
	return nil
}

func (c *KeyCache) get(kid string) (ed25519.PublicKey, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.now().After(c.expiresAt) {
		return nil, false
	}
	k, ok := c.keys[kid]
	return k, ok
}
