// Package manifest fetches and verifies the hashed target manifests a Scope
// Token points at (doc 01 §5.5, doc 11 §3.2). Two forms exist:
//
//   - exact-enumerated: a JSON target list; the PEP re-checks every target
//     string against it before each network action (defense in depth).
//   - scope-bound (Ruling A watch tokens): the canonical RoE scope document
//     (schemas/gatekeeper/v1/scope-manifest.schema.json); sha256(manifest) IS
//     the "scope:sha256:<hash>" audit value.
//
// Manifests live in the MinIO "token-manifests" bucket; token claim URIs look
// like "blob://tokens/<jti>/targets.json" — the "tokens" prefix maps to the
// token-manifests bucket (see deploy/docker-compose.yml minio-init).
package manifest

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aegisbastion/aegisbastion/sdks/go/scope"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"
)

// DefaultBucket is the MinIO bucket holding token manifests.
const DefaultBucket = "token-manifests"

// Fetch/verification failure kinds (all fail-closed).
var (
	// ErrURI — manifest_uri does not parse / maps to no object.
	ErrURI = errors.New("manifest: invalid manifest_uri")
	// ErrFetch — the manifest object could not be fetched (fail-closed).
	ErrFetch = errors.New("manifest: fetch failed")
	// ErrHash — sha256(fetched bytes) != targets.manifest_sha256. For
	// scope-bound tokens this also breaks the "scope:sha256:<hash>" audit
	// value (Ruling A.3) — refuse target contact.
	ErrHash = errors.New("manifest: sha256 mismatch with token claim")
	// ErrParse — the manifest document does not decode.
	ErrParse = errors.New("manifest: manifest does not decode")
	// ErrCount — exact-enumerated manifest length != targets.count claim.
	ErrCount = errors.New("manifest: target count mismatch with token claim")
)

// MapURI maps a token manifest_uri to (bucket, key). Accepted forms:
//
//	blob://tokens/<jti>/<name>          → (token-manifests, <jti>/<name>)
//	blob://<bucket>/<key…>              → (<bucket>, <key…>)
//	s3://<bucket>/<key…>                → (<bucket>, <key…>)
//
// bucketOverride (when non-empty) wins over the URI bucket — deployments pin
// manifests to the provisioned token-manifests bucket.
func MapURI(uri, bucketOverride string) (bucket, key string, err error) {
	rest, ok := strings.CutPrefix(uri, "blob://")
	if !ok {
		rest, ok = strings.CutPrefix(uri, "s3://")
		if !ok {
			return "", "", fmt.Errorf("%w: unsupported scheme in %q", ErrURI, uri)
		}
	}
	slash := strings.Index(rest, "/")
	if slash <= 0 || slash == len(rest)-1 {
		return "", "", fmt.Errorf("%w: %q has no object key", ErrURI, uri)
	}
	host, objKey := rest[:slash], rest[slash+1:]
	bucket = host
	if host == "tokens" {
		bucket = DefaultBucket
	}
	if bucketOverride != "" {
		bucket = bucketOverride
	}
	return bucket, objKey, nil
}

// Fetcher retrieves manifest bytes by URI.
type Fetcher interface {
	Fetch(ctx context.Context, uri string) ([]byte, error)
}

// FetcherFunc adapts a function to Fetcher (tests, in-memory deployments).
type FetcherFunc func(ctx context.Context, uri string) ([]byte, error)

// Fetch implements Fetcher.
func (f FetcherFunc) Fetch(ctx context.Context, uri string) ([]byte, error) { return f(ctx, uri) }

// S3Config configures an S3Fetcher (MinIO at MVP-A — see deploy/.env.example).
type S3Config struct {
	// Endpoint host:port, e.g. "localhost:9000" (no scheme).
	Endpoint string
	// Region — MinIO accepts anything; "us-east-1" is the convention.
	Region string
	// AccessKeyID / SecretAccessKey — MinIO root or a scoped service account.
	AccessKeyID     string
	SecretAccessKey string
	// UseTLS — https vs http endpoint.
	UseTLS bool
	// Bucket overrides the URI-derived bucket (usually "token-manifests").
	Bucket string
}

// S3Fetcher fetches manifests from MinIO/S3 (path-style, SigV4).
type S3Fetcher struct {
	client *s3.Client
	bucket string
}

// NewS3Fetcher builds an S3Fetcher from cfg.
func NewS3Fetcher(cfg S3Config) *S3Fetcher {
	scheme := "http"
	if cfg.UseTLS {
		scheme = "https"
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	client := s3.New(s3.Options{
		Region:       region,
		BaseEndpoint: aws.String(scheme + "://" + cfg.Endpoint),
		Credentials: credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		UsePathStyle: true, // MinIO
	})
	return &S3Fetcher{client: client, bucket: cfg.Bucket}
}

// Fetch implements Fetcher.
func (f *S3Fetcher) Fetch(ctx context.Context, uri string) ([]byte, error) {
	bucket, key, err := MapURI(uri, f.bucket)
	if err != nil {
		return nil, err
	}
	out, err := f.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("%w: s3://%s/%s: %v", ErrFetch, bucket, key, err)
	}
	defer out.Body.Close()
	body, err := io.ReadAll(io.LimitReader(out.Body, 4<<20))
	if err != nil {
		return nil, fmt.Errorf("%w: s3://%s/%s read: %v", ErrFetch, bucket, key, err)
	}
	return body, nil
}

// ScopeManifest is the canonical scope document carried by a scope-bound
// watch token (schemas/gatekeeper/v1/scope-manifest.schema.json; JCS/RFC 8785
// serialized by gatekeeper before hashing).
type ScopeManifest struct {
	ROEID      string      `json:"roe_id"`
	ROEVersion uint64      `json:"roe_version"`
	ResolvedAt string      `json:"resolved_at,omitempty"`
	Scope      scope.Scope `json:"scope"`
}

// Manifest is a fetched, hash-verified, parsed target manifest.
type Manifest struct {
	// SHA256Hex is the verified sha256 (hex) of the raw manifest bytes —
	// equals the token claim and, for scope-bound tokens, the hash inside the
	// "scope:sha256:<hash>" audit value.
	SHA256Hex string
	// ExactTargets holds the canonicalized targets (exact-enumerated form).
	ExactTargets []string
	// ScopeManifest holds the canonical scope document (scope-bound form).
	ScopeManifest *ScopeManifest
}

// ScopeBound reports the manifest form.
func (m *Manifest) ScopeBound() bool { return m.ScopeManifest != nil }

// Contains reports whether target is in the exact-enumerated manifest,
// compared in canonical form (doc 01 §10.1). Always false for scope-bound
// manifests (use Scope evaluation instead).
func (m *Manifest) Contains(target string) bool {
	if m.ScopeManifest != nil {
		return false
	}
	t, err := scope.Canonicalize(target)
	if err != nil {
		return false
	}
	for _, et := range m.ExactTargets {
		if et == t.Canonical {
			return true
		}
	}
	return false
}

// EvaluateScope evaluates target against the embedded canonical scope
// (scope-bound form only; nil-safe deny otherwise).
func (m *Manifest) EvaluateScope(target string) scope.Decision {
	if m.ScopeManifest == nil {
		return scope.Decision{Reason: "manifest carries no scope document (fail-closed)"}
	}
	return m.ScopeManifest.Scope.Evaluate(target)
}

// ScopeAuditValue returns the "scope:sha256:<hash>" audit value for a
// scope-bound manifest (Ruling A.3/A.4) — empty for exact-enumerated ones.
func (m *Manifest) ScopeAuditValue() string {
	if m.ScopeManifest == nil {
		return ""
	}
	return ScopeAuditValue(m.SHA256Hex)
}

// ScopeAuditValue renders the canonical audit form "scope:sha256:<hash>"
// (doc 01 §5.5/§5.7, doc 03 §4.3).
func ScopeAuditValue(sha256Hex string) string {
	return "scope:sha256:" + sha256Hex
}

// Load fetches the manifest referenced by ref, verifies its sha256 against
// the token claim, and parses it. scopeBound must equal the token's
// scope_bound claim; a mismatch with the actual document is a hard failure.
// Fail-closed throughout: any error means "refuse target contact".
func Load(ctx context.Context, f Fetcher, ref token.TargetManifestRef, scopeBound bool) (*Manifest, error) {
	if ref.HashAlg != "sha256" {
		return nil, fmt.Errorf("%w: unsupported hash_alg %q", ErrParse, ref.HashAlg)
	}
	raw, err := f.Fetch(ctx, ref.ManifestURI)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	hexSum := hex.EncodeToString(sum[:])
	if !strings.EqualFold(hexSum, ref.ManifestSHA256) {
		return nil, fmt.Errorf("%w: got %s, claim %s", ErrHash, hexSum, ref.ManifestSHA256)
	}
	m := &Manifest{SHA256Hex: strings.ToLower(hexSum)}
	if scopeBound {
		var sm ScopeManifest
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&sm); err != nil {
			return nil, fmt.Errorf("%w: scope manifest: %v", ErrParse, err)
		}
		if sm.ROEID == "" || sm.ROEVersion < 1 {
			return nil, fmt.Errorf("%w: scope manifest missing roe_id/roe_version", ErrParse)
		}
		m.ScopeManifest = &sm
		return m, nil
	}

	targets, err := parseExactTargets(raw)
	if err != nil {
		return nil, err
	}
	if ref.Count > 0 && int(ref.Count) != len(targets) {
		return nil, fmt.Errorf("%w: manifest has %d, claim %d", ErrCount, len(targets), ref.Count)
	}
	m.ExactTargets = make([]string, 0, len(targets))
	for _, raw := range targets {
		t, err := scope.Canonicalize(raw)
		if err != nil {
			return nil, fmt.Errorf("%w: manifest target %q: %v", ErrParse, raw, err)
		}
		m.ExactTargets = append(m.ExactTargets, t.Canonical)
	}
	return m, nil
}

// parseExactTargets accepts both a bare JSON array of target strings and an
// object {"targets": [...]}.
func parseExactTargets(raw []byte) ([]string, error) {
	var list []string
	if err := json.Unmarshal(raw, &list); err == nil {
		return list, nil
	}
	var obj struct {
		Targets []string `json:"targets"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("%w: exact-enumerated manifest: %v", ErrParse, err)
	}
	if obj.Targets == nil {
		return nil, fmt.Errorf("%w: exact-enumerated manifest has no targets", ErrParse)
	}
	return obj.Targets, nil
}
