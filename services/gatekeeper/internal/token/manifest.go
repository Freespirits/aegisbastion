package token

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"

	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/jsonx"
)

// ObjectStore abstracts the manifest blob store (MinIO bucket
// "token-manifests" in production; fakes in tests).
type ObjectStore interface {
	Put(ctx context.Context, bucket, key string, body []byte) error
	Get(ctx context.Context, bucket, key string) ([]byte, error)
	EnsureBucket(ctx context.Context, bucket string) error
	Ping(ctx context.Context) error
}

// S3Store is the MinIO-backed ObjectStore.
type S3Store struct {
	cli *minio.Client
}

// NewS3Store dials a MinIO/S3 endpoint.
func NewS3Store(endpoint, accessKey, secretKey string, useTLS bool) (*S3Store, error) {
	cli, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useTLS,
	})
	if err != nil {
		return nil, fmt.Errorf("token: minio client: %w", err)
	}
	return &S3Store{cli: cli}, nil
}

// Put uploads body.
func (s *S3Store) Put(ctx context.Context, bucket, key string, body []byte) error {
	_, err := s.cli.PutObject(ctx, bucket, key, bytes.NewReader(body), int64(len(body)),
		minio.PutObjectOptions{ContentType: "application/json"})
	if err != nil {
		return fmt.Errorf("token: put %s/%s: %w", bucket, key, err)
	}
	return nil
}

// Get downloads an object fully.
func (s *S3Store) Get(ctx context.Context, bucket, key string) ([]byte, error) {
	obj, err := s.cli.GetObject(ctx, bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, fmt.Errorf("token: get %s/%s: %w", bucket, key, err)
	}
	defer obj.Close()
	raw, err := io.ReadAll(obj)
	if err != nil {
		return nil, fmt.Errorf("token: read %s/%s: %w", bucket, key, err)
	}
	return raw, nil
}

// EnsureBucket creates the bucket when absent (idempotent).
func (s *S3Store) EnsureBucket(ctx context.Context, bucket string) error {
	exists, err := s.cli.BucketExists(ctx, bucket)
	if err != nil {
		return fmt.Errorf("token: bucket exists %s: %w", bucket, err)
	}
	if exists {
		return nil
	}
	if err := s.cli.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
		return fmt.Errorf("token: make bucket %s: %w", bucket, err)
	}
	return nil
}

// Ping checks connectivity (health endpoint).
func (s *S3Store) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := s.cli.ListBuckets(ctx)
	return err
}

// ---------------------------------------------------------------------------
// manifests (doc 11 §3.2 / doc 01 §5.5 / Ruling A)
// ---------------------------------------------------------------------------

// ExactManifest is the exact-enumerated target manifest (R1–R3 non-watch
// tokens). Serialized with JCS before hashing/upload.
type ExactManifest struct {
	Jti     string   `json:"jti"`
	TaskID  string   `json:"task_id"`
	Targets []string `json:"targets"`
}

// ScopeManifest is the scope-bound watch-token manifest (Ruling A): the
// canonical RoE scope document. Its shape matches
// schemas/gatekeeper/v1/scope-manifest.schema.json and its sha256 IS the
// "scope:sha256:<hash>" audit value.
type ScopeManifest struct {
	RoeID      string `json:"roe_id"`
	RoeVersion uint64 `json:"roe_version"`
	ResolvedAt string `json:"resolved_at"`
	Scope      struct {
		AssetGroupIds    []string `json:"asset_group_ids,omitempty"`
		Domains          []string `json:"domains"`
		CIDRs            []string `json:"cidrs"`
		CloudAccounts    []string `json:"cloud_accounts,omitempty"`
		ExplicitExcludes []string `json:"explicit_excludes"`
	} `json:"scope"`
}

// manifestObjectKey maps a manifest URI (blob://tokens/<jti>/<file>.json) to
// its object key.
func manifestObjectKey(uri string) (string, error) {
	key, ok := strings.CutPrefix(uri, "blob://")
	if !ok || key == "" || strings.Contains(key, "..") {
		return "", fmt.Errorf("token: bad manifest URI %q", uri)
	}
	return key, nil
}

// putManifest JCS-canonicalizes, hashes and uploads a manifest, returning
// (sha256hex, canonicalBytes).
func putManifest(ctx context.Context, st ObjectStore, bucket, key string, v any) (string, []byte, error) {
	canon, err := jsonx.Canonical(v)
	if err != nil {
		return "", nil, err
	}
	// Validate it parses back (defensive — the bytes we ship must be valid JSON).
	var probe any
	if err := json.Unmarshal(canon, &probe); err != nil {
		return "", nil, fmt.Errorf("token: manifest invalid: %w", err)
	}
	if err := st.Put(ctx, bucket, key, canon); err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(canon)
	return hex.EncodeToString(sum[:]), canon, nil
}

// fetchManifest downloads a manifest and verifies its hash against the claim.
func fetchManifest(ctx context.Context, st ObjectStore, bucket, uri, wantSHA256 string) ([]byte, error) {
	key, err := manifestObjectKey(uri)
	if err != nil {
		return nil, err
	}
	raw, err := st.Get(ctx, bucket, key)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	if hex.EncodeToString(sum[:]) != wantSHA256 {
		return nil, fmt.Errorf("token: manifest hash mismatch for %s", uri)
	}
	return raw, nil
}
