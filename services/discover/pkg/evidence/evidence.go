// Package evidence archives raw source response payloads to the platform
// object store (doc 02 §2.2: S3-compatible bucket for raw evidence,
// referenced from findings.evidence_uri; retention 90 days hot per §6.4).
// MinIO at MVP-A (path-style SigV4, same client profile as the SDK's
// manifest fetcher).
//
// Archiving is best-effort: an archive failure degrades to findings without
// an evidence URI — it never fails the task (the finding data itself is the
// asset signal; evidence is replay material).
package evidence

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// Bucket is the provisioned evidence bucket (deploy minio-init).
const Bucket = "evidence"

// Config mirrors the S3_* env contract (deploy/docker-compose x-object-env).
type Config struct {
	Endpoint        string // host:port, no scheme
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	UseTLS          bool
	Bucket          string // empty ⇒ "evidence"
}

// Archiver uploads raw payloads.
type Archiver struct {
	client *s3.Client
	bucket string
}

// New builds an Archiver. Returns nil when cfg.Endpoint is empty (evidence
// archiving disabled — offline/fixture modes).
func New(cfg Config) *Archiver {
	if cfg.Endpoint == "" {
		return nil
	}
	scheme := "http"
	if cfg.UseTLS {
		scheme = "https"
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	bucket := cfg.Bucket
	if bucket == "" {
		bucket = Bucket
	}
	return &Archiver{
		client: s3.New(s3.Options{
			Region:       region,
			BaseEndpoint: aws.String(scheme + "://" + cfg.Endpoint),
			Credentials: credentials.NewStaticCredentialsProvider(
				cfg.AccessKeyID, cfg.SecretAccessKey, ""),
			UsePathStyle: true,
		}),
		bucket: bucket,
	}
}

// URI renders the s3:// form stored in findings.evidence_uri.
func (a *Archiver) URI(key string) string {
	return "s3://" + a.bucket + "/" + key
}

// Put stores one raw payload and returns its evidence URI. Keys are
// tenant-scoped: discover/<tenant>/<order>/<task>/<source>-<unixnano>.bin.
func (a *Archiver) Put(ctx context.Context, tenantID, orderID, taskID, source string, body []byte) (string, error) {
	if a == nil {
		return "", nil
	}
	key := fmt.Sprintf("discover/%s/%s/%s/%s-%d.bin",
		tenantID, orderID, taskID, sanitize(source), time.Now().UnixNano())
	_, err := a.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(a.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(body),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		return "", fmt.Errorf("evidence: put %s: %w", key, err)
	}
	return a.URI(key), nil
}

func sanitize(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			out = append(out, r)
		case r >= 'A' && r <= 'Z':
			out = append(out, r+('a'-'A'))
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}
