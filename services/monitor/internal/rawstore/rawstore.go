// Package rawstore is the M9 raw snapshot store adapter (doc 03 §8/§9.5):
// HTTP bodies (and later cert chains / raw DNS answers) are PII-redacted,
// zstd-compressed, and uploaded to the MinIO monitor-raw bucket under
// <mission>/<asset>/<date>/<snapshot>.body.zst. The 30 d lifecycle is
// provisioned by deploy minio-init.
package rawstore

import (
	"bytes"
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/klauspost/compress/zstd"
)

// Uploader stores one raw body and returns its reference ("s3://bucket/key").
// Implementations must be safe for concurrent use.
type Uploader interface {
	Upload(ctx context.Context, missionID, assetID, snapshotID string, body []byte, ts time.Time) (string, error)
}

// Config wires the S3/MinIO uploader.
type Config struct {
	Endpoint        string // host:port, no scheme
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	UseTLS          bool
	Bucket          string // monitor-raw
}

// S3Uploader uploads to MinIO/S3 (path-style, SigV4).
type S3Uploader struct {
	client *s3.Client
	bucket string
}

// NewS3 builds an S3Uploader from cfg.
func NewS3(cfg Config) *S3Uploader {
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
		UsePathStyle: true,
	})
	return &S3Uploader{client: client, bucket: cfg.Bucket}
}

// Key renders the object key (doc 03 §6.2 raw_ref layout).
func Key(missionID, assetID, snapshotID string, ts time.Time) string {
	return fmt.Sprintf("%s/%s/%s/%s.body.zst",
		missionID, assetID, ts.UTC().Format("2006-01-02"), snapshotID)
}

// Upload implements Uploader: zstd-compress, PUT, return the s3:// ref.
func (u *S3Uploader) Upload(ctx context.Context, missionID, assetID, snapshotID string, body []byte, ts time.Time) (string, error) {
	enc, err := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedFastest))
	if err != nil {
		return "", fmt.Errorf("rawstore: zstd init: %w", err)
	}
	compressed := enc.EncodeAll(body, nil)
	_ = enc.Close()

	key := Key(missionID, assetID, snapshotID, ts)
	_, err = u.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(u.bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(compressed),
		ContentType: aws.String("application/zstd"),
	})
	if err != nil {
		return "", fmt.Errorf("rawstore: put s3://%s/%s: %w", u.bucket, key, err)
	}
	return "s3://" + u.bucket + "/" + key, nil
}

// NopUploader drops bodies and returns "" (tests, MinIO-outage spill path is
// handled by the caller via raw_pending).
type NopUploader struct{}

// Upload implements Uploader.
func (NopUploader) Upload(context.Context, string, string, string, []byte, time.Time) (string, error) {
	return "", nil
}

// FailingUploader always fails (MinIO-outage tests, doc 03 §12).
type FailingUploader struct{ Err error }

// Upload implements Uploader.
func (f FailingUploader) Upload(context.Context, string, string, string, []byte, time.Time) (string, error) {
	if f.Err != nil {
		return "", f.Err
	}
	return "", fmt.Errorf("rawstore: forced failure")
}
