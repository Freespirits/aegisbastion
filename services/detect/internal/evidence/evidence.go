// Package evidence is the Detect Evidence Store writer (doc 04 §3.1 D9):
// request/response transcripts, scanner raw output, and sandbox logs are
// uploaded to the task's pre-signed artifact prefix (doc 01 §5.6) —
// content-hashed, redacted BEFORE upload (credentials/session tokens are
// stripped, doc 04 §10.4), and write-once so a CONFIRMED finding is always
// backed by tamper-evident proof.
//
// Upload failures fall back to a local spill file and surface an error: the
// coordinator downgrades affected CONFIRMED verdicts to INCONCLUSIVE rather
// than report a CONFIRMED finding without evidence (doc 04 §12 — "a
// CONFIRMED finding without evidence is a contract violation").
package evidence

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// S3Config mirrors the SDK manifest.S3Config fields (kept separate so the
// evidence writer does not depend on the token-manifest bucket default).
type S3Config struct {
	Endpoint        string
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	UseTLS          bool
}

// Store uploads redacted evidence objects to the artifact bucket.
type Store struct {
	client *s3.Client
	// SpillDir receives uploads that failed after retries (doc 04 §12).
	SpillDir string
}

// New builds a Store against a MinIO/S3 endpoint (path-style, SigV4).
func New(cfg S3Config) *Store {
	scheme := "http"
	if cfg.UseTLS {
		scheme = "https"
	}
	region := cfg.Region
	if region == "" {
		region = "us-east-1"
	}
	return &Store{client: s3.New(s3.Options{
		Region:       region,
		BaseEndpoint: aws.String(scheme + "://" + cfg.Endpoint),
		Credentials: credentials.NewStaticCredentialsProvider(
			cfg.AccessKeyID, cfg.SecretAccessKey, ""),
		UsePathStyle: true,
	})}
}

// Upload writes data (already redacted by the caller via Redact, but Redact
// is applied here again as a hard invariant) under bucket/prefix/name and
// returns the artifact reference ("s3://bucket/prefix/name") plus the
// content hash ("sha256:<hex>") recorded in the evidence manifest.
func (s *Store) Upload(ctx context.Context, bucket, prefix, name string, data []byte) (ref, contentHash string, err error) {
	data = Redact(data)
	sum := sha256.Sum256(data)
	contentHash = "sha256:" + hex.EncodeToString(sum[:])
	key := prefix + name
	_, err = s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(data),
		ContentType: aws.String("application/octet-stream"),
	})
	if err != nil {
		spillRef, serr := s.spill(key, data)
		if serr != nil {
			return "", contentHash, fmt.Errorf("evidence: upload s3://%s/%s: %w (spill also failed: %v)", bucket, key, err, serr)
		}
		return "", contentHash, fmt.Errorf("evidence: upload s3://%s/%s: %w (spilled to %s)", bucket, key, err, spillRef)
	}
	return "s3://" + bucket + "/" + key, contentHash, nil
}

// spill writes a failed upload to local disk for operator recovery.
func (s *Store) spill(key string, data []byte) (string, error) {
	dir := s.SpillDir
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "aegisbastion-detect-evidence-spill")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	name := hex.EncodeToString([]byte(key))
	if len(name) > 64 {
		name = name[:64]
	}
	path := filepath.Join(dir, name+".bin")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// ---------------------------------------------------------------------------
// Redaction filter (doc 04 §6/§10.4: secrets in responses are redacted
// BEFORE storage — applied again inside Upload as a hard invariant)
// ---------------------------------------------------------------------------

var redactionRules = []struct {
	re  *regexp.Regexp
	rep []byte
}{
	// Authorization / proxy-authorization headers.
	{regexp.MustCompile(`(?i)(authorization(?:\s*):[^\r\n]{0,1000})`), []byte("authorization: [REDACTED]")},
	// Cookie / Set-Cookie headers (session tokens).
	{regexp.MustCompile(`(?i)((?:set-)?cookie\s*:[^\r\n]{0,1000})`), []byte("cookie: [REDACTED]")},
	// Bearer / Basic tokens anywhere in bodies.
	{regexp.MustCompile(`(?i)(bearer\s+[a-z0-9._~+/=-]{8,})`), []byte("Bearer [REDACTED]")},
	{regexp.MustCompile(`(?i)(basic\s+[a-z0-9+/=]{8,})`), []byte("Basic [REDACTED]")},
	// JSON form secrets: "password"|"passwd"|"secret"|"token"|"api_key"|"session" values.
	{regexp.MustCompile(`(?i)("(?:password|passwd|secret|token|api[-_]?key|session[-_]?id|access[-_]?token|refresh[-_]?token|private[-_]?key)"\s*:\s*")[^"]{1,512}(")`), []byte(`${1}[REDACTED]${2}`)},
	// Form-encoded secrets: password=…& / token=…&.
	{regexp.MustCompile(`(?i)((?:password|passwd|secret|token|api[-_]?key|session[-_]?id)=)[^&\s"']{1,512}`), []byte(`${1}[REDACTED]`)},
	// AWS-style access key ids.
	{regexp.MustCompile(`\b(AKIA|ASIA)[0-9A-Z]{16}\b`), []byte("[REDACTED-AWS-KEY]")},
	// PEM private keys.
	{regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]{0,1000}?-----END [A-Z ]*PRIVATE KEY-----`), []byte("[REDACTED-PRIVATE-KEY]")},
}

// Redact strips credentials/session tokens from a transcript or raw scanner
// record before storage (doc 04 §6 evidence contract, §10.4).
func Redact(data []byte) []byte {
	out := data
	for _, r := range redactionRules {
		out = r.re.ReplaceAll(out, r.rep)
	}
	return out
}
