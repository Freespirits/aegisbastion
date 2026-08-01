// Package retention is the purge engine of doc 09 §10: per-tenant,
// per-data-class retention enforced from the tenant's retention profile
// (tenancy.retention_profiles). MVP-A implements the two classes the MVP
// stores actually hold (doc 09 §11: fixed retention profile, manual purge
// job):
//
//	findings_resolved  — terminal findings (verified_closed|false_positive|
//	                     accepted_risk) past their terminal date (default P2Y).
//	                     Legal hold freezes the subtree (RETENTION_LOCKED).
//	evidence_blobs     — "finding+P90D": evidence blobs of terminal findings
//	                     outlive the parent by 90 days, then are deleted
//	                     from object storage and the reference is cleared.
//
// Open findings are kept indefinitely (findings_open: "indefinite"). Asset
// attribute history offloading, event hot retention and audit metadata
// retention are handled elsewhere (object-storage lifecycle, JetStream stream
// MaxAge, gatekeeper respectively) and are out of this engine's MVP scope.
//
// Every purge emits a retention.purged data-access audit record (counts +
// sha256 of the purged ids, forwarded to gatekeeper) BEFORE the deletion,
// then deletes, then publishes the retention.purged change event.
package retention

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/events"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
)

// Engine runs retention sweeps.
type Engine struct {
	st    *store.Store
	ev    *events.Publisher
	evi   *s3.Client // evidence blob deleter; nil disables blob deletion
	actor store.Actor
	log   *slog.Logger
}

// New builds the purge engine. s3cfg configures the evidence object store
// (MinIO at MVP-A); a zero Endpoint disables blob deletion (refs are kept).
func New(st *store.Store, ev *events.Publisher, s3cfg manifest.S3Config, instanceID string, log *slog.Logger) *Engine {
	e := &Engine{
		st: st, ev: ev,
		actor: store.Actor{Type: "service", ID: instanceID},
		log:   log,
	}
	if s3cfg.Endpoint != "" {
		scheme := "http"
		if s3cfg.UseTLS {
			scheme = "https"
		}
		region := s3cfg.Region
		if region == "" {
			region = "us-east-1"
		}
		e.evi = s3.New(s3.Options{
			Region:       region,
			BaseEndpoint: aws.String(scheme + "://" + s3cfg.Endpoint),
			Credentials: credentials.NewStaticCredentialsProvider(
				s3cfg.AccessKeyID, s3cfg.SecretAccessKey, ""),
			UsePathStyle: true, // MinIO
		})
	}
	return e
}

// Run loops the sweep on a ticker until ctx is cancelled.
func (e *Engine) Run(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		return
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := e.Sweep(ctx); err != nil && e.log != nil {
				e.log.Error("retention sweep failed", "err", err)
			}
		}
	}
}

// Sweep performs one full pass: monthly findings partitions for the current
// and next month (doc 09 §4.2), then the per-tenant purge classes.
func (e *Engine) Sweep(ctx context.Context) error {
	if _, err := e.st.EnsureFindingPartitions(ctx, 1); err != nil {
		return fmt.Errorf("ensure partitions: %w", err)
	}
	tenants, err := e.st.ActiveTenantIDs(ctx)
	if err != nil {
		return fmt.Errorf("list tenants: %w", err)
	}
	for _, tenantID := range tenants {
		if err := ctx.Err(); err != nil {
			return err
		}
		policy, err := e.st.RetentionPolicy(ctx, tenantID)
		if err != nil {
			return fmt.Errorf("retention policy tenant %s: %w", tenantID, err)
		}
		if err := e.purgeResolvedFindings(ctx, tenantID, policy); err != nil {
			return fmt.Errorf("purge findings tenant %s: %w", tenantID, err)
		}
		if err := e.purgeEvidence(ctx, tenantID, policy); err != nil {
			return fmt.Errorf("purge evidence tenant %s: %w", tenantID, err)
		}
	}
	return nil
}

// purgeResolvedFindings deletes terminal findings older than the
// findings_resolved retention. Open findings are never touched
// ("indefinite" parses to no cutoff).
func (e *Engine) purgeResolvedFindings(ctx context.Context, tenantID string, policy map[string]any) error {
	cutoff, ok := cutoffFor(policy["findings_resolved"], time.Now().UTC())
	if !ok {
		return nil // indefinite or unset
	}
	batch, err := e.st.TerminalFindingIDs(ctx, tenantID, cutoff, 500)
	if err != nil {
		return err
	}
	if len(batch) == 0 {
		return nil
	}
	ids := make([]string, 0, len(batch))
	createdAts := make([]time.Time, 0, len(batch))
	for _, f := range batch {
		ids = append(ids, f.FindingID)
		createdAts = append(createdAts, f.CreatedAt)
	}
	hash := hashIDs(ids)
	// Audit BEFORE delete (certified deletion, doc 09 §10): the record of what
	// was purged must exist even if the deletion half-fails.
	if err := e.st.AuditOutbox(ctx, store.AuditRecord{
		TenantID:   tenantID,
		Actor:      e.actor,
		Action:     "retention.purge",
		ObjectRef:  "findings/resolved",
		ParamsHash: "sha256:" + hash,
	}); err != nil {
		return fmt.Errorf("purge audit: %w", err)
	}
	deleted, err := e.st.DeleteFindings(ctx, tenantID, ids, createdAts)
	if err != nil {
		return err
	}
	if deleted > 0 {
		e.publishPurged(ctx, tenantID, "findings_resolved", deleted, hash)
	}
	return nil
}

// purgeEvidence deletes outlived evidence blobs and clears their references.
func (e *Engine) purgeEvidence(ctx context.Context, tenantID string, policy map[string]any) error {
	cutoff, ok := evidenceCutoff(policy["evidence_blobs"], time.Now().UTC())
	if !ok {
		return nil
	}
	batch, err := e.st.ExpiredEvidence(ctx, tenantID, cutoff, 500)
	if err != nil {
		return err
	}
	if len(batch) == 0 {
		return nil
	}
	var ids []string
	for _, f := range batch {
		if f.EvidenceRef == nil {
			continue
		}
		if e.evi != nil {
			if err := e.deleteBlob(ctx, *f.EvidenceRef); err != nil {
				// Blob deletion failed: keep the reference, retry next sweep.
				if e.log != nil {
					e.log.Warn("evidence blob delete failed; will retry",
						"finding", f.FindingID, "ref", *f.EvidenceRef, "err", err)
				}
				continue
			}
		}
		if err := e.st.ClearEvidenceRef(ctx, tenantID, f.FindingID, f.CreatedAt); err != nil {
			return err
		}
		ids = append(ids, f.FindingID)
	}
	if len(ids) == 0 {
		return nil
	}
	hash := hashIDs(ids)
	if err := e.st.AuditOutbox(ctx, store.AuditRecord{
		TenantID:   tenantID,
		Actor:      e.actor,
		Action:     "retention.purge",
		ObjectRef:  "findings/evidence",
		ParamsHash: "sha256:" + hash,
	}); err != nil {
		return fmt.Errorf("purge audit: %w", err)
	}
	e.publishPurged(ctx, tenantID, "evidence_blobs", len(ids), hash)
	return nil
}

// deleteBlob removes one evidence object (s3://bucket/key or blob://…).
func (e *Engine) deleteBlob(ctx context.Context, ref string) error {
	bucket, key, err := manifest.MapURI(ref, "")
	if err != nil {
		return err
	}
	_, err = e.evi.DeleteObject(ctx, &s3.DeleteObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	return err
}

// publishPurged emits the retention.purged change event (doc 09 §2.1/§10).
func (e *Engine) publishPurged(ctx context.Context, tenantID, dataClass string, count int, hash string) {
	if e.ev == nil {
		return
	}
	if err := e.ev.Publish(ctx, events.Event{
		Type:      events.TypeRetentionPurged,
		Subject:   events.SubjectRetentionPurged,
		TenantID:  tenantID,
		ObjectRef: "retention/" + dataClass,
		Data: map[string]any{
			"data_class":  dataClass,
			"count":       count,
			"ids_sha256":  hash,
			"occurred_at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	}); err != nil && e.log != nil {
		e.log.Error("retention.purged publish failed", "err", err)
	}
}

// hashIDs renders the certified-deletion hash over the purged id set.
func hashIDs(ids []string) string {
	sorted := append([]string{}, ids...)
	sort.Strings(sorted)
	h := sha256.New()
	enc := json.NewEncoder(h)
	for _, id := range sorted {
		_ = enc.Encode(id)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// cutoffFor parses an ISO-8601-ish duration value from the retention policy
// ("P2Y", "P90D", "P1Y6M") into now-minus-duration. ok=false means the class
// is not purged ("indefinite", unset, or unparseable — fail-safe: never
// delete on a policy we cannot parse).
func cutoffFor(v any, now time.Time) (time.Time, bool) {
	s, _ := v.(string)
	d, ok := parseDuration(s)
	if !ok {
		return time.Time{}, false
	}
	return now.Add(-d), true
}

// evidenceCutoff parses the "finding+<duration>" evidence rule: the offset
// after the parent's terminal date.
func evidenceCutoff(v any, now time.Time) (time.Time, bool) {
	s, _ := v.(string)
	rest, found := strings.CutPrefix(s, "finding+")
	if !found {
		// Bare duration is also accepted.
		return cutoffFor(v, now)
	}
	d, ok := parseDuration(rest)
	if !ok {
		return time.Time{}, false
	}
	return now.Add(-d), true
}

// parseDuration parses the small ISO-8601 duration subset the retention
// profiles use: P<n>Y, P<n>M (months), P<n>D, combinable after one "P"
// (e.g. "P1Y90D"). Weeks are not used. "indefinite"/"" → ok=false.
func parseDuration(s string) (time.Duration, bool) {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "INDEFINITE" {
		return 0, false
	}
	s, ok := strings.CutPrefix(s, "P")
	if !ok || s == "" {
		return 0, false
	}
	const day = 24 * time.Hour
	var total time.Duration
	num := ""
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
			num += string(r)
		case r == 'Y' || r == 'M' || r == 'D':
			n, err := strconv.Atoi(num)
			if err != nil || n < 0 {
				return 0, false
			}
			num = ""
			switch r {
			case 'Y':
				total += time.Duration(n) * 365 * day
			case 'M':
				total += time.Duration(n) * 30 * day
			case 'D':
				total += time.Duration(n) * day
			}
		default:
			return 0, false
		}
	}
	if num != "" || total <= 0 {
		return 0, false
	}
	return total, true
}
