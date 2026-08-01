// Package publish is the Detect event-publishing surface:
//
//   - Findings: the canonical full stream on detect.findings
//     (doc 04 §4.3 → data platform 09, commanders), proto FindingReport in
//     the doc 01 §8.2 envelope, dedup-idempotent on finding_id (doc 04 §12).
//   - Alert mapper (D11, Ruling C8): the producer-side mapping from
//     CONFIRMED findings at/above a configurable tier threshold to doc 05
//     §5.2's AlertEvent v1 (JSON-schema only) inside a CloudEvents 1.0
//     envelope (source //aegisbastion/detect) on detect.alert, with the
//     MANDATORY authorization_token_id = the task's Scope Token jti.
//   - Ingest: findings also flow to the data-platform Ingest API
//     (doc 09 §2.2); when it is unavailable/unconfigured the local
//     detect.findings_fallback table keeps Detect runnable (doc 04 §13).
package publish

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/types/known/timestamppb"

	detectv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/detect/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/sdks/go/bus"
)

// SubjectFindings is the canonical full findings stream (doc 04 §4.3).
const SubjectFindings = "detect.findings"

// SubjectAlert is the Ruling C8 alert-mapping subject (doc 05 §5.2 input).
const SubjectAlert = "detect.alert"

// FindingsPublisher emits FindingReports on detect.findings. Publishing is
// idempotent on finding_id: Nats-Msg-Id = "finding-<finding_id>" so
// redelivered tasks do not double-publish (doc 04 §12).
type FindingsPublisher struct {
	b *bus.Client
}

// NewFindingsPublisher builds the publisher over the SDK bus client.
func NewFindingsPublisher(b *bus.Client) *FindingsPublisher {
	return &FindingsPublisher{b: b}
}

// PublishFinding emits one completed FindingReport.
func (p *FindingsPublisher) PublishFinding(ctx context.Context, fr *detectv1.FindingReport, missionID string, trace *platformv1.TraceContext) (string, error) {
	if fr.GetFindingId() == "" {
		return "", fmt.Errorf("publish: finding_id required (idempotency key)")
	}
	return p.b.Publish(ctx, SubjectFindings, fr, bus.PublishOptions{
		MissionID: missionID,
		Trace:     trace,
		EventID:   "finding-" + fr.GetFindingId(),
	})
}

// Now is a small helper for validated_at/first_seen timestamps (UTC).
func Now() *timestamppb.Timestamp { return timestamppb.Now() }
