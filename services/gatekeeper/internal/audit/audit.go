// Package audit implements audit-service (doc 11 §2.1.6/§3.4, doc 01 §10.4):
// a hash-chained, append-only audit log in gatekeeper.audit_events.
//
// Chain rule (doc 11 §3.4):
//
//	event_hash = sha256(prev_hash || JCS_canonical_json(event_without_hash))
//
// where prev_hash is the previous link's hex hash string ("" for genesis) and
// the canonical form is JCS (RFC 8785). One chain per org partition; sequence
// numbers are assigned under a Postgres advisory lock keyed by org, so a
// single gatekeeper writer keeps the chain gap-free. The DB itself enforces
// append-only (migration 000002 trigger denies UPDATE/DELETE).
//
// Fail-closed: R1–R3 decisions are audit-gated — when Record returns an
// error, policy-service converts it to an AUDIT_UNAVAILABLE deny (step 11).
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ids"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/jsonx"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
)

// Event kinds (doc 11 §3.4 v1 vocabulary).
const (
	KindAuthorizationDecision = "authorization.decision"
	KindTokenMinted           = "token.minted"
	KindTokenRevoked          = "token.revoked"
	KindROECreated            = "roe.created"
	KindROEUpdated            = "roe.updated"
	KindROEActivated          = "roe.activated"
	KindROESuspended          = "roe.suspended"
	KindROERevoked            = "roe.revoked"
	KindApprovalRequested     = "approval.requested"
	KindApprovalGranted       = "approval.granted"
	KindApprovalRejected      = "approval.rejected"
	KindExecutionStarted      = "execution.started"
	KindExecutionCompleted    = "execution.completed"
	KindExecutionHalted       = "execution.halted"
	KindRevocationIssued      = "revocation.issued"
	KindRBACChanged           = "rbac.changed"
	KindAdminAction           = "admin.action"
)

// kindFromProto maps the proto enum to the stored kind string.
var kindFromProto = map[gatekeeperv1.AuditEventKind]string{
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_AUTHORIZATION_DECISION: KindAuthorizationDecision,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_TOKEN_MINTED:           KindTokenMinted,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_TOKEN_REVOKED:          KindTokenRevoked,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_ROE_CREATED:            KindROECreated,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_ROE_UPDATED:            KindROEUpdated,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_ROE_ACTIVATED:          KindROEActivated,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_ROE_SUSPENDED:          KindROESuspended,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_ROE_REVOKED:            KindROERevoked,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_APPROVAL_REQUESTED:     KindApprovalRequested,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_APPROVAL_GRANTED:       KindApprovalGranted,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_APPROVAL_REJECTED:      KindApprovalRejected,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_EXECUTION_STARTED:      KindExecutionStarted,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_EXECUTION_COMPLETED:    KindExecutionCompleted,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_EXECUTION_HALTED:       KindExecutionHalted,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_REVOCATION_ISSUED:      KindRevocationIssued,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_RBAC_CHANGED:           KindRBACChanged,
	gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_ADMIN_ACTION:           KindAdminAction,
}

// Input is one event to append to the chain.
type Input struct {
	EventID    string         // assigned when empty
	OrgID      string         // chain partition; "" is the platform partition
	Kind       string         // one of the Kind* constants
	Actor      map[string]any // {kind, id, spiffe_id?}
	Subject    map[string]any // {mission_id?, task_id?, roe_id?}
	Payload    map[string]any // small payloads inline
	PayloadRef string         // large payloads by ref
	TraceID    string
	OccurredAt time.Time
}

// Event is a chained, persisted audit event.
type Event struct {
	EventID       string
	OrgID         string
	Seq           uint64
	PrevHash      string
	EventHash     string
	Kind          string
	Actor         map[string]any
	Subject       map[string]any
	Payload       map[string]any
	PayloadRef    string
	PayloadSHA256 string
	TraceID       string
	OccurredAt    time.Time
	RecordedAt    time.Time
}

// Hash computes the chain link hash for a fully-populated event:
// sha256(prev_hash || JCS(event_without_hash)).
func Hash(e *Event) (string, error) {
	doc := map[string]any{
		"event_id":    e.EventID,
		"org_id":      e.OrgID,
		"seq":         e.Seq,
		"prev_hash":   e.PrevHash,
		"kind":        e.Kind,
		"actor":       orEmpty(e.Actor),
		"subject":     orEmpty(e.Subject),
		"occurred_at": e.OccurredAt.UTC().Format(time.RFC3339Nano),
		"recorded_at": e.RecordedAt.UTC().Format(time.RFC3339Nano),
	}
	if e.Payload != nil {
		doc["payload"] = e.Payload
	}
	if e.PayloadRef != "" {
		doc["payload_ref"] = e.PayloadRef
	}
	if e.PayloadSHA256 != "" {
		doc["payload_sha256"] = e.PayloadSHA256
	}
	if e.TraceID != "" {
		doc["trace_id"] = e.TraceID
	}
	canon, err := jsonx.Canonical(doc)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(append([]byte(e.PrevHash), canon...))
	return hex.EncodeToString(sum[:]), nil
}

func orEmpty(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

// Service is the audit-service: gRPC ingest, hash-chain builder, VerifyChain.
// It is the AUDIT_WRITE dependency of policy pipeline step 11 — Record must
// only return nil when the event is durably persisted.
type Service struct {
	gatekeeperv1.UnimplementedAuditServiceServer
	db  *store.DB
	mu  sync.Mutex // serialize chain writes within this process
	now func() time.Time
}

// New builds the service on the gatekeeper schema.
func New(db *store.DB) *Service {
	return &Service{db: db, now: time.Now}
}

// Record appends one event to the org's chain and persists it. Errors mean
// the event is NOT durably recorded (callers fail closed).
func (s *Service) Record(ctx context.Context, in Input) (*Event, error) {
	evs, err := s.RecordBatch(ctx, []Input{in})
	if err != nil {
		return nil, err
	}
	return evs[0], nil
}

// RecordBatch appends a batch, preserving chain order.
func (s *Service) RecordBatch(ctx context.Context, ins []Input) ([]*Event, error) {
	if len(ins) == 0 {
		return nil, nil
	}
	// Group by org partition, keeping input order within each partition.
	byOrg := map[string][]int{}
	var orgs []string
	for i, in := range ins {
		if _, seen := byOrg[in.OrgID]; !seen {
			orgs = append(orgs, in.OrgID)
		}
		byOrg[in.OrgID] = append(byOrg[in.OrgID], i)
	}
	out := make([]*Event, len(ins))
	for _, org := range orgs {
		evs, err := s.recordPartition(ctx, org, indexInputs(ins, byOrg[org]))
		if err != nil {
			return nil, err
		}
		for j, idx := range byOrg[org] {
			out[idx] = evs[j]
		}
	}
	return out, nil
}

func indexInputs(ins []Input, idxs []int) []Input {
	out := make([]Input, len(idxs))
	for i, idx := range idxs {
		out[i] = ins[idx]
	}
	return out
}

func (s *Service) recordPartition(ctx context.Context, org string, ins []Input) ([]*Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tx, err := s.db.Pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// One chain writer per org partition (doc 11 §6): advisory xact lock +
	// MAX(seq) gives gap-free sequence assignment even with multiple pods.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock(hashtextextended($1, 42))", org); err != nil {
		return nil, fmt.Errorf("audit: lock partition %q: %w", org, err)
	}
	var prevHash string
	var seq uint64
	row := tx.QueryRow(ctx,
		"SELECT seq, event_hash FROM audit_events WHERE org_id = $1 ORDER BY seq DESC LIMIT 1", org)
	var lastSeq uint64
	var lastHash string
	switch err := row.Scan(&lastSeq, &lastHash); {
	case err == nil:
		seq, prevHash = lastSeq+1, lastHash
	case err == pgx.ErrNoRows:
		seq, prevHash = 1, ""
	default:
		return nil, fmt.Errorf("audit: chain head %q: %w", org, err)
	}

	evs := make([]*Event, 0, len(ins))
	for _, in := range ins {
		ev := &Event{
			EventID:    in.EventID,
			OrgID:      org,
			Seq:        seq,
			PrevHash:   prevHash,
			Kind:       in.Kind,
			Actor:      orEmpty(in.Actor),
			Subject:    orEmpty(in.Subject),
			Payload:    in.Payload,
			PayloadRef: in.PayloadRef,
			TraceID:    in.TraceID,
			OccurredAt: in.OccurredAt,
			// Postgres timestamptz is microsecond-precision: truncate before
			// hashing so VerifyRange recomputation matches byte-for-byte.
			RecordedAt: s.now().UTC().Truncate(time.Microsecond),
		}
		if ev.EventID == "" {
			ev.EventID = ids.New("evt")
		}
		if ev.OccurredAt.IsZero() {
			ev.OccurredAt = ev.RecordedAt
		} else {
			ev.OccurredAt = ev.OccurredAt.UTC().Truncate(time.Microsecond)
		}
		if ev.PayloadRef != "" && in.Payload != nil {
			raw, err := json.Marshal(in.Payload)
			if err != nil {
				return nil, fmt.Errorf("audit: payload marshal: %w", err)
			}
			sum := sha256.Sum256(raw)
			ev.PayloadSHA256 = hex.EncodeToString(sum[:])
		}
		h, err := Hash(ev)
		if err != nil {
			return nil, fmt.Errorf("audit: hash: %w", err)
		}
		ev.EventHash = h

		var payloadJSON, payloadSHA *string
		if in.Payload != nil && ev.PayloadRef == "" {
			raw, _ := json.Marshal(in.Payload)
			s := string(raw)
			payloadJSON = &s
		}
		if ev.PayloadSHA256 != "" {
			payloadSHA = &ev.PayloadSHA256
		}
		var payloadRef *string
		if ev.PayloadRef != "" {
			payloadRef = &ev.PayloadRef
		}
		var traceID *string
		if ev.TraceID != "" {
			traceID = &ev.TraceID
		}
		actorJSON, _ := json.Marshal(ev.Actor)
		subjectJSON, _ := json.Marshal(ev.Subject)

		if _, err := tx.Exec(ctx, `
			INSERT INTO audit_events
			  (event_id, org_id, seq, prev_hash, event_hash, kind, actor, subject,
			   payload, payload_ref, payload_sha256, trace_id, occurred_at, recorded_at)
			VALUES ($1,$2,$3,$4,$5,$6,$7::jsonb,$8::jsonb,$9::jsonb,$10,$11,$12,$13,$14)`,
			ev.EventID, ev.OrgID, ev.Seq, ev.PrevHash, ev.EventHash, ev.Kind,
			string(actorJSON), string(subjectJSON), nullableJSON(payloadJSON),
			payloadRef, payloadSHA, traceID, ev.OccurredAt, ev.RecordedAt); err != nil {
			return nil, fmt.Errorf("audit: insert seq %d: %w", ev.Seq, err)
		}
		evs = append(evs, ev)
		seq++
		prevHash = ev.EventHash
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("audit: commit: %w", err)
	}
	return evs, nil
}

func nullableJSON(s *string) any {
	if s == nil {
		return nil
	}
	return *s
}

// VerifyRange re-checks linkage and hashes over [fromSeq, toSeq] of an org
// partition (auditor API, doc 11 §3.4). Gaps lists missing or invalid seqs.
func (s *Service) VerifyRange(ctx context.Context, org string, fromSeq, toSeq uint64) (valid bool, gaps []uint64, err error) {
	rows, err := s.db.Pool.Query(ctx, `
		SELECT event_id, org_id, seq, prev_hash, event_hash, kind, actor, subject,
		       payload, payload_ref, payload_sha256, trace_id, occurred_at, recorded_at
		FROM audit_events
		WHERE org_id = $1 AND seq BETWEEN $2 AND $3
		ORDER BY seq`, org, fromSeq, toSeq)
	if err != nil {
		return false, nil, fmt.Errorf("audit: verify query: %w", err)
	}
	defer rows.Close()

	bySeq := map[uint64]*Event{}
	for rows.Next() {
		var e Event
		var actor, subject string
		var payload, payloadRef, payloadSHA, traceID *string
		if err := rows.Scan(&e.EventID, &e.OrgID, &e.Seq, &e.PrevHash, &e.EventHash, &e.Kind,
			&actor, &subject, &payload, &payloadRef, &payloadSHA, &traceID, &e.OccurredAt, &e.RecordedAt); err != nil {
			return false, nil, fmt.Errorf("audit: verify scan: %w", err)
		}
		_ = json.Unmarshal([]byte(actor), &e.Actor)
		_ = json.Unmarshal([]byte(subject), &e.Subject)
		if payload != nil {
			_ = json.Unmarshal([]byte(*payload), &e.Payload)
		}
		if payloadRef != nil {
			e.PayloadRef = *payloadRef
		}
		if payloadSHA != nil {
			e.PayloadSHA256 = *payloadSHA
		}
		if traceID != nil {
			e.TraceID = *traceID
		}
		bySeq[e.Seq] = &e
	}
	if err := rows.Err(); err != nil {
		return false, nil, err
	}

	valid = true
	var prev string
	for seq := fromSeq; seq <= toSeq; seq++ {
		e, ok := bySeq[seq]
		if !ok {
			valid = false
			gaps = append(gaps, seq)
			prev = "" // chain broken; next present event must link to nothing we trust
			continue
		}
		if seq > fromSeq && prev != "" && e.PrevHash != prev {
			valid = false
			gaps = append(gaps, seq)
		}
		want, herr := Hash(e)
		if herr != nil || want != e.EventHash {
			valid = false
			gaps = append(gaps, seq)
		}
		prev = e.EventHash
	}
	return valid, gaps, nil
}

// ---------------------------------------------------------------------------
// gRPC surface (gatekeeper.v1.AuditService)
// ---------------------------------------------------------------------------

// IngestAuditEvents chains and durably persists a batch (fail-closed
// semantics: any error means the caller must treat the events as unrecorded).
func (s *Service) IngestAuditEvents(ctx context.Context, req *gatekeeperv1.IngestAuditEventsRequest) (*gatekeeperv1.IngestAuditEventsResponse, error) {
	ins := make([]Input, 0, len(req.GetEvents()))
	for _, e := range req.GetEvents() {
		kind, ok := kindFromProto[e.GetKind()]
		if !ok {
			return nil, fmt.Errorf("audit: unknown event kind %v", e.GetKind())
		}
		in := Input{
			EventID: e.GetEventId(),
			Kind:    kind,
			Actor: map[string]any{
				"kind": e.GetActor().GetKind(),
				"id":   e.GetActor().GetId(),
			},
			PayloadRef: e.GetPayloadRef(),
			TraceID:    e.GetTraceId(),
		}
		if spiffe := e.GetActor().GetSpiffeId(); spiffe != "" {
			in.Actor["spiffe_id"] = spiffe
		}
		if ts := e.GetOccurredAt(); ts != nil {
			in.OccurredAt = ts.AsTime()
		}
		ins = append(ins, in)
	}
	evs, err := s.RecordBatch(ctx, ins)
	if err != nil {
		return nil, err
	}
	return &gatekeeperv1.IngestAuditEventsResponse{Recorded: uint32(len(evs))}, nil
}

// VerifyChain implements the auditor chain-verification RPC.
func (s *Service) VerifyChain(ctx context.Context, req *gatekeeperv1.VerifyChainRequest) (*gatekeeperv1.VerifyChainResponse, error) {
	valid, gaps, err := s.VerifyRange(ctx, req.GetOrgId(), req.GetFromSeq(), req.GetToSeq())
	if err != nil {
		return nil, err
	}
	return &gatekeeperv1.VerifyChainResponse{Valid: valid, Gaps: gaps}, nil
}

// ToProto renders a stored event for APIs that need the proto form.
func ToProto(e *Event) *gatekeeperv1.AuditEvent {
	kind := gatekeeperv1.AuditEventKind_AUDIT_EVENT_KIND_UNSPECIFIED
	for k, v := range kindFromProto {
		if v == e.Kind {
			kind = k
			break
		}
	}
	actor := &gatekeeperv1.AuditActor{
		Kind: fmt.Sprint(e.Actor["kind"]),
		Id:   fmt.Sprint(e.Actor["id"]),
	}
	if sp, ok := e.Actor["spiffe_id"].(string); ok {
		actor.SpiffeId = sp
	}
	return &gatekeeperv1.AuditEvent{
		EventId:       e.EventID,
		Seq:           e.Seq,
		PrevHash:      e.PrevHash,
		EventHash:     e.EventHash,
		Kind:          kind,
		Actor:         actor,
		OccurredAt:    timestamppb.New(e.OccurredAt),
		RecordedAt:    timestamppb.New(e.RecordedAt),
		PayloadRef:    e.PayloadRef,
		PayloadSha256: e.PayloadSHA256,
		TraceId:       e.TraceID,
	}
}
