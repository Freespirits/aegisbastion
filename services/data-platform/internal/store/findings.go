package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// FindingUpsert is one finding write item (ingest or bus consumer).
type FindingUpsert struct {
	FindingID   string // optional; server assigns UUIDv7 when empty
	AssetUID    string // direct reference…
	AssetType   string // …or resolved via (type, value) in the tenant
	AssetValue  string
	Module      string
	CheckID     string
	Title       string
	Severity    string
	State       string // target lifecycle state (default new) — advanceTo
	Fingerprint string
	Validation  map[string]any
	Risk        map[string]any
	EvidenceRef string
	Occurrence  int
	FirstSeen   time.Time
	LastSeen    time.Time
	TaskID      string
	Compliance  map[string]any
	Sensitive   bool
	LegalHold   bool
}

// FindingOutcome reports what a finding upsert did (drives dp.finding.* events).
type FindingOutcome struct {
	FindingID      string
	AssetUID       string
	Created        bool
	StateChanged   bool
	FromState      string
	ToState        string
	IllegalSkipped bool // proposed state unreachable — kept current state
}

// UpsertFindingTx inserts a finding, or merges into the existing row when
// the (tenant, fingerprint) dedup key matches (doc 04 §7.2 cross-run dedup:
// re-scans update last_seen instead of spamming new findings). The lifecycle
// state machine (doc 04 §7.3) is enforced: a proposed state is reached via
// the legal hop path and every hop is recorded in
// dp.finding_state_transitions; unreachable proposals keep the current state
// and set IllegalSkipped.
func UpsertFindingTx(ctx context.Context, tx pgx.Tx, tenantID string, f FindingUpsert,
	actor Actor, advance func(from, to string) ([]string, bool)) (*FindingOutcome, error) {

	assetUID, err := resolveAssetRefTx(ctx, tx, tenantID, f.AssetUID, f.AssetType, f.AssetValue)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	fs, ls := f.FirstSeen, f.LastSeen
	if fs.IsZero() {
		fs = now
	}
	if ls.IsZero() {
		ls = now
	}
	validation := f.Validation
	if validation == nil {
		validation = map[string]any{"status": "unvalidated"}
	}
	validationJSON, err := json.Marshal(validation)
	if err != nil {
		return nil, fmt.Errorf("validation: %w", err)
	}
	risk := f.Risk
	if risk == nil {
		risk = map[string]any{}
	}
	riskJSON, err := json.Marshal(risk)
	if err != nil {
		return nil, fmt.Errorf("risk: %w", err)
	}
	var complianceJSON []byte
	if f.Compliance != nil {
		if complianceJSON, err = json.Marshal(f.Compliance); err != nil {
			return nil, fmt.Errorf("compliance: %w", err)
		}
	}
	occ := f.Occurrence
	if occ < 1 {
		occ = 1
	}
	target := f.State
	if target == "" {
		target = "new"
	}
	actorJSON, err := json.Marshal(actor)
	if err != nil {
		return nil, fmt.Errorf("actor: %w", err)
	}

	out := &FindingOutcome{AssetUID: assetUID, ToState: target}

	// --- dedup: existing finding with the same fingerprint ---------------
	var (
		existingID, existingState string
		existingCreated           time.Time
	)
	if f.Fingerprint != "" {
		err = tx.QueryRow(ctx, `
			SELECT finding_id::text, state, created_at
			FROM dp.findings
			WHERE tenant_id = $1::uuid AND fingerprint = $2
			ORDER BY created_at DESC LIMIT 1
			FOR UPDATE`, tenantID, f.Fingerprint).
			Scan(&existingID, &existingState, &existingCreated)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}

	if existingID != "" {
		out.FindingID = existingID
		out.FromState = existingState
		if _, err := tx.Exec(ctx, `
			UPDATE dp.findings SET
			    occurrence = occurrence + $4,
			    last_seen  = GREATEST(last_seen, $5),
			    first_seen = LEAST(first_seen, $6),
			    updated_at = now(),
			    validation = $7,
			    risk       = $8,
			    evidence_ref = COALESCE($9, evidence_ref),
			    legal_hold = legal_hold OR $10,
			    sensitive  = sensitive OR $11
			WHERE tenant_id = $1::uuid AND finding_id = $2::uuid AND created_at = $3`,
			tenantID, existingID, existingCreated, occ, ls, fs,
			validationJSON, riskJSON, nilIfEmpty(f.EvidenceRef), f.LegalHold, f.Sensitive); err != nil {
			return nil, fmt.Errorf("merge finding %s: %w", existingID, err)
		}
		if target != existingState {
			hops, ok := advance(existingState, target)
			if !ok {
				out.IllegalSkipped = true
				out.ToState = existingState
			} else {
				prev := existingState
				for _, hop := range hops {
					if err := recordTransitionTx(ctx, tx, tenantID, existingID, prev, hop, actorJSON, f.TaskID, "ingest: state proposed by "+f.Module); err != nil {
						return nil, err
					}
					prev = hop
				}
				if _, err := tx.Exec(ctx, `
					UPDATE dp.findings SET state = $4, updated_at = now()
					WHERE tenant_id = $1::uuid AND finding_id = $2::uuid AND created_at = $3`,
					tenantID, existingID, existingCreated, target); err != nil {
					return nil, err
				}
				out.StateChanged = true
				out.ToState = target
			}
		}
		return out, nil
	}

	// --- insert path ------------------------------------------------------
	findingID := f.FindingID
	if findingID == "" {
		findingID = newUUIDv7()
	}
	out.FindingID = findingID
	out.Created = true
	_, err = tx.Exec(ctx, `
		INSERT INTO dp.findings
		    (tenant_id, finding_id, created_at, updated_at, asset_uid, module, check_id,
		     title, severity, state, fingerprint, validation, risk, evidence_ref,
		     occurrence, first_seen, last_seen, task_id, compliance, legal_hold, sensitive)
		VALUES ($1, $2::uuid, $3, $4, $5::uuid, $6, $7, $8, $9, 'new', $10, $11, $12, $13,
		        $14, $15, $16, $17, $18, $19, $20)`,
		tenantID, findingID, now, now, assetUID, f.Module, f.CheckID,
		f.Title, f.Severity, nilIfEmpty(f.Fingerprint), validationJSON, riskJSON,
		nilIfEmpty(f.EvidenceRef), occ, fs, ls, nilIfEmpty(f.TaskID), complianceJSON,
		f.LegalHold, f.Sensitive)
	if err != nil {
		return nil, fmt.Errorf("insert finding: %w", err)
	}
	// Advance from 'new' to the proposed state, recording each hop.
	if target != "new" {
		hops, ok := advance("new", target)
		if !ok {
			out.IllegalSkipped = true
			out.ToState = "new"
		} else {
			prev := "new"
			for _, hop := range hops {
				if err := recordTransitionTx(ctx, tx, tenantID, findingID, prev, hop, actorJSON, f.TaskID, "ingest: state proposed by "+f.Module); err != nil {
					return nil, err
				}
				prev = hop
			}
			if _, err := tx.Exec(ctx, `
				UPDATE dp.findings SET state = $4, updated_at = now()
				WHERE tenant_id = $1::uuid AND finding_id = $2::uuid AND created_at = $3`,
				tenantID, findingID, now, target); err != nil {
				return nil, err
			}
			out.StateChanged = true
			out.ToState = target
		}
	}
	return out, nil
}

// recordTransitionTx appends one lifecycle transition row.
func recordTransitionTx(ctx context.Context, tx pgx.Tx, tenantID, findingID, from, to string,
	actorJSON []byte, taskID, note string) error {
	_, err := tx.Exec(ctx, `
		INSERT INTO dp.finding_state_transitions
		    (tenant_id, finding_id, from_state, to_state, actor, task_id, note)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, $7)`,
		tenantID, findingID, nilIfEmpty(from), to, actorJSON,
		nilIfEmpty(taskID), nilIfEmpty(note))
	if err != nil {
		return fmt.Errorf("record transition %s→%s: %w", from, to, err)
	}
	return nil
}

// ApplyTransitionTx applies one operator-driven lifecycle transition within
// tx. from==to is a recorded no-op only when identical (returns changed=false);
// illegal edges return ok=false.
func ApplyTransitionTx(ctx context.Context, tx pgx.Tx, tenantID, findingID, to string,
	actor Actor, taskID, note string) (from string, changed bool, ok bool, err error) {
	var curState string
	var created time.Time
	err = tx.QueryRow(ctx, `
		SELECT state, created_at FROM dp.findings
		WHERE tenant_id = $1::uuid AND finding_id = $2::uuid
		FOR UPDATE`, tenantID, findingID).Scan(&curState, &created)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, false, nil
	}
	if err != nil {
		return "", false, false, err
	}
	if curState == to {
		return curState, false, true, nil
	}
	actorJSON, err := json.Marshal(actor)
	if err != nil {
		return "", false, false, err
	}
	// Single-hop legality (doc 04 §7.3); multi-hop only via ingest advance.
	if !LegalTransition(curState, to) {
		return curState, false, false, nil
	}
	if err := recordTransitionTx(ctx, tx, tenantID, findingID, curState, to, actorJSON, taskID, note); err != nil {
		return "", false, false, err
	}
	if _, err := tx.Exec(ctx, `
		UPDATE dp.findings SET state = $4, updated_at = now()
		WHERE tenant_id = $1::uuid AND finding_id = $2::uuid AND created_at = $3`,
		tenantID, findingID, created, to); err != nil {
		return "", false, false, err
	}
	return curState, true, true, nil
}

// LegalTransition is the store-local edge check (kept here so store has no
// dependency on the lifecycle package; identical to lifecycle.Legal).
func LegalTransition(from, to string) bool {
	switch from {
	case "new":
		return to == "triaged"
	case "triaged":
		return to == "validating" || to == "false_positive"
	case "validating":
		return to == "confirmed_open" || to == "accepted_risk"
	case "confirmed_open":
		return to == "remediation_claimed"
	case "remediation_claimed":
		return to == "verified_closed" || to == "reopened"
	case "reopened":
		return to == "confirmed_open"
	}
	return false
}

// GetFinding reads one tenant-scoped finding.
func (s *Store) GetFinding(ctx context.Context, tenantID, findingID string) (*Finding, error) {
	rows, err := s.Pool.Query(ctx, findingSelect+`
		WHERE tenant_id = $1::uuid AND finding_id = $2::uuid
		ORDER BY created_at DESC LIMIT 1`, tenantID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	return scanFinding(rows)
}

const findingSelect = `
	SELECT tenant_id::text, finding_id::text, created_at, updated_at, asset_uid::text,
	       module, check_id, title, severity, state, fingerprint, validation, risk,
	       evidence_ref, occurrence, first_seen, last_seen, task_id, compliance,
	       legal_hold, sensitive
	FROM dp.findings `

// FindingFilter narrows finding list queries.
type FindingFilter struct {
	Modules       []string
	Severities    []string
	States        []string
	AssetUID      string
	TaskID        string
	CheckIDPrefix string
	Since         *time.Time // last_seen >= since
}

// ListFindings returns one keyset page (ORDER BY created_at DESC,
// finding_id) plus the tenant-scoped total.
func (s *Store) ListFindings(ctx context.Context, tenantID string, f FindingFilter, limit int, afterCreated time.Time, afterID string) ([]*Finding, int, error) {
	where := "tenant_id = $1::uuid"
	args := []any{tenantID}
	n := 1
	if len(f.Modules) > 0 {
		n++
		where += fmt.Sprintf(" AND module = ANY($%d)", n)
		args = append(args, f.Modules)
	}
	if len(f.Severities) > 0 {
		n++
		where += fmt.Sprintf(" AND severity = ANY($%d)", n)
		args = append(args, f.Severities)
	}
	if len(f.States) > 0 {
		n++
		where += fmt.Sprintf(" AND state = ANY($%d)", n)
		args = append(args, f.States)
	}
	if f.AssetUID != "" {
		n++
		where += fmt.Sprintf(" AND asset_uid = $%d::uuid", n)
		args = append(args, f.AssetUID)
	}
	if f.TaskID != "" {
		n++
		where += fmt.Sprintf(" AND task_id = $%d", n)
		args = append(args, f.TaskID)
	}
	if f.CheckIDPrefix != "" {
		n++
		where += fmt.Sprintf(" AND check_id LIKE $%d", n)
		args = append(args, f.CheckIDPrefix+"%")
	}
	if f.Since != nil {
		n++
		where += fmt.Sprintf(" AND last_seen >= $%d", n)
		args = append(args, *f.Since)
	}
	var total int
	if err := s.Pool.QueryRow(ctx,
		"SELECT count(*) FROM dp.findings WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	if !afterCreated.IsZero() {
		n++
		where += fmt.Sprintf(" AND (created_at, finding_id) < ($%d, $%d::uuid)", n, n+1)
		args = append(args, afterCreated, afterID)
		n++
	}
	n++
	rows, err := s.Pool.Query(ctx, findingSelect+`
		WHERE `+where+`
		ORDER BY created_at DESC, finding_id DESC LIMIT $`+fmt.Sprint(n), append(args, limit)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, f)
	}
	return out, total, rows.Err()
}

func scanFinding(rows pgx.Rows) (*Finding, error) {
	var f Finding
	var validation, risk, compliance []byte
	var fingerprint, evidenceRef, taskID *string
	err := rows.Scan(&f.TenantID, &f.FindingID, &f.CreatedAt, &f.UpdatedAt, &f.AssetUID,
		&f.Module, &f.CheckID, &f.Title, &f.Severity, &f.State, &fingerprint,
		&validation, &risk, &evidenceRef, &f.Occurrence, &f.FirstSeen, &f.LastSeen,
		&taskID, &compliance, &f.LegalHold, &f.Sensitive)
	if err != nil {
		return nil, err
	}
	f.Fingerprint, f.EvidenceRef, f.TaskID = fingerprint, evidenceRef, taskID
	_ = json.Unmarshal(validation, &f.Validation)
	_ = json.Unmarshal(risk, &f.Risk)
	if compliance != nil {
		_ = json.Unmarshal(compliance, &f.Compliance)
	}
	return &f, nil
}

// ListTransitions returns the lifecycle history of one finding.
func (s *Store) ListTransitions(ctx context.Context, tenantID, findingID string) ([]*StateTransition, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT tenant_id::text, finding_id::text, from_state, to_state, actor, task_id, note, ts
		FROM dp.finding_state_transitions
		WHERE tenant_id = $1::uuid AND finding_id = $2::uuid
		ORDER BY ts ASC, id ASC`, tenantID, findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*StateTransition
	for rows.Next() {
		var t StateTransition
		var actor []byte
		if err := rows.Scan(&t.TenantID, &t.FindingID, &t.FromState, &t.ToState,
			&actor, &t.TaskID, &t.Note, &t.TS); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(actor, &t.Actor)
		out = append(out, &t)
	}
	return out, rows.Err()
}

// TaskRollup is the ingest-side attribution rollup for one Orchestrator task
// (doc 09 §3.1: dp stores no task records; it indexes ingested data by task_id).
type TaskRollup struct {
	TaskID             string         `json:"task_id"`
	TenantID           string         `json:"tenant_id"`
	Batches            int            `json:"batches"`
	RejectedBatches    int            `json:"rejected_batches"`
	AssetsTouched      int            `json:"assets_touched"`
	FindingsProduced   int            `json:"findings_produced"`
	FindingsBySeverity map[string]int `json:"findings_by_severity"`
	FirstActivity      *time.Time     `json:"first_activity,omitempty"`
	LastActivity       *time.Time     `json:"last_activity,omitempty"`
}

// Rollup computes the per-task attribution view (tenant-scoped, fail-closed).
func (s *Store) Rollup(ctx context.Context, tenantID, taskID string) (*TaskRollup, error) {
	r := &TaskRollup{TaskID: taskID, TenantID: tenantID, FindingsBySeverity: map[string]int{}}
	if err := s.Pool.QueryRow(ctx, `
		SELECT count(*), count(*) FILTER (WHERE status = 'rejected'),
		       min(received_at), max(received_at)
		FROM dp.ingest_batches
		WHERE tenant_id = $1::uuid AND task_id = $2`, tenantID, taskID).
		Scan(&r.Batches, &r.RejectedBatches, &r.FirstActivity, &r.LastActivity); err != nil {
		return nil, err
	}
	if err := s.Pool.QueryRow(ctx, `
		SELECT count(DISTINCT asset_id) FROM dp.finding_provenance
		WHERE tenant_id = $1::uuid AND task_id = $2 AND asset_id IS NOT NULL`,
		tenantID, taskID).Scan(&r.AssetsTouched); err != nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `
		SELECT severity, count(*) FROM dp.findings
		WHERE tenant_id = $1::uuid AND task_id = $2
		GROUP BY severity`, tenantID, taskID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var sev string
		var c int
		if err := rows.Scan(&sev, &c); err != nil {
			return nil, err
		}
		r.FindingsBySeverity[sev] = c
		r.FindingsProduced += c
	}
	if r.Batches == 0 && r.FindingsProduced == 0 && r.AssetsTouched == 0 {
		return nil, nil // unknown task in this tenant
	}
	return r, rows.Err()
}
