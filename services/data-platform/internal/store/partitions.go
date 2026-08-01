package store

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// EnsureFindingPartitions creates the monthly RANGE partitions of
// dp.findings for the current month plus ahead months (doc 09 §4.2: native
// monthly partitions at MVP-A). Idempotent; the migration's default
// partition keeps any earlier inserts safe.
func (s *Store) EnsureFindingPartitions(ctx context.Context, ahead int) ([]string, error) {
	if ahead < 0 {
		ahead = 0
	}
	now := time.Now().UTC()
	base := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	var created []string
	for i := 0; i <= ahead; i++ {
		start := base.AddDate(0, i, 0)
		end := start.AddDate(0, 1, 0)
		name := fmt.Sprintf("findings_y%04dm%02d", start.Year(), int(start.Month()))
		var exists bool
		if err := s.Pool.QueryRow(ctx,
			`SELECT to_regclass('dp.' || $1) IS NOT NULL`, name).Scan(&exists); err != nil {
			return created, err
		}
		if exists {
			continue
		}
		// Rows that landed in the default partition before its monthly
		// partition existed would violate the new constraint. Move them via
		// a temp holding table (a direct DELETE…INSERT CTE would route the
		// re-inserted rows right back into the default partition, since the
		// monthly partition does not exist yet). The lock blocks concurrent
		// inserts into the range for the duration of the relocation.
		tx, err := s.Pool.Begin(ctx)
		if err != nil {
			return created, err
		}
		if _, err := tx.Exec(ctx, `LOCK TABLE dp.findings_default IN SHARE ROW EXCLUSIVE MODE`); err != nil {
			_ = tx.Rollback(ctx)
			return created, err
		}
		if _, err := tx.Exec(ctx, `
			CREATE TEMP TABLE IF NOT EXISTS dp_findings_reloc
			    (LIKE dp.findings INCLUDING ALL) ON COMMIT DROP`); err != nil {
			_ = tx.Rollback(ctx)
			return created, err
		}
		if _, err := tx.Exec(ctx, `
			WITH moved AS (
			    DELETE FROM dp.findings_default
			    WHERE created_at >= $1 AND created_at < $2
			    RETURNING *
			)
			INSERT INTO dp_findings_reloc SELECT * FROM moved`,
			start, end); err != nil {
			_ = tx.Rollback(ctx)
			return created, fmt.Errorf("relocate default-partition rows for %s: %w", name, err)
		}
		stmt := fmt.Sprintf(
			`CREATE TABLE dp.%s PARTITION OF dp.findings FOR VALUES FROM ('%s') TO ('%s')`,
			name, start.Format("2006-01-02"), end.Format("2006-01-02"))
		if _, err := tx.Exec(ctx, stmt); err != nil {
			_ = tx.Rollback(ctx)
			// A concurrent creator races here; treat "already exists" as OK.
			if strings.Contains(err.Error(), "already exists") {
				continue
			}
			return created, fmt.Errorf("create partition %s: %w", name, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO dp.findings SELECT * FROM dp_findings_reloc`); err != nil {
			_ = tx.Rollback(ctx)
			return created, fmt.Errorf("reinsert relocated rows for %s: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return created, fmt.Errorf("commit partition %s: %w", name, err)
		}
		created = append(created, name)
	}
	return created, nil
}

// TerminalFindingIDs returns finding ids (with created_at partition keys)
// whose lifecycle reached a terminal state before cutoff and that are not
// under legal hold (doc 09 §10: legal hold freezes the retention subtree).
func (s *Store) TerminalFindingIDs(ctx context.Context, tenantID string, cutoff time.Time, limit int) ([]*Finding, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT f.tenant_id::text, f.finding_id::text, f.created_at
		FROM dp.findings f
		WHERE f.tenant_id = $1::uuid
		  AND f.state IN ('verified_closed','false_positive','accepted_risk')
		  AND f.legal_hold = false
		  AND COALESCE((
		        SELECT max(t.ts) FROM dp.finding_state_transitions t
		        WHERE t.tenant_id = f.tenant_id AND t.finding_id = f.finding_id
		          AND t.to_state IN ('verified_closed','false_positive','accepted_risk')
		      ), f.updated_at) < $2
		ORDER BY f.created_at ASC
		LIMIT $3`, tenantID, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Finding
	for rows.Next() {
		var f Finding
		if err := rows.Scan(&f.TenantID, &f.FindingID, &f.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &f)
	}
	return out, rows.Err()
}

// DeleteFindings removes findings + their transition history (certified
// deletion, doc 09 §10). Legal-hold rows are never passed here.
func (s *Store) DeleteFindings(ctx context.Context, tenantID string, ids []string, createdAts []time.Time) (int, error) {
	if len(ids) == 0 {
		return 0, nil
	}
	deleted := 0
	for i, id := range ids {
		if _, err := s.Pool.Exec(ctx, `
			DELETE FROM dp.finding_state_transitions
			WHERE tenant_id = $1::uuid AND finding_id = $2::uuid`, tenantID, id); err != nil {
			return deleted, err
		}
		tag, err := s.Pool.Exec(ctx, `
			DELETE FROM dp.findings
			WHERE tenant_id = $1::uuid AND finding_id = $2::uuid AND created_at = $3`,
			tenantID, id, createdAts[i])
		if err != nil {
			return deleted, err
		}
		deleted += int(tag.RowsAffected())
	}
	return deleted, nil
}

// ExpiredEvidence lists terminal findings whose evidence blob outlived the
// evidence retention (doc 09 §10: evidence blobs → parent finding + 90 days).
// Legal-hold rows are excluded — the hold freezes the whole subtree.
func (s *Store) ExpiredEvidence(ctx context.Context, tenantID string, cutoff time.Time, limit int) ([]*Finding, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT f.tenant_id::text, f.finding_id::text, f.created_at, f.evidence_ref
		FROM dp.findings f
		WHERE f.tenant_id = $1::uuid
		  AND f.state IN ('verified_closed','false_positive','accepted_risk')
		  AND f.legal_hold = false
		  AND f.evidence_ref IS NOT NULL
		  AND COALESCE((
		        SELECT max(t.ts) FROM dp.finding_state_transitions t
		        WHERE t.tenant_id = f.tenant_id AND t.finding_id = f.finding_id
		          AND t.to_state IN ('verified_closed','false_positive','accepted_risk')
		      ), f.updated_at) < $2
		LIMIT $3`, tenantID, cutoff, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Finding
	for rows.Next() {
		var f Finding
		var ref *string
		if err := rows.Scan(&f.TenantID, &f.FindingID, &f.CreatedAt, &ref); err != nil {
			return nil, err
		}
		f.EvidenceRef = ref
		out = append(out, &f)
	}
	return out, rows.Err()
}

// ClearEvidenceRef nulls the evidence reference after the blob was deleted.
func (s *Store) ClearEvidenceRef(ctx context.Context, tenantID, findingID string, created time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE dp.findings SET evidence_ref = NULL, updated_at = now()
		WHERE tenant_id = $1::uuid AND finding_id = $2::uuid AND created_at = $3`,
		tenantID, findingID, created)
	return err
}
