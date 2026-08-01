// Package store is the Detect module's local Postgres surface (schema
// detect, migration 000004): the MVP findings_fallback table (doc 04 §13 —
// mirrors dp.findings so migration is a copy once 09 ships), the cross-run
// fingerprint cache (doc 04 §7.2), and the false-positive suppression list
// with monthly expiry (doc 04 §7.3). These are operational stores, NOT the
// system of record — findings of record live in the data platform (Ruling
// C4).
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps the pgx pool scoped to the detect schema.
type Store struct {
	Pool *pgxpool.Pool
	// TenantID scopes KnownView Record calls (set by main from config).
	TenantID string
}

// New connects and sets the search path (schema-per-context; one DB
// "aegisbastion").
func New(ctx context.Context, databaseURL, searchPath string) (*Store, error) {
	if databaseURL == "" {
		return nil, errors.New("store: DATABASE_URL required")
	}
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: parse DATABASE_URL: %w", err)
	}
	if searchPath != "" {
		cfg.ConnConfig.RuntimeParams["search_path"] = searchPath
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{Pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.Pool.Close() }

// FindingRow is one detect.findings_fallback record (mirrors dp.findings).
type FindingRow struct {
	TenantID    string
	FindingID   string // uuid (ids.UUIDv5 of the wire fnd_… id)
	CheckID     string
	Title       string
	Severity    string // info|low|medium|high|critical (CHECK constraint)
	State       string // doc 04 §7.3 lifecycle states
	Fingerprint string
	Validation  map[string]any
	Risk        map[string]any
	EvidenceRef string
	Occurrence  int
	FirstSeen   time.Time
	LastSeen    time.Time
	TaskID      string
	Compliance  map[string]any
}

// UpsertFinding writes one fallback row (idempotent on (tenant, finding_id):
// redeliveries merge occurrences + last_seen).
func (s *Store) UpsertFinding(ctx context.Context, r FindingRow) error {
	val, err := json.Marshal(r.Validation)
	if err != nil {
		return err
	}
	risk, err := json.Marshal(r.Risk)
	if err != nil {
		return err
	}
	comp, err := json.Marshal(r.Compliance)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err = s.Pool.Exec(ctx, `
INSERT INTO detect.findings_fallback
  (tenant_id, finding_id, created_at, updated_at, module, check_id, title,
   severity, state, fingerprint, validation, risk, evidence_ref, occurrence,
   first_seen, last_seen, task_id, compliance)
VALUES ($1,$2,$3,$3,'detect',$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
ON CONFLICT (tenant_id, finding_id) DO UPDATE SET
  updated_at = EXCLUDED.updated_at,
  state      = EXCLUDED.state,
  validation = EXCLUDED.validation,
  risk       = EXCLUDED.risk,
  occurrence = detect.findings_fallback.occurrence + 1,
  last_seen  = EXCLUDED.last_seen`,
		r.TenantID, r.FindingID, now, r.CheckID, r.Title, r.Severity, r.State,
		r.Fingerprint, val, risk, nullStr(r.EvidenceRef), max1(r.Occurrence),
		r.FirstSeen, r.LastSeen, nullStr(r.TaskID), comp)
	if err != nil {
		return fmt.Errorf("store: upsert findings_fallback: %w", err)
	}
	return nil
}

// FindingByFingerprint loads one fallback row by fingerprint (revalidate
// path, doc 04 §4.1 detect.revalidate).
func (s *Store) FindingByFingerprint(ctx context.Context, tenantID, fingerprint string) (*FindingRow, error) {
	row := s.Pool.QueryRow(ctx, `
SELECT finding_id, check_id, title, severity, state, validation, risk,
       COALESCE(evidence_ref,''), occurrence, first_seen, last_seen, COALESCE(task_id,'')
FROM detect.findings_fallback
WHERE tenant_id = $1 AND fingerprint = $2
ORDER BY last_seen DESC LIMIT 1`, tenantID, fingerprint)
	var r FindingRow
	var val, risk []byte
	r.TenantID = tenantID
	r.Fingerprint = fingerprint
	if err := row.Scan(&r.FindingID, &r.CheckID, &r.Title, &r.Severity, &r.State,
		&val, &risk, &r.EvidenceRef, &r.Occurrence, &r.FirstSeen, &r.LastSeen, &r.TaskID); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(val, &r.Validation)
	_ = json.Unmarshal(risk, &r.Risk)
	return &r, nil
}

// ---------------------------------------------------------------------------
// Cross-run fingerprint cache (doc 04 §7.2) — implements normalize.KnownView
// ---------------------------------------------------------------------------

// Lookup implements normalize.KnownView.
func (s *Store) Lookup(fingerprint string) (string, uint64, bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var id string
	var occ int
	err := s.Pool.QueryRow(ctx,
		`SELECT finding_id::text, occurrences FROM detect.fingerprints WHERE fingerprint = $1`,
		fingerprint).Scan(&id, &occ)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", 0, false, nil
		}
		return "", 0, false, fmt.Errorf("store: fingerprint lookup: %w", err)
	}
	return id, uint64(occ), true, nil
}

// Record implements normalize.KnownView (tenant-scoped via Store.TenantID).
func (s *Store) Record(fingerprint, findingID string) error {
	return s.RecordForTenant(s.TenantID, fingerprint, findingID)
}

// RecordForTenant upserts one fingerprint sighting for a tenant.
func (s *Store) RecordForTenant(tenantID, fingerprint, findingID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.Pool.Exec(ctx, `
INSERT INTO detect.fingerprints (fingerprint, tenant_id, finding_id, first_seen, last_seen, occurrences)
VALUES ($1, $2, $3, now(), now(), 1)
ON CONFLICT (fingerprint) DO UPDATE SET last_seen = now(),
  occurrences = detect.fingerprints.occurrences + 1`,
		fingerprint, tenantID, findingID)
	if err != nil {
		return fmt.Errorf("store: fingerprint record: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Suppression list (doc 04 §7.3: false_positive signatures, monthly expiry)
// ---------------------------------------------------------------------------

// Suppressed reports whether a check signature is currently suppressed
// (expired entries do not suppress — suppressed checks get re-tried as
// validators improve).
func (s *Store) Suppressed(ctx context.Context, signatureHash string) (bool, error) {
	var one int
	err := s.Pool.QueryRow(ctx,
		`SELECT 1 FROM detect.suppressions WHERE signature_hash = $1 AND expires_at > now()`,
		signatureHash).Scan(&one)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("store: suppression lookup: %w", err)
	}
	return true, nil
}

// AddSuppression records a false-positive signature (default 30-day expiry,
// doc 04 §7.3).
func (s *Store) AddSuppression(ctx context.Context, signatureHash, tenantID, checkID, reason, createdBy string) error {
	_, err := s.Pool.Exec(ctx, `
INSERT INTO detect.suppressions (signature_hash, tenant_id, check_id, reason, created_by)
VALUES ($1,$2,$3,$4,$5)
ON CONFLICT (signature_hash) DO UPDATE SET
  reason = EXCLUDED.reason, created_at = now(),
  expires_at = now() + interval '30 days'`,
		signatureHash, tenantID, checkID, reason, createdBy)
	if err != nil {
		return fmt.Errorf("store: add suppression: %w", err)
	}
	return nil
}

// TransitionState applies a lifecycle state change to a fallback row
// (revalidate: remediation_claimed → verified_closed | reopened, doc 04 §7.3).
func (s *Store) TransitionState(ctx context.Context, tenantID, findingID, toState string) error {
	tag, err := s.Pool.Exec(ctx, `
UPDATE detect.findings_fallback SET state = $3, updated_at = now()
WHERE tenant_id = $1 AND finding_id = $2`, tenantID, findingID, toState)
	if err != nil {
		return fmt.Errorf("store: transition: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("store: finding %s not found for transition", findingID)
	}
	return nil
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func max1(v int) int {
	if v < 1 {
		return 1
	}
	return v
}
