package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ---------------------------------------------------------------------------
// Ingest idempotency ledger (dp.ingest_batches, doc 09 §2.2/§3.1)
// ---------------------------------------------------------------------------

// BatchRecord is one dp.ingest_batches row.
type BatchRecord struct {
	IdempotencyKey string
	TenantID       string
	TaskID         string
	ScopeTokenJTI  string
	Status         string
	RejectReason   string
	Counts         map[string]int
	ReceivedAt     time.Time
}

// BeginBatchTx records an accepted batch within tx. Returns false when the
// idempotency key already exists (replay — the caller returns the recorded
// outcome without re-applying).
func BeginBatchTx(ctx context.Context, tx pgx.Tx, tenantID, key, taskID, jti string) (bool, error) {
	tag, err := tx.Exec(ctx, `
		INSERT INTO dp.ingest_batches (idempotency_key, tenant_id, task_id, scope_token_jti)
		VALUES ($1, $2::uuid, $3, $4)
		ON CONFLICT (idempotency_key) DO NOTHING`,
		key, tenantID, nilIfEmpty(taskID), nilIfEmpty(jti))
	if err != nil {
		return false, fmt.Errorf("begin batch: %w", err)
	}
	return tag.RowsAffected() == 1, nil
}

// FinishBatchTx records the outcome counts for an accepted batch.
func FinishBatchTx(ctx context.Context, tx pgx.Tx, key string, counts map[string]int) error {
	cj, err := json.Marshal(counts)
	if err != nil {
		return err
	}
	if cj == nil {
		cj = []byte("{}")
	}
	_, err = tx.Exec(ctx, `
		UPDATE dp.ingest_batches SET counts = $2 WHERE idempotency_key = $1`, key, cj)
	return err
}

// RejectBatch records a rejected batch (best-effort ledger; the rejection is
// also audit-logged). Idempotent: re-rejection of the same key is a no-op.
func (s *Store) RejectBatch(ctx context.Context, tenantID, key, taskID, reason string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO dp.ingest_batches (idempotency_key, tenant_id, task_id, status, reject_reason)
		VALUES ($1, $2::uuid, $3, 'rejected', $4)
		ON CONFLICT (idempotency_key) DO NOTHING`,
		key, tenantID, nilIfEmpty(taskID), reason)
	return err
}

// GetBatch loads a batch ledger row (nil when unknown).
func (s *Store) GetBatch(ctx context.Context, key string) (*BatchRecord, error) {
	var b BatchRecord
	var taskID, jti, reason *string
	var counts []byte
	err := s.Pool.QueryRow(ctx, `
		SELECT idempotency_key, tenant_id::text, task_id, scope_token_jti, status,
		       reject_reason, counts, received_at
		FROM dp.ingest_batches WHERE idempotency_key = $1`, key).
		Scan(&b.IdempotencyKey, &b.TenantID, &taskID, &jti, &b.Status, &reason,
			&counts, &b.ReceivedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if taskID != nil {
		b.TaskID = *taskID
	}
	if jti != nil {
		b.ScopeTokenJTI = *jti
	}
	if reason != nil {
		b.RejectReason = *reason
	}
	_ = json.Unmarshal(counts, &b.Counts)
	return &b, nil
}

// ---------------------------------------------------------------------------
// Data-access audit outbox (dp.audit_outbox, doc 09 §4.4)
// ---------------------------------------------------------------------------

// AuditRecord is one data-access audit event. Records cover dp domain
// actions ONLY — authorization decisions are gatekeeper's (Ruling B).
type AuditRecord struct {
	TenantID   string // may be empty for cross-tenant platform actions
	Actor      Actor
	Action     string // ingest.batch|ingest.rejected|query.metadata|query.evidence_access|retention.purge|admin.action
	ObjectRef  string
	ParamsHash string // sha256 hex of the canonical params
}

// AuditOutboxTx appends an audit record within tx (atomic with the action).
func AuditOutboxTx(ctx context.Context, tx pgx.Tx, r AuditRecord) error {
	actorJSON, err := json.Marshal(r.Actor)
	if err != nil {
		return err
	}
	var tenant *string
	if r.TenantID != "" {
		tenant = &r.TenantID
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO dp.audit_outbox (tenant_id, actor, action, object_ref, params_hash)
		VALUES ($1::uuid, $2, $3, $4, $5)`,
		tenant, actorJSON, r.Action, nilIfEmpty(r.ObjectRef), nilIfEmpty(r.ParamsHash))
	return err
}

// AuditOutbox appends an audit record outside any transaction.
func (s *Store) AuditOutbox(ctx context.Context, r AuditRecord) error {
	actorJSON, err := json.Marshal(r.Actor)
	if err != nil {
		return err
	}
	var tenant *string
	if r.TenantID != "" {
		tenant = &r.TenantID
	}
	_, err = s.Pool.Exec(ctx, `
		INSERT INTO dp.audit_outbox (tenant_id, actor, action, object_ref, params_hash)
		VALUES ($1::uuid, $2, $3, $4, $5)`,
		tenant, actorJSON, r.Action, nilIfEmpty(r.ObjectRef), nilIfEmpty(r.ParamsHash))
	return err
}

// PendingAudit is one outbox row awaiting forward to gatekeeper.
type PendingAudit struct {
	AuditID    string
	TS         time.Time
	TenantID   *string
	Actor      Actor
	Action     string
	ObjectRef  *string
	ParamsHash *string
}

// PendingAuditBatch fetches up to limit unforwarded rows.
func (s *Store) PendingAuditBatch(ctx context.Context, limit int) ([]*PendingAudit, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT audit_id::text, ts, tenant_id::text, actor, action, object_ref, params_hash
		FROM dp.audit_outbox
		WHERE forwarded_at IS NULL
		ORDER BY ts ASC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*PendingAudit
	for rows.Next() {
		var p PendingAudit
		var actor []byte
		if err := rows.Scan(&p.AuditID, &p.TS, &p.TenantID, &actor, &p.Action,
			&p.ObjectRef, &p.ParamsHash); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(actor, &p.Actor)
		out = append(out, &p)
	}
	return out, rows.Err()
}

// MarkAuditForwarded stamps forwarded_at on the given rows.
func (s *Store) MarkAuditForwarded(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := s.Pool.Exec(ctx, `
		UPDATE dp.audit_outbox SET forwarded_at = now()
		WHERE audit_id = ANY($1::uuid[])`, ids)
	return err
}

// ---------------------------------------------------------------------------
// Tenancy (tenancy.*, doc 09 §4.3)
// ---------------------------------------------------------------------------

// GrantsForPrincipal lists all dp grants held by a principal (TPEL tenant
// resolution: the credential determines the tenant, never the payload).
func (s *Store) GrantsForPrincipal(ctx context.Context, principal string) ([]*Grant, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT grant_id::text, tenant_id::text, principal, role
		FROM tenancy.grants WHERE principal = $1`, principal)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Grant
	for rows.Next() {
		var g Grant
		if err := rows.Scan(&g.GrantID, &g.TenantID, &g.Principal, &g.Role); err != nil {
			return nil, err
		}
		out = append(out, &g)
	}
	return out, rows.Err()
}

// TenantExists reports whether the tenant exists and is active.
func (s *Store) TenantExists(ctx context.Context, tenantID string) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM tenancy.tenants
		WHERE tenant_id = $1::uuid AND status = 'active'`, tenantID).Scan(&n)
	return n > 0, err
}

// CreateTenant inserts a tenant (UUIDv7 id) with the default retention profile.
func (s *Store) CreateTenant(ctx context.Context, name, tier, dataRegion string) (*Tenant, error) {
	if tier == "" {
		tier = "standard"
	}
	if dataRegion == "" {
		dataRegion = "local"
	}
	var t Tenant
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO tenancy.tenants (tenant_id, name, tier, data_region, retention_profile_id)
		VALUES ($1::uuid, $2, $3, $4,
		        (SELECT retention_profile_id FROM tenancy.retention_profiles WHERE name = 'default'))
		RETURNING tenant_id::text, name, tier, data_region, retention_profile_id::text, status`,
		newUUIDv7(), name, tier, dataRegion).
		Scan(&t.TenantID, &t.Name, &t.Tier, &t.DataRegion, &t.RetentionProfileID, &t.Status)
	if err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}
	return &t, nil
}

// ListTenants returns all tenants (admin API).
func (s *Store) ListTenants(ctx context.Context) ([]*Tenant, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT tenant_id::text, name, tier, data_region, retention_profile_id::text, status
		FROM tenancy.tenants ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.TenantID, &t.Name, &t.Tier, &t.DataRegion,
			&t.RetentionProfileID, &t.Status); err != nil {
			return nil, err
		}
		out = append(out, &t)
	}
	return out, rows.Err()
}

// CreateGrant inserts a dp data-access grant (doc 09 §4.3 — dp roles only;
// platform-wide RBAC is gatekeeper rbac-service).
func (s *Store) CreateGrant(ctx context.Context, tenantID, principal, role string) (*Grant, error) {
	var g Grant
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO tenancy.grants (tenant_id, principal, role)
		VALUES ($1::uuid, $2, $3)
		ON CONFLICT (tenant_id, principal, role) DO UPDATE SET granted_at = now()
		RETURNING grant_id::text, tenant_id::text, principal, role`,
		tenantID, principal, role).
		Scan(&g.GrantID, &g.TenantID, &g.Principal, &g.Role)
	if err != nil {
		return nil, fmt.Errorf("create grant: %w", err)
	}
	return &g, nil
}

// CreateWorkspace inserts a sub-tenant grouping row (doc 09 §4.3).
func (s *Store) CreateWorkspace(ctx context.Context, tenantID, name string) (string, error) {
	var id string
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO tenancy.workspaces (tenant_id, name)
		VALUES ($1::uuid, $2) RETURNING workspace_id::text`, tenantID, name).Scan(&id)
	return id, err
}

// SingleActiveTenant returns the only active tenant, or "" when zero or
// several exist (MVP-A one-tenant-cohort fallback for bus events that carry
// no tenant discriminator — fail-closed in multi-tenant deployments).
func (s *Store) SingleActiveTenant(ctx context.Context) (string, error) {
	var ids []string
	rows, err := s.Pool.Query(ctx, `
		SELECT tenant_id::text FROM tenancy.tenants WHERE status = 'active' LIMIT 2`)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", err
		}
		ids = append(ids, id)
	}
	if len(ids) != 1 {
		return "", nil
	}
	return ids[0], rows.Err()
}

// RetentionPolicy resolves the tenant's retention policy JSON (doc 09 §10),
// falling back to the 'default' profile.
func (s *Store) RetentionPolicy(ctx context.Context, tenantID string) (map[string]any, error) {
	var raw []byte
	err := s.Pool.QueryRow(ctx, `
		SELECT COALESCE(
		    (SELECT rp.policy FROM tenancy.tenants t
		     JOIN tenancy.retention_profiles rp USING (retention_profile_id)
		     WHERE t.tenant_id = $1::uuid),
		    (SELECT policy FROM tenancy.retention_profiles WHERE name = 'default'))`,
		tenantID).Scan(&raw)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("retention policy decode: %w", err)
	}
	return m, nil
}

// ActiveTenantIDs lists active tenants (retention sweep).
func (s *Store) ActiveTenantIDs(ctx context.Context) ([]string, error) {
	rows, err := s.Pool.Query(ctx,
		`SELECT tenant_id::text FROM tenancy.tenants WHERE status = 'active'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}
