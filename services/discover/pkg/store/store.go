// Package store is the discover.* working-store repository (doc 02 §4.1,
// migration 000004 — producer-side working store per Ruling C4; the data
// platform is the system of record). Postgres 16 via pgx; schema-per-context
// via DB_SEARCH_PATH=discover.
package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// ErrNotFound is returned by point lookups.
var ErrNotFound = errors.New("store: not found")

// Store wraps the pgx pool.
type Store struct {
	pool *pgxpool.Pool
}

// Connect opens the pool (DATABASE_URL) and pins the schema search path
// (DB_SEARCH_PATH=discover).
func Connect(ctx context.Context, databaseURL, searchPath string) (*Store, error) {
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
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// Ping implements the readiness check.
func (s *Store) Ping(ctx context.Context) error { return s.pool.Ping(ctx) }

// Tx runs fn in a transaction.
func (s *Store) Tx(ctx context.Context, fn func(tx pgx.Tx) error) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback(ctx)
		return err
	}
	return tx.Commit(ctx)
}

// Pool exposes the pool (schema bootstrap in tests).
func (s *Store) Pool() *pgxpool.Pool { return s.pool }

// confFromDB normalizes the `real` (float32) column's round-trip noise:
// Postgres stores confidence as float32, so 0.9 reads back as
// 0.8999999761581421. Confidence values are doc 02 §4.4 weights (0.6–1.0, one
// decimal) plus clamped corroboration sums, so 4-decimal rounding is exact
// for every producible value and keeps the reducer's merge comparisons
// stable (a re-delivered finding must not register a spurious confidence
// change — doc 02 §7.2 re-emission dedup).
func confFromDB(v float64) float64 { return math.Round(v*1e4) / 1e4 }

// --- orders -----------------------------------------------------------------

// OrderRow is one discovery_orders row.
type OrderRow struct {
	OrderID   string
	TenantID  string
	Request   json.RawMessage
	State     string
	Gate      json.RawMessage // model.Gate, nullable
	Progress  model.Progress
	CreatedAt time.Time
	UpdatedAt time.Time
}

// InsertOrder persists a new order (state PENDING or DENIED).
func (s *Store) InsertOrder(ctx context.Context, o *OrderRow) error {
	gate, err := json.Marshal(o.Gate)
	if err != nil {
		return err
	}
	if len(o.Gate) == 0 {
		gate = nil
	}
	progress, err := json.Marshal(o.Progress)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO discovery_orders (order_id, tenant_id, request, state, gate, progress, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6, now(), now())`,
		o.OrderID, o.TenantID, o.Request, o.State, gate, progress)
	return err
}

// SetOrderGate writes the gate decision record.
func (s *Store) SetOrderGate(ctx context.Context, orderID string, gate model.Gate) error {
	g, err := json.Marshal(gate)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`UPDATE discovery_orders SET gate=$2, updated_at=now() WHERE order_id=$1`, orderID, g)
	return err
}

// SetOrderState transitions the order state (error message optional).
func (s *Store) SetOrderState(ctx context.Context, orderID, state string, errMsg *string) error {
	// The schema has no error column; terminal errors ride in the request
	// audit + status events. updated_at marks the transition.
	_, err := s.pool.Exec(ctx,
		`UPDATE discovery_orders SET state=$2, updated_at=now() WHERE order_id=$1`, orderID, state)
	return err
}

// GetOrder fetches one order.
func (s *Store) GetOrder(ctx context.Context, orderID string) (*OrderRow, error) {
	var o OrderRow
	var gate []byte
	var progress []byte
	err := s.pool.QueryRow(ctx, `
		SELECT order_id, tenant_id, request, state, gate, progress, created_at, updated_at
		FROM discovery_orders WHERE order_id=$1`, orderID).
		Scan(&o.OrderID, &o.TenantID, &o.Request, &o.State, &gate, &progress, &o.CreatedAt, &o.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	o.Gate = gate
	if len(progress) > 0 {
		_ = json.Unmarshal(progress, &o.Progress)
	}
	return &o, nil
}

// ListOrdersByState returns orders in one state (janitor sweeps, revocation
// fan-out). tenantID empty = all tenants.
func (s *Store) ListOrdersByState(ctx context.Context, state, tenantID string) ([]OrderRow, error) {
	q := `SELECT order_id, tenant_id, request, state, gate, progress, created_at, updated_at
		FROM discovery_orders WHERE state=$1`
	args := []any{state}
	if tenantID != "" {
		q += ` AND tenant_id=$2`
		args = append(args, tenantID)
	}
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OrderRow
	for rows.Next() {
		var o OrderRow
		var gate, progress []byte
		if err := rows.Scan(&o.OrderID, &o.TenantID, &o.Request, &o.State, &gate, &progress, &o.CreatedAt, &o.UpdatedAt); err != nil {
			return nil, err
		}
		o.Gate = gate
		if len(progress) > 0 {
			_ = json.Unmarshal(progress, &o.Progress)
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// IncrementProgress atomically adds deltas to progress counters (single SQL
// statement per field set — safe for concurrent reducer updates).
func (s *Store) IncrementProgress(ctx context.Context, orderID string, deltas map[string]int) error {
	for field, d := range deltas {
		if d == 0 {
			continue
		}
		if _, err := s.pool.Exec(ctx, `
			UPDATE discovery_orders
			SET progress = jsonb_set(progress, $2,
				to_jsonb(COALESCE((progress->>$3)::int, 0) + $4), false),
			    updated_at = now()
			WHERE order_id = $1`, orderID, "{"+field+"}", field, d); err != nil {
			return fmt.Errorf("increment %s: %w", field, err)
		}
	}
	return nil
}

// SetProgressTotal records the planned task count.
func (s *Store) SetProgressTotal(ctx context.Context, orderID string, total int) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE discovery_orders
		SET progress = jsonb_set(progress, '{tasks_total}', to_jsonb($2::int), false), updated_at=now()
		WHERE order_id=$1`, orderID, total)
	return err
}

// --- assets -----------------------------------------------------------------

// GetAsset fetches by the dedup canonical key (tenant,type,value).
func (s *Store) GetAsset(ctx context.Context, tenantID string, typ model.AssetType, value string) (*model.AssetRecord, error) {
	var r model.AssetRecord
	var attrs []byte
	err := s.pool.QueryRow(ctx, `
		SELECT asset_id, tenant_id, type, value, attributes, confidence, status, first_seen, last_seen, roe_id
		FROM assets WHERE tenant_id=$1 AND type=$2 AND value=$3`, tenantID, string(typ), value).
		Scan(&r.AssetID, &r.TenantID, &r.Type, &r.Value, &attrs, &r.Confidence, &r.Status, &r.FirstSeen, &r.LastSeen, &r.ROEID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Confidence = confFromDB(r.Confidence)
	r.Attributes = map[string]any{}
	if len(attrs) > 0 {
		_ = json.Unmarshal(attrs, &r.Attributes)
	}
	return &r, nil
}

// GetAssetByID fetches by primary key.
func (s *Store) GetAssetByID(ctx context.Context, assetID string) (*model.AssetRecord, error) {
	var r model.AssetRecord
	var attrs []byte
	err := s.pool.QueryRow(ctx, `
		SELECT asset_id, tenant_id, type, value, attributes, confidence, status, first_seen, last_seen, roe_id
		FROM assets WHERE asset_id=$1`, assetID).
		Scan(&r.AssetID, &r.TenantID, &r.Type, &r.Value, &attrs, &r.Confidence, &r.Status, &r.FirstSeen, &r.LastSeen, &r.ROEID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.Confidence = confFromDB(r.Confidence)
	r.Attributes = map[string]any{}
	if len(attrs) > 0 {
		_ = json.Unmarshal(attrs, &r.Attributes)
	}
	return &r, nil
}

// InsertAsset inserts a new asset row.
func (s *Store) InsertAsset(ctx context.Context, r *model.AssetRecord) error {
	if r.AssetID == "" {
		r.AssetID = uuid.NewString()
	}
	attrs, err := json.Marshal(r.Attributes)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO assets (asset_id, tenant_id, type, value, attributes, confidence, status, first_seen, last_seen, roe_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		r.AssetID, r.TenantID, string(r.Type), r.Value, attrs, r.Confidence, r.Status,
		r.FirstSeen, r.LastSeen, r.ROEID)
	return err
}

// UpdateAsset updates mutable fields (idempotent merge target).
func (s *Store) UpdateAsset(ctx context.Context, r *model.AssetRecord) error {
	attrs, err := json.Marshal(r.Attributes)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx, `
		UPDATE assets SET attributes=$2, confidence=$3, status=$4, last_seen=$5, roe_id=$6
		WHERE asset_id=$1`, r.AssetID, attrs, r.Confidence, r.Status, r.LastSeen, r.ROEID)
	return err
}

// AssetQuery filters the tenant-scoped read API (GET /v1/assets).
type AssetQuery struct {
	TenantID string
	Domain   string
	Type     string
	Since    *time.Time
	Cursor   string // last_seen,asset_id of the previous page (opaque)
	Limit    int
}

// ListAssets pages the working store (fresh path for Monitor, doc 02 §3.1).
func (s *Store) ListAssets(ctx context.Context, q AssetQuery) ([]model.AssetRecord, string, error) {
	if q.Limit <= 0 || q.Limit > 500 {
		q.Limit = 100
	}
	where := `tenant_id=$1`
	args := []any{q.TenantID}
	n := 2
	if q.Domain != "" {
		where += fmt.Sprintf(` AND value=$%d`, n)
		args = append(args, q.Domain)
		n++
	}
	if q.Type != "" {
		where += fmt.Sprintf(` AND type=$%d`, n)
		args = append(args, q.Type)
		n++
	}
	if q.Since != nil {
		where += fmt.Sprintf(` AND last_seen >= $%d`, n)
		args = append(args, *q.Since)
		n++
	}
	if q.Cursor != "" {
		var ts time.Time
		var id string
		if _, err := fmt.Sscanf(q.Cursor, "%d,%s", new(int64), &id); err == nil {
			// opaque cursor: "<unixnano>,<asset_id>"
			ts = time.Unix(0, mustParseInt64(q.Cursor))
			_ = ts
		}
		if t, cid, ok := decodeCursor(q.Cursor); ok {
			where += fmt.Sprintf(` AND (last_seen, asset_id) > ($%d, $%d)`, n, n+1)
			args = append(args, t, cid)
			n += 2
		}
	}
	rows, err := s.pool.Query(ctx, `
		SELECT asset_id, tenant_id, type, value, attributes, confidence, status, first_seen, last_seen, roe_id
		FROM assets WHERE `+where+`
		ORDER BY last_seen, asset_id LIMIT `+fmt.Sprint(q.Limit+1), args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out, next, err := scanAssetPage(rows, q.Limit)
	return out, next, err
}

// ListOrderAssets pages assets attributed to an order (via findings).
func (s *Store) ListOrderAssets(ctx context.Context, orderID, cursor string, limit int) ([]model.AssetRecord, string, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	args := []any{orderID}
	cursorClause := ""
	if t, cid, ok := decodeCursor(cursor); ok {
		cursorClause = ` AND (a.last_seen, a.asset_id) > ($2, $3)`
		args = append(args, t, cid)
	}
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT a.asset_id, a.tenant_id, a.type, a.value, a.attributes, a.confidence, a.status,
		       a.first_seen, a.last_seen, a.roe_id
		FROM assets a JOIN findings f ON f.asset_id = a.asset_id
		WHERE f.order_id = $1`+cursorClause+`
		ORDER BY a.last_seen, a.asset_id LIMIT `+fmt.Sprint(limit+1), args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	return scanAssetPage(rows, limit)
}

func scanAssetPage(rows pgx.Rows, limit int) ([]model.AssetRecord, string, error) {
	var out []model.AssetRecord
	for rows.Next() {
		var r model.AssetRecord
		var attrs []byte
		if err := rows.Scan(&r.AssetID, &r.TenantID, &r.Type, &r.Value, &attrs, &r.Confidence, &r.Status, &r.FirstSeen, &r.LastSeen, &r.ROEID); err != nil {
			return nil, "", err
		}
		r.Confidence = confFromDB(r.Confidence)
		r.Attributes = map[string]any{}
		if len(attrs) > 0 {
			_ = json.Unmarshal(attrs, &r.Attributes)
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	next := ""
	if len(out) > limit {
		last := out[limit-1]
		next = encodeCursor(last.LastSeen, last.AssetID)
		out = out[:limit]
	}
	return out, next, nil
}

func encodeCursor(t time.Time, id string) string {
	return fmt.Sprintf("%d,%s", t.UTC().UnixNano(), id)
}

func decodeCursor(c string) (time.Time, string, bool) {
	var nanos int64
	var id string
	if _, err := fmt.Sscanf(c, "%d,%36s", &nanos, &id); err != nil || nanos == 0 {
		return time.Time{}, "", false
	}
	return time.Unix(0, nanos).UTC(), id, true
}

func mustParseInt64(s string) int64 {
	var v int64
	_, _ = fmt.Sscanf(s, "%d", &v)
	return v
}

// ExpireStaleAssets flips active/candidate assets not seen since the cutoff
// to expired (the AssetChange "expired" sweeper, doc 02 §2.2).
func (s *Store) ExpireStaleAssets(ctx context.Context, cutoff time.Time) ([]model.AssetRecord, error) {
	rows, err := s.pool.Query(ctx, `
		UPDATE assets SET status='expired'
		WHERE status IN ('active','candidate') AND last_seen < $1
		RETURNING asset_id, tenant_id, type, value, attributes, confidence, status, first_seen, last_seen, roe_id`,
		cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AssetRecord
	for rows.Next() {
		var r model.AssetRecord
		var attrs []byte
		if err := rows.Scan(&r.AssetID, &r.TenantID, &r.Type, &r.Value, &attrs, &r.Confidence, &r.Status, &r.FirstSeen, &r.LastSeen, &r.ROEID); err != nil {
			return nil, err
		}
		r.Confidence = confFromDB(r.Confidence)
		r.Attributes = map[string]any{}
		if len(attrs) > 0 {
			_ = json.Unmarshal(attrs, &r.Attributes)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// --- edges ------------------------------------------------------------------

// UpsertEdge inserts/refreshes one asset_edges row.
func (s *Store) UpsertEdge(ctx context.Context, tenantID, srcID, dstID, rel string, now time.Time) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO asset_edges (tenant_id, src, dst, rel, attributes, first_seen, last_seen)
		VALUES ($1,$2,$3,$4,'{}',$5,$5)
		ON CONFLICT (tenant_id, src, dst, rel) DO UPDATE SET last_seen=EXCLUDED.last_seen`,
		tenantID, srcID, dstID, rel, now)
	return err
}

// --- findings ---------------------------------------------------------------

// FindingRow is one findings row (provenance, doc 02 §4.1).
type FindingRow struct {
	FindingID      string
	TaskID         string
	OrderID        string
	TenantID       string
	AssetID        string
	Source         string
	ObservedAt     time.Time
	EvidenceURI    string
	ConfidenceHint float64
}

// InsertFinding appends provenance (insert-only).
func (s *Store) InsertFinding(ctx context.Context, f *FindingRow) error {
	if f.FindingID == "" {
		f.FindingID = uuid.NewString()
	}
	var orderID *string
	if f.OrderID != "" {
		orderID = &f.OrderID
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO findings (finding_id, task_id, order_id, tenant_id, asset_id, source, observed_at, evidence_uri, confidence_hint)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		f.FindingID, f.TaskID, orderID, f.TenantID, f.AssetID, f.Source, f.ObservedAt, f.EvidenceURI, f.ConfidenceHint)
	return err
}

// FindingExists is the reducer's re-emission dedup check (doc 02 §7.2):
// dedup on (task, source, asset, observed_at bucket) so worker re-delivery is
// a no-op. The bucket is minute-granular (observed_at truncated to the
// minute).
func (s *Store) FindingExists(ctx context.Context, taskID, source, assetID string, observedBucket time.Time) (bool, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM findings
		WHERE task_id=$1 AND source=$2 AND asset_id=$3
		  AND observed_at >= $4 AND observed_at < $4 + interval '1 minute'`,
		taskID, source, assetID, observedBucket.Truncate(time.Minute)).Scan(&n)
	return n > 0, err
}

// --- quarantine -------------------------------------------------------------

// QuarantineRow is one quarantined_findings row (doc 02 §4.2: out-of-scope
// findings land here with a reason code, never in assets).
type QuarantineRow struct {
	FindingID  string
	TenantID   string
	OrderID    string
	Asset      model.Asset
	Source     string
	ReasonCode string // OUT_OF_SCOPE|EXCLUDED|UNVALIDATED_GUESS|…
	ObservedAt time.Time
}

// Quarantine reason codes.
const (
	ReasonOutOfScope       = "OUT_OF_SCOPE"
	ReasonExcluded         = "EXCLUDED"
	ReasonUnvalidatedGuess = "UNVALIDATED_GUESS"
)

// InsertQuarantine appends one quarantined finding.
func (s *Store) InsertQuarantine(ctx context.Context, q *QuarantineRow) error {
	if q.FindingID == "" {
		q.FindingID = uuid.NewString()
	}
	asset, err := json.Marshal(q.Asset)
	if err != nil {
		return err
	}
	var orderID *string
	if q.OrderID != "" {
		orderID = &q.OrderID
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO quarantined_findings (finding_id, tenant_id, order_id, asset, source, reason_code, observed_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		q.FindingID, q.TenantID, orderID, asset, q.Source, q.ReasonCode, q.ObservedAt)
	return err
}

// --- audit spool (doc 02 §4.1/§6.4) -----------------------------------------

// SpoolRow is one audit_spool row.
type SpoolRow struct {
	Seq         int64
	TenantID    string
	Actor       json.RawMessage
	Action      string
	Target      string
	Payload     json.RawMessage
	TS          time.Time
	ForwardedAt *time.Time
}

// AppendSpool appends one audit event to the local spool.
func (s *Store) AppendSpool(ctx context.Context, r *SpoolRow) (int64, error) {
	var seq int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO audit_spool (tenant_id, actor, action, target, payload)
		VALUES ($1,$2,$3,$4,$5) RETURNING seq`,
		r.TenantID, r.Actor, r.Action, r.Target, r.Payload).Scan(&seq)
	return seq, err
}

// UnforwardedSpool pages unforwarded rows in order.
func (s *Store) UnforwardedSpool(ctx context.Context, limit int) ([]SpoolRow, error) {
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.pool.Query(ctx, `
		SELECT seq, tenant_id, actor, action, target, payload, ts
		FROM audit_spool WHERE forwarded_at IS NULL ORDER BY seq LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SpoolRow
	for rows.Next() {
		var r SpoolRow
		if err := rows.Scan(&r.Seq, &r.TenantID, &r.Actor, &r.Action, &r.Target, &r.Payload, &r.TS); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkSpoolForwarded marks one row forwarded.
func (s *Store) MarkSpoolForwarded(ctx context.Context, seq int64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE audit_spool SET forwarded_at=now() WHERE seq=$1 AND forwarded_at IS NULL`, seq)
	return err
}

// UnforwardedSpoolCount backs the fail-closed intake pause (doc 02 §6.4:
// spool full ⇒ intake pauses).
func (s *Store) UnforwardedSpoolCount(ctx context.Context) (int64, error) {
	var n int64
	err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_spool WHERE forwarded_at IS NULL`).Scan(&n)
	return n, err
}
