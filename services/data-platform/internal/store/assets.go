package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// AssetUpsert is one asset write item (ingest or bus consumer).
type AssetUpsert struct {
	Type       string
	Value      string // already canonicalized by the caller
	Attributes map[string]any
	Confidence float64
	Status     string // empty → active
	RoeID      string
	FirstSeen  time.Time
	LastSeen   time.Time
	// Provenance, optional: one dp.finding_provenance row is written when
	// Source != "" (doc 02 §4.1 findings provenance).
	Source         string
	TaskID         string
	EvidenceURI    string
	ConfidenceHint *float64
}

// UpsertOutcome reports what an asset upsert did (drives dp.asset.* events).
type UpsertOutcome struct {
	AssetID      string
	Created      bool
	AttrsChanged bool
	Reactivated  bool // status was expired and became active again
}

// UpsertAssetTx upserts one asset within tx with deterministic temporal
// merge semantics (doc 09 §4.1: first_seen/last_seen; idempotent retries are
// no-ops, doc 09 §8). Attribute merge is additive (new keys win).
func UpsertAssetTx(ctx context.Context, tx pgx.Tx, tenantID string, a AssetUpsert) (*UpsertOutcome, error) {
	status := a.Status
	if status == "" {
		status = StatusActive
	}
	now := time.Now().UTC()
	fs, ls := a.FirstSeen, a.LastSeen
	if fs.IsZero() {
		fs = now
	}
	if ls.IsZero() {
		ls = now
	}
	attrs := a.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return nil, fmt.Errorf("asset attributes: %w", err)
	}

	var (
		id        string
		oldAttrs  []byte
		oldFirst  time.Time
		oldStatus string
		oldLast   time.Time
		existing  bool
	)
	err = tx.QueryRow(ctx, `
		SELECT asset_id::text, attributes, first_seen, status, last_seen
		FROM dp.assets
		WHERE tenant_id = $1 AND type = $2 AND value = $3
		FOR UPDATE`, tenantID, a.Type, a.Value).
		Scan(&id, &oldAttrs, &oldFirst, &oldStatus, &oldLast)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// insert path
	case err != nil:
		return nil, err
	default:
		existing = true
	}

	out := &UpsertOutcome{}
	if !existing {
		err = tx.QueryRow(ctx, `
			INSERT INTO dp.assets
			    (asset_id, tenant_id, type, value, attributes, confidence, status, first_seen, last_seen, roe_id)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING asset_id::text`,
			tenantID, a.Type, a.Value, attrsJSON, a.Confidence, status, fs, ls, a.RoeID).
			Scan(&id)
		if err != nil {
			return nil, fmt.Errorf("insert asset %s/%s: %w", a.Type, a.Value, err)
		}
		out.AssetID, out.Created, out.AttrsChanged = id, true, true
	} else {
		// Merge: new attributes overlay old; temporal extremes win; an
		// expired asset seen again is reactivated; explicit terminal
		// statuses (expired/quarantined) win over active/candidate.
		newStatus := oldStatus
		switch {
		case status == StatusExpired || status == StatusQuarantined:
			newStatus = status
		case oldStatus == StatusExpired && status == StatusActive:
			newStatus = StatusActive
			out.Reactivated = true
		case oldStatus == StatusQuarantined:
			newStatus = StatusQuarantined // quarantine is sticky
		case oldStatus == StatusCandidate && status == StatusActive:
			newStatus = StatusActive
		}
		merged := map[string]any{}
		_ = json.Unmarshal(oldAttrs, &merged)
		for k, v := range attrs {
			merged[k] = v
		}
		mergedJSON, _ := json.Marshal(merged)
		_, err = tx.Exec(ctx, `
			UPDATE dp.assets SET
			    attributes = $4,
			    confidence = GREATEST(confidence, $5),
			    status     = $6,
			    first_seen = LEAST(first_seen, $7),
			    last_seen  = GREATEST(last_seen, $8)
			WHERE tenant_id = $1 AND asset_id = $2::uuid AND type = $3`,
			tenantID, id, a.Type, mergedJSON, a.Confidence, newStatus, fs, ls)
		if err != nil {
			return nil, fmt.Errorf("update asset %s/%s: %w", a.Type, a.Value, err)
		}
		out.AssetID = id
		out.AttrsChanged = string(mergedJSON) != canonicalJSON(oldAttrs)
	}

	if a.Source != "" {
		if _, err := tx.Exec(ctx, `
			INSERT INTO dp.finding_provenance
			    (task_id, tenant_id, asset_id, source, observed_at, evidence_uri, confidence_hint)
			VALUES ($1, $2, $3::uuid, $4, $5, $6, $7)`,
			nilIfEmpty(a.TaskID), tenantID, out.AssetID, a.Source, ls,
			nilIfEmpty(a.EvidenceURI), a.ConfidenceHint); err != nil {
			return nil, fmt.Errorf("asset provenance: %w", err)
		}
	}
	return out, nil
}

// canonicalJSON re-marshals a jsonb document into the deterministic form
// Postgres returns (keys sorted — Go's encoding/json matches for maps).
func canonicalJSON(raw []byte) string {
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return string(raw)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return string(raw)
	}
	return string(out)
}

// EdgeUpsert is one edge write item. Src/Dst reference assets by asset_id or
// by (type, value) within the tenant (both already canonical).
type EdgeUpsert struct {
	SrcAssetID string
	SrcType    string
	SrcValue   string
	DstAssetID string
	DstType    string
	DstValue   string
	Rel        string
	Attributes map[string]any
	FirstSeen  time.Time
	LastSeen   time.Time
}

// UpsertEdgeTx upserts one edge within tx. Returns the edge id.
func UpsertEdgeTx(ctx context.Context, tx pgx.Tx, tenantID string, e EdgeUpsert) (string, error) {
	src, err := resolveAssetRefTx(ctx, tx, tenantID, e.SrcAssetID, e.SrcType, e.SrcValue)
	if err != nil {
		return "", fmt.Errorf("edge src: %w", err)
	}
	dst, err := resolveAssetRefTx(ctx, tx, tenantID, e.DstAssetID, e.DstType, e.DstValue)
	if err != nil {
		return "", fmt.Errorf("edge dst: %w", err)
	}
	now := time.Now().UTC()
	fs, ls := e.FirstSeen, e.LastSeen
	if fs.IsZero() {
		fs = now
	}
	if ls.IsZero() {
		ls = now
	}
	attrs := e.Attributes
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrsJSON, err := json.Marshal(attrs)
	if err != nil {
		return "", fmt.Errorf("edge attributes: %w", err)
	}
	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO dp.asset_edges
		    (tenant_id, src, dst, rel, attributes, first_seen, last_seen)
		VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7)
		ON CONFLICT (tenant_id, src, dst, rel) DO UPDATE SET
		    attributes = dp.asset_edges.attributes || EXCLUDED.attributes,
		    first_seen = LEAST(dp.asset_edges.first_seen, EXCLUDED.first_seen),
		    last_seen  = GREATEST(dp.asset_edges.last_seen, EXCLUDED.last_seen)
		RETURNING edge_id::text`,
		tenantID, src, dst, e.Rel, attrsJSON, fs, ls).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("upsert edge %s -[%s]-> %s: %w", src, e.Rel, dst, err)
	}
	return id, nil
}

// resolveAssetRefTx finds an asset id by asset_id or (type, value).
func resolveAssetRefTx(ctx context.Context, tx pgx.Tx, tenantID, assetID, typ, value string) (string, error) {
	if assetID != "" {
		var id string
		err := tx.QueryRow(ctx,
			`SELECT asset_id::text FROM dp.assets WHERE tenant_id = $1 AND asset_id = $2::uuid`,
			tenantID, assetID).Scan(&id)
		if err != nil {
			return "", fmt.Errorf("asset_id %s not found in tenant: %w", assetID, err)
		}
		return id, nil
	}
	var id string
	err := tx.QueryRow(ctx,
		`SELECT asset_id::text FROM dp.assets WHERE tenant_id = $1 AND type = $2 AND value = $3`,
		tenantID, typ, value).Scan(&id)
	if err != nil {
		return "", fmt.Errorf("asset %s/%s not found in tenant: %w", typ, value, err)
	}
	return id, nil
}

// GetAsset reads one tenant-scoped asset by uid (fail-closed: other tenants'
// assets are invisible, not merely filtered after the fact).
func (s *Store) GetAsset(ctx context.Context, tenantID, assetID string) (*Asset, error) {
	var a Asset
	var attrs []byte
	err := s.Pool.QueryRow(ctx, `
		SELECT asset_id::text, tenant_id::text, type, value, attributes, confidence,
		       status, first_seen, last_seen, roe_id
		FROM dp.assets WHERE tenant_id = $1::uuid AND asset_id = $2::uuid`,
		tenantID, assetID).
		Scan(&a.AssetID, &a.TenantID, &a.Type, &a.Value, &attrs, &a.Confidence,
			&a.Status, &a.FirstSeen, &a.LastSeen, &a.RoeID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	_ = json.Unmarshal(attrs, &a.Attributes)
	return &a, nil
}

// AssetFilter narrows asset list queries.
type AssetFilter struct {
	Types       []string
	Statuses    []string
	ValuePrefix string
	Since       *time.Time // last_seen >= since
}

// ListAssets returns one keyset page (ORDER BY value, asset_id) plus the
// tenant-scoped total. afterValue/afterID form the exclusive cursor.
func (s *Store) ListAssets(ctx context.Context, tenantID string, f AssetFilter, limit int, afterValue, afterID string) ([]*Asset, int, error) {
	where := "tenant_id = $1::uuid"
	args := []any{tenantID}
	n := 1
	if len(f.Types) > 0 {
		n++
		where += fmt.Sprintf(" AND type = ANY($%d)", n)
		args = append(args, f.Types)
	}
	if len(f.Statuses) > 0 {
		n++
		where += fmt.Sprintf(" AND status = ANY($%d)", n)
		args = append(args, f.Statuses)
	}
	if f.ValuePrefix != "" {
		n++
		where += fmt.Sprintf(" AND value LIKE $%d", n)
		args = append(args, f.ValuePrefix+"%")
	}
	if f.Since != nil {
		n++
		where += fmt.Sprintf(" AND last_seen >= $%d", n)
		args = append(args, *f.Since)
	}
	var total int
	if err := s.Pool.QueryRow(ctx,
		"SELECT count(*) FROM dp.assets WHERE "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	qwhere := where
	if afterValue != "" {
		n++
		qwhere += fmt.Sprintf(" AND (value, asset_id) > ($%d, $%d::uuid)", n, n+1)
		args = append(args, afterValue, afterID)
		n++
	}
	n++
	rows, err := s.Pool.Query(ctx, `
		SELECT asset_id::text, tenant_id::text, type, value, attributes, confidence,
		       status, first_seen, last_seen, roe_id
		FROM dp.assets WHERE `+qwhere+`
		ORDER BY value, asset_id LIMIT $`+fmt.Sprint(n), append(args, limit)...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*Asset
	for rows.Next() {
		var a Asset
		var attrs []byte
		if err := rows.Scan(&a.AssetID, &a.TenantID, &a.Type, &a.Value, &attrs,
			&a.Confidence, &a.Status, &a.FirstSeen, &a.LastSeen, &a.RoeID); err != nil {
			return nil, 0, err
		}
		_ = json.Unmarshal(attrs, &a.Attributes)
		out = append(out, &a)
	}
	return out, total, rows.Err()
}

// Neighborhood is the bounded adjacency walk for assetNeighborhood
// (doc 09 §5: recursive adjacency queries at MVP-A, depth ≤ 4).
type Neighborhood struct {
	Root   *Asset
	Assets []*Asset
	Edges  []*Edge
}

// Neighborhood walks the adjacency graph around root up to maxDepth hops,
// always inside tenantID (TPEL, doc 09 §7: partition key everywhere).
func (s *Store) Neighborhood(ctx context.Context, tenantID, rootID string, maxDepth int) (*Neighborhood, error) {
	root, err := s.GetAsset(ctx, tenantID, rootID)
	if err != nil || root == nil {
		return nil, err
	}
	rows, err := s.Pool.Query(ctx, `
		WITH RECURSIVE walk AS (
		    SELECT $2::uuid AS node, 0 AS depth
		    UNION
		    SELECT CASE WHEN e.src = w.node THEN e.dst ELSE e.src END, w.depth + 1
		    FROM walk w
		    JOIN dp.asset_edges e
		      ON e.tenant_id = $1::uuid AND (e.src = w.node OR e.dst = w.node)
		    WHERE w.depth < $3
		)
		SELECT DISTINCT a.asset_id::text, a.tenant_id::text, a.type, a.value, a.attributes,
		       a.confidence, a.status, a.first_seen, a.last_seen, a.roe_id
		FROM walk w JOIN dp.assets a ON a.tenant_id = $1::uuid AND a.asset_id = w.node`,
		tenantID, rootID, maxDepth)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	nb := &Neighborhood{Root: root}
	ids := make([]string, 0, 16)
	for rows.Next() {
		var a Asset
		var attrs []byte
		if err := rows.Scan(&a.AssetID, &a.TenantID, &a.Type, &a.Value, &attrs,
			&a.Confidence, &a.Status, &a.FirstSeen, &a.LastSeen, &a.RoeID); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(attrs, &a.Attributes)
		nb.Assets = append(nb.Assets, &a)
		ids = append(ids, a.AssetID)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nb, nil
	}
	erows, err := s.Pool.Query(ctx, `
		SELECT edge_id::text, tenant_id::text, src::text, dst::text, rel, attributes,
		       first_seen, last_seen
		FROM dp.asset_edges
		WHERE tenant_id = $1::uuid AND src = ANY($2::uuid[]) AND dst = ANY($2::uuid[])`,
		tenantID, ids)
	if err != nil {
		return nil, err
	}
	defer erows.Close()
	for erows.Next() {
		var e Edge
		var attrs []byte
		if err := erows.Scan(&e.EdgeID, &e.TenantID, &e.Src, &e.Dst, &e.Rel,
			&attrs, &e.FirstSeen, &e.LastSeen); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(attrs, &e.Attributes)
		nb.Edges = append(nb.Edges, &e)
	}
	return nb, erows.Err()
}

// VerifiedTarget reports whether a canonical target is present in the
// verified inventory — an active asset at or above the doc 02 §4.4 exposure
// threshold (confidence ≥ 0.5; below that assets are candidates). Used by
// gatekeeper's R2/R3 TARGET_SCOPE step (doc 11 §3.3 step 4). The check is
// platform-global by design: gatekeeper's caller passes targets, not tenants.
func (s *Store) VerifiedTarget(ctx context.Context, canonicalValue string) (bool, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM dp.assets
		WHERE status = 'active' AND confidence >= 0.5 AND value = $1`,
		canonicalValue).Scan(&n)
	return n > 0, err
}

// FindAssetByValue looks up one asset by canonical value across the asset
// types (bus-consumer tenant resolution: the inventory row identifies the
// owning tenant). Prefers active rows.
func (s *Store) FindAssetByValue(ctx context.Context, value string) (*Asset, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT asset_id::text, tenant_id::text, type, value, attributes, confidence,
		       status, first_seen, last_seen, roe_id
		FROM dp.assets WHERE value = $1
		ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'candidate' THEN 1 ELSE 2 END
		LIMIT 1`, value)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var a Asset
	var attrs []byte
	if err := rows.Scan(&a.AssetID, &a.TenantID, &a.Type, &a.Value, &attrs,
		&a.Confidence, &a.Status, &a.FirstSeen, &a.LastSeen, &a.RoeID); err != nil {
		return nil, err
	}
	_ = json.Unmarshal(attrs, &a.Attributes)
	return &a, nil
}

func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
