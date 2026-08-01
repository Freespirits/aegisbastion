// Package store is the monitor module's PostgreSQL access layer (doc 03 §8,
// schema `monitor` — tables migrated in db/migrations/000004). pgx pool with
// the schema pinned per connection; every write that pairs a change_events
// row with its event_outbox rows runs in ONE transaction (doc 03 §8: the
// outbox is transactional with the change insert).
package store

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps the pgx pool. All queries schema-qualify explicitly.
type Store struct {
	Pool *pgxpool.Pool
}

// New connects and pins the search_path per connection (mirrors
// services/platform-core/internal/store).
func New(ctx context.Context, databaseURL, searchPath string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: parse DATABASE_URL: %w", err)
	}
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET search_path TO "+pgx.Identifier{searchPath}.Sanitize()+", public")
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{Pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.Pool.Close() }

// Ping is the readiness probe.
func (s *Store) Ping(ctx context.Context) error { return s.Pool.Ping(ctx) }

// Bootstrap applies idempotent service-local DDL (mirrors platform-core's
// bootstrap.Ensure pattern — deliberately separate from golang-migrate
// versioning): the additive watch_assets.failing_since column (§12 asset
// churn persistence window), the two-consecutive-probe confirmation table
// (§7.1), the passive-candidate metadata table (§9.4), and this/next month's
// partitions for the partitioned tables (the migration ships only the
// DEFAULT partitions).
func (s *Store) Bootstrap(ctx context.Context) error {
	stmts := []string{
		`ALTER TABLE monitor.watch_assets ADD COLUMN IF NOT EXISTS failing_since timestamptz`,
		// State-transition changes (http.status_changed, port.*, …) emit only
		// after 2 consecutive agreeing probes (doc 03 §7.1); the first
		// observation parks here until the next probe confirms or voids it.
		`CREATE TABLE IF NOT EXISTS monitor.pending_changes (
		    asset_id     uuid        NOT NULL,
		    probe_type   text        NOT NULL,
		    diff_key     text        NOT NULL,
		    fingerprint  text        NOT NULL,
		    after_hash   text        NOT NULL,
		    payload      jsonb       NOT NULL,
		    first_seen_at timestamptz NOT NULL DEFAULT now(),
		    PRIMARY KEY (asset_id, probe_type, diff_key)
		)`,
		// Passive candidates (doc 03 §9.4): out-of-scope discoveries are
		// metadata-only (identifier + source + first_seen; never probed).
		`CREATE TABLE IF NOT EXISTS monitor.asset_candidates (
		    mission_id  text        NOT NULL,
		    identifier  text        NOT NULL,
		    kind        text        NOT NULL,
		    scope_match text        NOT NULL,
		    source      jsonb       NOT NULL DEFAULT '{}',
		    first_seen  timestamptz NOT NULL DEFAULT now(),
		    PRIMARY KEY (mission_id, identifier)
		)`,
	}
	now := time.Now().UTC()
	for _, t := range []time.Time{now, now.AddDate(0, 1, 0)} {
		y, m := t.Year(), int(t.Month())
		start := time.Date(y, time.Month(m), 1, 0, 0, 0, 0, time.UTC)
		end := start.AddDate(0, 1, 0)
		stmts = append(stmts,
			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS monitor.snapshots_history_%d_%02d PARTITION OF monitor.snapshots_history FOR VALUES FROM ('%s') TO ('%s')`,
				y, m, start.Format("2006-01-02"), end.Format("2006-01-02")),
			fmt.Sprintf(`CREATE TABLE IF NOT EXISTS monitor.change_events_%d_%02d PARTITION OF monitor.change_events FOR VALUES FROM ('%s') TO ('%s')`,
				y, m, start.Format("2006-01-02"), end.Format("2006-01-02")),
		)
	}
	for _, q := range stmts {
		if _, err := s.Pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("store: bootstrap %q: %w", q[:min(60, len(q))], err)
		}
	}
	return nil
}

// TryAdvisoryLock attempts the module's leader lock (doc 03 §11: single M1
// scheduler / M7 poller at MVP, leader-elected via PG advisory lock).
func (s *Store) TryAdvisoryLock(ctx context.Context, key int64) (pgx.Tx, bool, error) {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return nil, false, err
	}
	var ok bool
	if err := tx.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&ok); err != nil {
		_ = tx.Rollback(ctx)
		return nil, false, err
	}
	if !ok {
		_ = tx.Rollback(ctx)
		return nil, false, nil
	}
	return tx, true, nil // hold the tx (session) for the lock's lifetime
}

// ---------------------------------------------------------------------------
// watch_assets (persisted scheduler heap, doc 03 §8)
// ---------------------------------------------------------------------------

// WatchAsset is one row of monitor.watch_assets.
type WatchAsset struct {
	RowUUID        string
	AssetID        string
	MissionID      string
	Identifier     string
	CadenceProfile string
	NextDueAt      time.Time
	FastUntil      *time.Time
	LastProbeAt    *time.Time
	State          string
	FailingSince   *time.Time
}

// UpsertWatchAsset inserts or refreshes a watch-set member (watch-set
// convergence, doc 03 §4.2). New rows schedule immediately (next_due now).
func (s *Store) UpsertWatchAsset(ctx context.Context, assetID, missionID, identifier, cadence string, due time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO monitor.watch_assets (asset_id, mission_id, identifier, cadence_profile, next_due_at, state)
		VALUES ($1, $2, $3, $4, $5, 'active')
		ON CONFLICT (mission_id, identifier) DO UPDATE
		SET asset_id = EXCLUDED.asset_id,
		    cadence_profile = EXCLUDED.cadence_profile,
		    state = CASE WHEN monitor.watch_assets.state = 'removed' THEN 'removed' ELSE 'active' END`,
		assetID, missionID, identifier, cadence, due)
	return err
}

// ListWatchAssets returns the watch set for a mission in a given state
// (empty state = all).
func (s *Store) ListWatchAssets(ctx context.Context, missionID, state string) ([]WatchAsset, error) {
	q := `SELECT watch_id::text, asset_id::text, mission_id, identifier, cadence_profile,
	             next_due_at, fast_until, last_probe_at, state, failing_since
	      FROM monitor.watch_assets WHERE mission_id = $1`
	args := []any{missionID}
	if state != "" {
		q += ` AND state = $2`
		args = append(args, state)
	}
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WatchAsset
	for rows.Next() {
		var w WatchAsset
		if err := rows.Scan(&w.RowUUID, &w.AssetID, &w.MissionID, &w.Identifier,
			&w.CadenceProfile, &w.NextDueAt, &w.FastUntil, &w.LastProbeAt, &w.State, &w.FailingSince); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ListDueAssets claims the due scan batch (doc 03 §11: M2 batches due
// assets). SKIP LOCKED keeps standby coordinators safe.
func (s *Store) ListDueAssets(ctx context.Context, missionID string, now time.Time, limit int) ([]WatchAsset, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT watch_id::text, asset_id::text, mission_id, identifier, cadence_profile,
		       next_due_at, fast_until, last_probe_at, state, failing_since
		FROM monitor.watch_assets
		WHERE mission_id = $1 AND state = 'active' AND next_due_at <= $2
		ORDER BY next_due_at ASC
		LIMIT $3
		FOR UPDATE SKIP LOCKED`, missionID, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WatchAsset
	for rows.Next() {
		var w WatchAsset
		if err := rows.Scan(&w.RowUUID, &w.AssetID, &w.MissionID, &w.Identifier,
			&w.CadenceProfile, &w.NextDueAt, &w.FastUntil, &w.LastProbeAt, &w.State, &w.FailingSince); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// ListDueAssetsState claims due assets in a specific state (reactivation
// sweep over parked assets, doc 03 §12).
func (s *Store) ListDueAssetsState(ctx context.Context, missionID, state string, now time.Time, limit int) ([]WatchAsset, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT watch_id::text, asset_id::text, mission_id, identifier, cadence_profile,
		       next_due_at, fast_until, last_probe_at, state, failing_since
		FROM monitor.watch_assets
		WHERE mission_id = $1 AND state = $2 AND next_due_at <= $3
		ORDER BY next_due_at ASC
		LIMIT $4
		FOR UPDATE SKIP LOCKED`, missionID, state, now, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []WatchAsset
	for rows.Next() {
		var w WatchAsset
		if err := rows.Scan(&w.RowUUID, &w.AssetID, &w.MissionID, &w.Identifier,
			&w.CadenceProfile, &w.NextDueAt, &w.FastUntil, &w.LastProbeAt, &w.State, &w.FailingSince); err != nil {
			return nil, err
		}
		out = append(out, w)
	}
	return out, rows.Err()
}

// CountDueAssets reports the current queue depth (progress/metrics).
func (s *Store) CountDueAssets(ctx context.Context, missionID string, now time.Time) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM monitor.watch_assets
		WHERE mission_id = $1 AND state = 'active' AND next_due_at <= $2`,
		missionID, now).Scan(&n)
	return n, err
}

// Reschedule sets an asset's next due time (jitter applied by the caller,
// doc 03 §6.4) and records the probe time.
func (s *Store) Reschedule(ctx context.Context, rowUUID string, nextDue, probedAt time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE monitor.watch_assets SET next_due_at = $2, last_probe_at = $3 WHERE watch_id = $1`,
		rowUUID, nextDue, probedAt)
	return err
}

// SetWatchState transitions an asset's watch state (active|paused|removed;
// §4.4 purge and §12 parking).
func (s *Store) SetWatchState(ctx context.Context, rowUUID, state string) error {
	_, err := s.Pool.Exec(ctx, `UPDATE monitor.watch_assets SET state = $2 WHERE watch_id = $1`, rowUUID, state)
	return err
}

// SetFailing records/clears the probe-failure persistence window (§12:
// consecutive failures > 24 h → asset.removed; success clears).
func (s *Store) SetFailing(ctx context.Context, rowUUID string, since *time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE monitor.watch_assets SET failing_since = $2 WHERE watch_id = $1`, rowUUID, since)
	return err
}

// SetFastUntil moves an asset onto the fast cadence after a confirmed change
// (doc 03 §6.4 post-change 48 h escalation).
func (s *Store) SetFastUntil(ctx context.Context, rowUUID string, until time.Time) error {
	_, err := s.Pool.Exec(ctx, `UPDATE monitor.watch_assets SET fast_until = $2 WHERE watch_id = $1`, rowUUID, until)
	return err
}

// PurgeNotIn purges (state='removed') every watch asset of missionID whose
// identifier is not in keep — the §4.4 RoE-narrowed purge.
func (s *Store) PurgeNotIn(ctx context.Context, missionID string, keep []string) (int64, error) {
	tag, err := s.Pool.Exec(ctx, `
		UPDATE monitor.watch_assets SET state = 'removed'
		WHERE mission_id = $1 AND state <> 'removed' AND identifier <> ALL ($2)`,
		missionID, keep)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

// ---------------------------------------------------------------------------
// snapshots (doc 03 §8: latest hot row + partitioned insert-on-change history)
// ---------------------------------------------------------------------------

// LatestSnapshot is the snapshots_latest row joined to nothing — the stored
// ids/hashes the executor diffs against.
type LatestSnapshot struct {
	SnapshotID  string
	ContentHash string
	ProbeTS     time.Time
	Status      string
}

// GetLatest returns the hot row for (asset, probe_type).
func (s *Store) GetLatest(ctx context.Context, assetID, probeType string) (*LatestSnapshot, error) {
	var ls LatestSnapshot
	err := s.Pool.QueryRow(ctx, `
		SELECT snapshot_id::text, content_hash, probe_ts, status
		FROM monitor.snapshots_latest WHERE asset_id = $1 AND probe_type = $2`,
		assetID, probeType).Scan(&ls.SnapshotID, &ls.ContentHash, &ls.ProbeTS, &ls.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &ls, err
}

// TouchLatest updates last_seen on an unchanged observation (doc 03 §7.1:
// "equal → update last_seen, done — no history row churn").
func (s *Store) TouchLatest(ctx context.Context, assetID, probeType string, probeTS time.Time, status string) error {
	_, err := s.Pool.Exec(ctx, `
		UPDATE monitor.snapshots_latest SET probe_ts = $3, status = $4
		WHERE asset_id = $1 AND probe_type = $2`, assetID, probeType, probeTS, status)
	return err
}

// WriteSnapshot persists a changed observation: latest upsert + history
// insert (doc 03 §7.1). Runs in the caller's tx when non-nil.
func (s *Store) WriteSnapshot(ctx context.Context, tx pgx.Tx, assetID, probeType, snapshotID, contentHash string,
	probeTS time.Time, status string, data []byte, rawRef *string) error {
	exec := func(q string, args ...any) (pgconn.CommandTag, error) {
		if tx != nil {
			return tx.Exec(ctx, q, args...)
		}
		return s.Pool.Exec(ctx, q, args...)
	}
	if _, err := exec(`
		INSERT INTO monitor.snapshots_latest (asset_id, probe_type, snapshot_id, content_hash, probe_ts, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (asset_id, probe_type) DO UPDATE
		SET snapshot_id = EXCLUDED.snapshot_id, content_hash = EXCLUDED.content_hash,
		    probe_ts = EXCLUDED.probe_ts, status = EXCLUDED.status`,
		assetID, probeType, snapshotID, contentHash, probeTS, status); err != nil {
		return err
	}
	_, err := exec(`
		INSERT INTO monitor.snapshots_history (snapshot_id, asset_id, probe_type, probe_ts, content_hash, data, raw_ref)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (snapshot_id, probe_ts) DO NOTHING`,
		snapshotID, assetID, probeType, probeTS, contentHash, data, rawRef)
	return err
}

// SnapshotData loads the full SnapshotDocument JSON for a history row.
func (s *Store) SnapshotData(ctx context.Context, snapshotID string) ([]byte, error) {
	var data []byte
	err := s.Pool.QueryRow(ctx, `
		SELECT data FROM monitor.snapshots_history WHERE snapshot_id = $1
		ORDER BY probe_ts DESC LIMIT 1`, snapshotID).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return data, err
}

// SnapshotHistory lists recent history rows for the management API
// (doc 03 §13 GET /v1/assets/{id}/snapshots).
func (s *Store) SnapshotHistory(ctx context.Context, assetID, probeType string, limit int) ([]LatestSnapshot, error) {
	q := `SELECT snapshot_id::text, content_hash, probe_ts, 'ok' FROM monitor.snapshots_history
	      WHERE asset_id = $1`
	args := []any{assetID}
	if probeType != "" {
		q += ` AND probe_type = $2`
		args = append(args, probeType)
	}
	q += ` ORDER BY probe_ts DESC LIMIT ` + fmt.Sprint(limit)
	rows, err := s.Pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LatestSnapshot
	for rows.Next() {
		var ls LatestSnapshot
		if err := rows.Scan(&ls.SnapshotID, &ls.ContentHash, &ls.ProbeTS, &ls.Status); err != nil {
			return nil, err
		}
		out = append(out, ls)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// change_events + event_outbox (transactional pair, doc 03 §8)
// ---------------------------------------------------------------------------

// OutboxRow is one event_outbox entry.
type OutboxRow struct {
	EventID   string
	Subject   string
	MissionID string
	Data      []byte // exact bus payload bytes
	CreatedAt time.Time
}

// InsertEventWithOutbox persists a change_events row and its outbox rows in
// one transaction (doc 03 §8/M6). payload is the MonitorChange JSON;
// outbox holds the pre-built bus messages.
func (s *Store) InsertEventWithOutbox(ctx context.Context, tx pgx.Tx,
	eventID, missionID, assetID, changeType, severity, fingerprint string,
	payload []byte, occurredAt time.Time, outbox []OutboxRow) error {
	exec := func(q string, args ...any) (pgconn.CommandTag, error) {
		if tx != nil {
			return tx.Exec(ctx, q, args...)
		}
		return s.Pool.Exec(ctx, q, args...)
	}
	if _, err := exec(`
		INSERT INTO monitor.change_events (event_id, mission_id, asset_id, change_type, severity, fingerprint, payload, occurred_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (event_id, occurred_at) DO NOTHING`,
		eventID, missionID, assetID, changeType, severity, fingerprint, payload, occurredAt); err != nil {
		return err
	}
	for _, row := range outbox {
		if _, err := exec(`
			INSERT INTO monitor.event_outbox (event_id, subject, payload, created_at)
			VALUES ($1, $2, $3, now())
			ON CONFLICT (event_id) DO NOTHING`,
			row.EventID, row.Subject,
			map[string]any{"encoding": "base64", "data": base64.StdEncoding.EncodeToString(row.Data), "mission_id": row.MissionID}); err != nil {
			return err
		}
	}
	return nil
}

// OutboxPending claims a publish batch (FOR UPDATE SKIP LOCKED — the relay
// may run on multiple replicas later). payload.data is base64-decoded in SQL.
func (s *Store) OutboxPending(ctx context.Context, limit int) ([]OutboxRow, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT event_id, subject, payload->>'mission_id', decode(payload->>'data', 'base64'), created_at
		FROM monitor.event_outbox
		WHERE published_at IS NULL
		ORDER BY created_at ASC
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []OutboxRow
	for rows.Next() {
		var r OutboxRow
		var mission *string
		if err := rows.Scan(&r.EventID, &r.Subject, &mission, &r.Data, &r.CreatedAt); err != nil {
			return nil, err
		}
		if mission != nil {
			r.MissionID = *mission
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// OutboxMarkPublished settles a relayed row.
func (s *Store) OutboxMarkPublished(ctx context.Context, eventID string) error {
	_, err := s.Pool.Exec(ctx,
		`UPDATE monitor.event_outbox SET published_at = now() WHERE event_id = $1`, eventID)
	return err
}

// ---------------------------------------------------------------------------
// dedup_window (doc 03 §8/M6: 24 h fingerprint window; repeats bump count)
// ---------------------------------------------------------------------------

// DedupHit reports a live dedup-window entry.
type DedupHit struct {
	FirstEventID string
	FirstSeenAt  time.Time
	Count        int
}

// DedupCheckInsert returns the live window entry for fingerprint, or inserts
// a fresh 24 h row when absent/expired. The bool is "suppressed" (true = a
// live window exists — increment its count; false = new row, emit).
func (s *Store) DedupCheckInsert(ctx context.Context, fingerprint, eventID string, now time.Time) (*DedupHit, bool, error) {
	var hit DedupHit
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO monitor.dedup_window (fingerprint, first_event_id, first_seen_at, count, expires_at)
		VALUES ($1, $2, $3, 1, $3::timestamptz + interval '24 hours')
		ON CONFLICT (fingerprint) DO UPDATE
		SET count = CASE WHEN monitor.dedup_window.expires_at > $3
		                 THEN monitor.dedup_window.count + 1 ELSE 1 END,
		    first_event_id = CASE WHEN monitor.dedup_window.expires_at > $3
		                 THEN monitor.dedup_window.first_event_id ELSE $2 END,
		    first_seen_at = CASE WHEN monitor.dedup_window.expires_at > $3
		                 THEN monitor.dedup_window.first_seen_at ELSE $3 END,
		    expires_at = CASE WHEN monitor.dedup_window.expires_at > $3
		                 THEN monitor.dedup_window.expires_at ELSE $3::timestamptz + interval '24 hours' END
		RETURNING first_event_id, first_seen_at, count`,
		fingerprint, eventID, now).Scan(&hit.FirstEventID, &hit.FirstSeenAt, &hit.Count)
	if err != nil {
		return nil, false, err
	}
	suppressed := hit.FirstEventID != eventID
	return &hit, suppressed, nil
}

// ---------------------------------------------------------------------------
// suppressions (doc 03 §8: gate outbound emission, never delete history)
// ---------------------------------------------------------------------------

// InsertSuppression creates a suppression (mgmt API; selector keys:
// mission_id|asset_id|rule_id|change_type). Returns the new id.
func (s *Store) InsertSuppression(ctx context.Context, selector map[string]string, reason, createdBy string, expiresAt time.Time) (string, error) {
	sel := map[string]any{}
	for k, v := range selector {
		switch k {
		case "mission_id", "asset_id", "rule_id", "change_type":
			sel[k] = v
		}
	}
	var id string
	err := s.Pool.QueryRow(ctx, `
		INSERT INTO monitor.suppressions (selector, reason, created_by, expires_at)
		VALUES ($1, $2, $3, $4) RETURNING suppression_id::text`,
		sel, reason, createdBy, expiresAt).Scan(&id)
	return id, err
}

// DeleteSuppression removes a suppression by id.
func (s *Store) DeleteSuppression(ctx context.Context, id string) error {
	_, err := s.Pool.Exec(ctx, `DELETE FROM monitor.suppressions WHERE suppression_id = $1`, id)
	return err
}

// IsSuppressed reports whether any live suppression matches (mission, asset,
// rule, change_type) — checked in M6 before emission.
func (s *Store) IsSuppressed(ctx context.Context, missionID, assetID, ruleID, changeType string, now time.Time) (bool, string, error) {
	var reason string
	err := s.Pool.QueryRow(ctx, `
		SELECT reason FROM monitor.suppressions
		WHERE expires_at > $5
		  AND (selector->>'mission_id' IS NULL OR selector->>'mission_id' = $1)
		  AND (selector->>'asset_id' IS NULL OR selector->>'asset_id' = $2)
		  AND (selector->>'rule_id' IS NULL OR selector->>'rule_id' = $3)
		  AND (selector->>'change_type' IS NULL OR selector->>'change_type' = $4)
		  AND (selector ? 'mission_id' OR selector ? 'asset_id' OR selector ? 'rule_id' OR selector ? 'change_type')
		LIMIT 1`, missionID, assetID, ruleID, changeType, now).Scan(&reason)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, "", nil
	}
	return true, reason, err
}

// ---------------------------------------------------------------------------
// pending_changes (doc 03 §7.1 two-consecutive-probe confirmation)
// ---------------------------------------------------------------------------

// PendingChange is one parked state-transition observation.
type PendingChange struct {
	DiffKey     string
	Fingerprint string
	AfterHash   string
	Payload     []byte // serialized diff.Change candidate
	FirstSeenAt time.Time
}

// PendingUpsert parks a state-transition candidate awaiting confirmation.
func (s *Store) PendingUpsert(ctx context.Context, assetID, probeType, diffKey, fingerprint, afterHash string, payload []byte, firstSeen time.Time) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO monitor.pending_changes (asset_id, probe_type, diff_key, fingerprint, after_hash, payload, first_seen_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (asset_id, probe_type, diff_key) DO UPDATE
		SET fingerprint = EXCLUDED.fingerprint, after_hash = EXCLUDED.after_hash,
		    payload = EXCLUDED.payload, first_seen_at = EXCLUDED.first_seen_at`,
		assetID, probeType, diffKey, fingerprint, afterHash, payload, firstSeen)
	return err
}

// PendingForAsset lists parked candidates for (asset, probe_type).
func (s *Store) PendingForAsset(ctx context.Context, assetID, probeType string) ([]PendingChange, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT diff_key, fingerprint, after_hash, payload, first_seen_at
		FROM monitor.pending_changes WHERE asset_id = $1 AND probe_type = $2`,
		assetID, probeType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []PendingChange
	for rows.Next() {
		var p PendingChange
		if err := rows.Scan(&p.DiffKey, &p.Fingerprint, &p.AfterHash, &p.Payload, &p.FirstSeenAt); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// PendingDelete drops a parked candidate (confirmed or voided).
func (s *Store) PendingDelete(ctx context.Context, assetID, probeType, diffKey string) error {
	_, err := s.Pool.Exec(ctx, `
		DELETE FROM monitor.pending_changes WHERE asset_id = $1 AND probe_type = $2 AND diff_key = $3`,
		assetID, probeType, diffKey)
	return err
}

// ---------------------------------------------------------------------------
// asset_candidates (doc 03 §9.4 passive-candidate metadata)
// ---------------------------------------------------------------------------

// InsertCandidate records a passive candidate; returns false when the
// (mission, identifier) pair was already known (dedup of feed replays).
func (s *Store) InsertCandidate(ctx context.Context, missionID, identifier, kind, scopeMatch string, source []byte) (bool, error) {
	tag, err := s.Pool.Exec(ctx, `
		INSERT INTO monitor.asset_candidates (mission_id, identifier, kind, scope_match, source)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (mission_id, identifier) DO NOTHING`,
		missionID, identifier, kind, scopeMatch, source)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// ---------------------------------------------------------------------------
// baselines / exposure_state / scan_jobs_dead
// ---------------------------------------------------------------------------

// BaselineRule is one monitor.baselines row.
type BaselineRule struct {
	RuleID    string
	MissionID string
	Name      string
	RegoRef   string
	Config    []byte
}

// UpsertBaselineRule stores a compiled baseline rule.
func (s *Store) UpsertBaselineRule(ctx context.Context, r BaselineRule) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO monitor.baselines (rule_id, mission_id, name, rego_ref, config)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (rule_id) DO UPDATE SET config = EXCLUDED.config, name = EXCLUDED.name`,
		r.RuleID, r.MissionID, r.Name, r.RegoRef, r.Config)
	return err
}

// BaselineRules returns the rules of one baseline id (rule_id prefix).
func (s *Store) BaselineRules(ctx context.Context, baselineID string) ([]BaselineRule, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT rule_id, mission_id, name, rego_ref, config FROM monitor.baselines
		WHERE rule_id LIKE $1 ORDER BY rule_id`, baselineID+":%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []BaselineRule
	for rows.Next() {
		var r BaselineRule
		if err := rows.Scan(&r.RuleID, &r.MissionID, &r.Name, &r.RegoRef, &r.Config); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// DriftState reads baseline_state for (asset, rule).
func (s *Store) DriftState(ctx context.Context, assetID, ruleID string) (string, error) {
	var state string
	err := s.Pool.QueryRow(ctx, `
		SELECT state FROM monitor.baseline_state WHERE asset_id = $1 AND rule_id = $2`,
		assetID, ruleID).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return state, err
}

// SetDriftState writes the sticky drift state (doc 03 §7.3: resolution fires
// exactly once).
func (s *Store) SetDriftState(ctx context.Context, assetID, ruleID, state string) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO monitor.baseline_state (asset_id, rule_id, state, since)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (asset_id, rule_id) DO UPDATE SET state = EXCLUDED.state,
		  since = CASE WHEN monitor.baseline_state.state <> EXCLUDED.state THEN now()
		               ELSE monitor.baseline_state.since END`,
		assetID, ruleID, state)
	return err
}

// ExposureState is one exposure_state row.
type ExposureState struct {
	RuleID   string
	State    string
	OpenedAt time.Time
	ClosedAt *time.Time
}

// ExposureStates lists one asset's exposure rows.
func (s *Store) ExposureStates(ctx context.Context, assetID string) ([]ExposureState, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT rule_id, state, opened_at, closed_at FROM monitor.exposure_state WHERE asset_id = $1`,
		assetID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExposureState
	for rows.Next() {
		var e ExposureState
		if err := rows.Scan(&e.RuleID, &e.State, &e.OpenedAt, &e.ClosedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// SetExposureState writes the exposure state machine transition (doc 03 §7.4:
// CLOSED → OPEN → CLOSED; only transitions emit).
func (s *Store) SetExposureState(ctx context.Context, assetID, ruleID, state string) error {
	var q string
	if state == "open" {
		q = `INSERT INTO monitor.exposure_state (asset_id, rule_id, state, opened_at)
		     VALUES ($1, $2, 'open', now())
		     ON CONFLICT (asset_id, rule_id) DO UPDATE SET state = 'open', opened_at = now(), closed_at = NULL`
	} else {
		q = `INSERT INTO monitor.exposure_state (asset_id, rule_id, state, closed_at)
		     VALUES ($1, $2, 'closed', now())
		     ON CONFLICT (asset_id, rule_id) DO UPDATE SET state = 'closed', closed_at = now()`
	}
	_, err := s.Pool.Exec(ctx, q, assetID, ruleID)
	return err
}

// ListExposures is the management-API exposure board (doc 03 §13).
func (s *Store) ListExposures(ctx context.Context, state string, limit int) ([]ExposureState, []string, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT asset_id::text, rule_id, state, opened_at, closed_at FROM monitor.exposure_state
		WHERE ($1 = '' OR state = $1) ORDER BY opened_at DESC LIMIT $2`, state, limit)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	var out []ExposureState
	var assets []string
	for rows.Next() {
		var e ExposureState
		var asset string
		if err := rows.Scan(&asset, &e.RuleID, &e.State, &e.OpenedAt, &e.ClosedAt); err != nil {
			return nil, nil, err
		}
		out = append(out, e)
		assets = append(assets, asset)
	}
	return out, assets, rows.Err()
}

// InsertDeadJob dead-letters a poison scan job (doc 03 §9.2/§12).
func (s *Store) InsertDeadJob(ctx context.Context, job []byte, errText string, attempts int) error {
	_, err := s.Pool.Exec(ctx, `
		INSERT INTO monitor.scan_jobs_dead (job, error, attempts) VALUES ($1, $2, $3)`,
		job, errText, attempts)
	return err
}

// ---------------------------------------------------------------------------
// cross-schema read-only lookups (single DB; gatekeeper/platform/dp own writes)
// ---------------------------------------------------------------------------

// MissionContext resolves the mission's RoE/org context (read-only;
// gatekeeper remains the PDP — this is classification data, doc 03 §5.1
// event enrichment).
type MissionContext struct {
	MissionID  string
	ROEID      string
	ROEVersion int
	OrgID      string
	ScopeJSON  []byte
}

// GetMissionContext joins platform.missions → gatekeeper.roe_records.
func (s *Store) GetMissionContext(ctx context.Context, missionID string) (*MissionContext, error) {
	var mc MissionContext
	err := s.Pool.QueryRow(ctx, `
		SELECT m.mission_id, m.roe_id, m.roe_version,
		       COALESCE(r.org_id, ''), r.scope
		FROM platform.missions m
		LEFT JOIN gatekeeper.roe_records r ON r.roe_id = m.roe_id AND r.version = m.roe_version
		WHERE m.mission_id = $1`, missionID).
		Scan(&mc.MissionID, &mc.ROEID, &mc.ROEVersion, &mc.OrgID, &mc.ScopeJSON)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &mc, err
}

// InventoryAsset is one dp.assets row (read-only watch-set sync source,
// doc 03 §2: the watch set syncs from the data-platform inventory).
type InventoryAsset struct {
	AssetID     string
	Type        string
	Value       string
	ROEID       string
	Criticality string
	OwnerGroup  string
}

// SyncInventory reads active dp assets for a RoE (kinds mapped by caller).
func (s *Store) SyncInventory(ctx context.Context, roeID string, types []string) ([]InventoryAsset, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT asset_id::text, type, value, roe_id,
		       COALESCE(attributes->>'criticality', ''),
		       COALESCE(attributes->>'owner_group', '')
		FROM dp.assets
		WHERE status = 'active' AND roe_id = $1 AND type = ANY ($2)`, roeID, types)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []InventoryAsset
	for rows.Next() {
		var a InventoryAsset
		if err := rows.Scan(&a.AssetID, &a.Type, &a.Value, &a.ROEID, &a.Criticality, &a.OwnerGroup); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// CountRecentEvents counts a mission's emitted change events in the window
// (M6 emission caps, doc 03 §11).
func (s *Store) CountRecentEvents(ctx context.Context, missionID string, since time.Time) (int, error) {
	var n int
	err := s.Pool.QueryRow(ctx, `
		SELECT count(*) FROM monitor.change_events WHERE mission_id = $1 AND occurred_at >= $2`,
		missionID, since).Scan(&n)
	return n, err
}

// EventTimeline is the management-API asset timeline (doc 03 §13).
func (s *Store) EventTimeline(ctx context.Context, assetID string, from, to time.Time, limit int) ([]map[string]any, error) {
	rows, err := s.Pool.Query(ctx, `
		SELECT payload FROM monitor.change_events
		WHERE asset_id = $1 AND occurred_at BETWEEN $2 AND $3
		ORDER BY occurred_at DESC LIMIT $4`, assetID, from, to, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var payload map[string]any
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		out = append(out, payload)
	}
	return out, rows.Err()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
