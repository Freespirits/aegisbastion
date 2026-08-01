-- 000006_monitor_snapshot_ids.down.sql
-- Reverts the snapshot_id columns to uuid. NOTE: fails while any row holds a
-- prefixed-ULID ("snp_…") id — delete or remap those rows first.

BEGIN;

ALTER TABLE monitor.snapshots_latest  ALTER COLUMN snapshot_id TYPE uuid USING snapshot_id::uuid;
ALTER TABLE monitor.snapshots_history ALTER COLUMN snapshot_id TYPE uuid USING snapshot_id::uuid;

COMMIT;
