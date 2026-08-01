-- 000006_monitor_snapshot_ids.up.sql
-- Monitor (doc 03 §6.2): snapshot_id is a prefixed ULID ("snp_01J9E…"), not a
-- uuid — 000004 declared the snapshots columns uuid, which rejected every
-- production SnapshotDocument id at write time. Change both snapshot tables
-- to text so the doc-03 wire form round-trips (MonitorChange.snapshot_refs
-- carries the same ids, doc 03 §5.1).

BEGIN;

ALTER TABLE monitor.snapshots_latest  ALTER COLUMN snapshot_id TYPE text;
ALTER TABLE monitor.snapshots_history ALTER COLUMN snapshot_id TYPE text;

COMMIT;
