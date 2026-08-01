-- 000003_data_platform.down.sql
BEGIN;
DROP TABLE IF EXISTS tenancy.grants;
DROP TABLE IF EXISTS tenancy.workspaces;
DROP TABLE IF EXISTS tenancy.tenants;
DROP TABLE IF EXISTS tenancy.retention_profiles;
DROP SCHEMA IF EXISTS tenancy;
DROP TABLE IF EXISTS dp.audit_outbox;
DROP TABLE IF EXISTS dp.ingest_batches;
DROP TABLE IF EXISTS dp.finding_state_transitions;
DROP TABLE IF EXISTS dp.findings_default;
DROP TABLE IF EXISTS dp.findings;
DROP TABLE IF EXISTS dp.finding_provenance;
DROP TABLE IF EXISTS dp.asset_edges;
DROP TABLE IF EXISTS dp.assets;
DROP SCHEMA IF EXISTS dp;
COMMIT;
