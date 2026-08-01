-- 000002_gatekeeper.down.sql
BEGIN;
DROP TABLE IF EXISTS gatekeeper.audit_events_default;
DROP TABLE IF EXISTS gatekeeper.audit_events;
DROP TABLE IF EXISTS gatekeeper.revocations;
DROP TABLE IF EXISTS gatekeeper.issued_tokens;
DROP TABLE IF EXISTS gatekeeper.authz_decisions;
DROP TABLE IF EXISTS gatekeeper.approval_votes;
DROP TABLE IF EXISTS gatekeeper.approvals;
DROP TABLE IF EXISTS gatekeeper.rbac_bindings;
DROP TABLE IF EXISTS gatekeeper.rbac_roles;
DROP TABLE IF EXISTS gatekeeper.roe_effective_targets;
DROP TABLE IF EXISTS gatekeeper.roe_records;
DROP FUNCTION IF EXISTS gatekeeper.audit_enforce_append_only();
DROP FUNCTION IF EXISTS gatekeeper.roe_enforce_immutability();
DROP SCHEMA IF EXISTS gatekeeper;
DROP ROLE IF EXISTS aegisbastion_audit_writer;
COMMIT;
