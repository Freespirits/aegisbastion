-- 000005_alert.down.sql
BEGIN;
DROP TRIGGER IF EXISTS audit_log_append_only ON alert.audit_log;
DROP FUNCTION IF EXISTS alert.audit_enforce_append_only();
DROP TABLE IF EXISTS alert.audit_log;
DROP TABLE IF EXISTS alert.egress_policies;
DROP TABLE IF EXISTS alert.acks;
DROP TABLE IF EXISTS alert.dedup_state;
DROP TABLE IF EXISTS alert.deliveries;
DROP TABLE IF EXISTS alert.routing_policies;
DROP TABLE IF EXISTS alert.escalation_policies;
DROP TABLE IF EXISTS alert.incident_alerts;
DROP TABLE IF EXISTS alert.alerts;
DROP TABLE IF EXISTS alert.incidents;
DROP SCHEMA IF EXISTS alert;
COMMIT;
