/**
 * Domain types for herald (doc 05). TS mirrors of the JSON contracts in
 * schemas/alert/v1 (AlertEvent v1 + CloudEvents envelope) and of the Postgres
 * rows in db/migrations/000005_alert.up.sql. The JSON Schemas remain the
 * source of truth (validated at ingress); these types are the in-service view.
 */
export const SEVERITIES = ["info", "low", "medium", "high", "critical"];
/** Ascending rank for comparisons (info=1 … critical=5). */
export function severityRank(s) {
    return SEVERITIES.indexOf(s) + 1;
}
export function maxSeverity(a, b) {
    return severityRank(a) >= severityRank(b) ? a : b;
}
export const CHANNELS = ["slack", "teams", "splunk-hec", "syslog", "webhook"];
