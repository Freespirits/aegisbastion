-- seeds/herald-service-alert.sql
-- ---------------------------------------------------------------------------
-- Tenancy bootstrap for herald's enrichment path (doc 05 §3.1 C2).
--
-- herald (services/alert) enriches alerts with asset criticality/owner_group
-- by calling the data-platform GraphQL Query API with the TPEL shim header
--   X-DP-Principal: herald            (HERALD_DP_PRINCIPAL, default "herald")
-- TPEL (internal/tpel) resolves that principal against tenancy.grants and
-- FAILS CLOSED with GRANT_REQUIRED when the principal holds no grant. The
-- grant herald needs in every tenant whose assets it must enrich is:
--
--   tenancy.grants (principal = 'herald', role = 'service_alert')
--
-- 'service_alert' is the dp data-access role reserved for the alert module
-- (db/migrations/000003_data_platform.up.sql CHECK constraint; dp grants
-- govern dp data access only — platform-wide RBAC stays in gatekeeper).
--
-- This script is idempotent (UNIQUE (tenant_id, principal, role) + ON
-- CONFLICT DO NOTHING) and additive: it grants 'herald' a 'service_alert'
-- row on EVERY existing tenant. Re-run it after onboarding a new tenant.
--
-- Multi-tenant note: a principal with grants in exactly ONE tenant binds
-- implicitly; with several tenants herald must select one per request via
-- X-DP-Tenant — set HERALD_DP_TENANT on the alert service, or grant only on
-- the single tenant herald serves (replace the SELECT with a VALUES row).
--
-- Apply (compose host):
--   docker exec -i aegisbastion-mvp-a-postgres-1 \
--     psql -U aegisbastion -d aegisbastion -f - < services/data-platform/seeds/herald-service-alert.sql
-- or from any psql:
--   psql "$DATABASE_URL" -f services/data-platform/seeds/herald-service-alert.sql
--
-- Cross-reference: services/alert/bin/smoke-dev.mjs seeds the same row for
-- its throwaway org_smoke tenant (and cleans it up) — same shape as below.
-- ---------------------------------------------------------------------------

BEGIN;

INSERT INTO tenancy.grants (tenant_id, principal, role)
SELECT t.tenant_id, 'herald', 'service_alert'
FROM tenancy.tenants t
ON CONFLICT (tenant_id, principal, role) DO NOTHING;

COMMIT;

-- Verify: expect one row per tenant.
SELECT t.name AS tenant, g.principal, g.role, g.granted_at
FROM tenancy.grants g
JOIN tenancy.tenants t USING (tenant_id)
WHERE g.principal = 'herald' AND g.role = 'service_alert'
ORDER BY t.name;
