// Package testenv wires integration tests to the compose Postgres
// (docker compose --profile infra up -d from deploy/). Tests skip
// themselves when the database is unreachable so unit runs stay hermetic.
package testenv

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
)

// DefaultDSN matches deploy/docker-compose.yml's published Postgres.
const DefaultDSN = "postgres://aegisbastion:aegisbastion-dev@localhost:5432/aegisbastion?sslmode=disable"

// Store connects to the integration database or skips the test.
func Store(t *testing.T) *store.Store {
	t.Helper()
	dsn := os.Getenv("DP_TEST_DATABASE_URL")
	if dsn == "" {
		dsn = DefaultDSN
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	st, err := store.New(ctx, dsn, "dp,tenancy")
	if err != nil {
		t.Skipf("integration database unavailable (%v) — start compose infra", err)
	}
	t.Cleanup(st.Close)
	return st
}

// Tenant creates a fresh tenant and returns its id. All tenant rows in the
// dp + tenancy schemas are removed at test cleanup.
func Tenant(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	ctx := context.Background()
	tn, err := st.CreateTenant(ctx, name, "standard", "local")
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	t.Cleanup(func() {
		cctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		for _, q := range []string{
			`DELETE FROM dp.finding_state_transitions WHERE tenant_id = $1`,
			`DELETE FROM dp.findings WHERE tenant_id = $1`,
			`DELETE FROM dp.finding_provenance WHERE tenant_id = $1`,
			`DELETE FROM dp.asset_edges WHERE tenant_id = $1`,
			`DELETE FROM dp.assets WHERE tenant_id = $1`,
			`DELETE FROM dp.ingest_batches WHERE tenant_id = $1`,
			`DELETE FROM dp.audit_outbox WHERE tenant_id = $1`,
			`DELETE FROM tenancy.grants WHERE tenant_id = $1`,
			`DELETE FROM tenancy.workspaces WHERE tenant_id = $1`,
			`DELETE FROM tenancy.tenants WHERE tenant_id = $1`,
		} {
			if _, err := st.Pool.Exec(cctx, q, tn.TenantID); err != nil {
				t.Logf("cleanup %q: %v", q, err)
			}
		}
	})
	return tn.TenantID
}

// Grant inserts a dp data-access grant (cleanup happens with the tenant).
func Grant(t *testing.T, st *store.Store, tenantID, principal, role string) {
	t.Helper()
	if _, err := st.CreateGrant(context.Background(), tenantID, principal, role); err != nil {
		t.Fatalf("create grant: %v", err)
	}
}

// Exec runs raw SQL against the integration database (fixture setup).
func Exec(t *testing.T, st *store.Store, query string, args ...any) {
	t.Helper()
	if _, err := st.Pool.Exec(context.Background(), query, args...); err != nil {
		t.Fatalf("exec %q: %v", query, err)
	}
}
