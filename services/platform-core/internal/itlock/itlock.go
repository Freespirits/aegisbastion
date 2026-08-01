// Package itlock serializes integration tests across packages: `go test
// ./...` runs package binaries concurrently, and every integration suite
// truncates the same platform schema — so each suite holds a Postgres
// advisory session lock for its duration.
package itlock

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// key is the shared lock id ("platform-core itest").
const key int64 = 0x706C6174666F726D

// Acquire takes the cross-package integration lock and releases it on test
// cleanup. Uses a dedicated pooled connection (session-level lock).
func Acquire(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("itlock acquire conn: %v", err)
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", key); err != nil {
		conn.Release()
		t.Fatalf("itlock: %v", err)
	}
	t.Cleanup(func() {
		if _, err := conn.Exec(context.Background(), "SELECT pg_advisory_unlock($1)", key); err != nil {
			t.Logf("itlock unlock: %v", err)
		}
		conn.Release()
	})
}
