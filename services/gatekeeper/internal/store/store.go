// Package store owns the Postgres connection pool for the gatekeeper binary.
// One database ("aegisbastion"), schema-per-bounded-context: all gatekeeper
// tables live in schema "gatekeeper" (db/migrations/000002), selected via
// DB_SEARCH_PATH (compose sets DB_SEARCH_PATH=gatekeeper).
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DB wraps the pool.
type DB struct {
	Pool *pgxpool.Pool
}

// Connect builds a pool from DATABASE_URL and applies search_path on every
// connection. It pings with a bounded timeout.
func Connect(ctx context.Context, databaseURL, searchPath string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("store: parse DATABASE_URL: %w", err)
	}
	cfg.MaxConns = 16
	cfg.MinConns = 1
	cfg.MaxConnLifetime = 30 * time.Minute
	if searchPath != "" {
		sp := searchPath
		cfg.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
			// Parameterized set_config avoids interpolating the env value into SQL.
			_, err := conn.Exec(ctx, "SELECT set_config('search_path', $1, false)", sp)
			return err
		}
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Ping reports DB liveness for health endpoints.
func (d *DB) Ping(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	return d.Pool.Ping(ctx)
}

// Close releases the pool.
func (d *DB) Close() { d.Pool.Close() }
