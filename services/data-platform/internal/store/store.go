// Package store is the Postgres data layer for the dp + tenancy schemas
// (one DB "aegisbastion", schema-per-context; doc 09 §4, Ruling C4). Every query
// carries an explicit tenant predicate — cross-tenant access is impossible by
// construction (TPEL, doc 09 §9.6), not by developer discipline.
package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Store wraps the connection pool.
type Store struct {
	Pool *pgxpool.Pool
}

// New connects and sets the schema search path (comma-separated, e.g.
// "dp,tenancy"). All queries in this package are schema-qualified anyway;
// the search path is belt-and-braces.
func New(ctx context.Context, databaseURL, searchPath string) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	if searchPath == "" {
		searchPath = "dp,tenancy"
	}
	parts := make([]string, 0, 3)
	for _, p := range strings.Split(searchPath, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			parts = append(parts, pgx.Identifier{p}.Sanitize())
		}
	}
	path := strings.Join(append(parts, "public"), ", ")
	cfg.AfterConnect = func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, "SET search_path TO "+path)
		return err
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping: %w", err)
	}
	return &Store{Pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.Pool.Close() }
