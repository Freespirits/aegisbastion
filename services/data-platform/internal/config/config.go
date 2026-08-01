// Package config loads data-platform configuration from the environment.
// All knobs are env-driven (doc 01 §14: single Compose host, 12-factor style).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved data-platform (doc 09) configuration.
type Config struct {
	// DatabaseURL is the Postgres DSN (one DB "aegisbastion", schema-per-context).
	DatabaseURL string
	// DBSearchPath selects the schemas (default "dp,tenancy", doc 09 §4).
	DBSearchPath string

	// NATSUrl is the JetStream bus address (canonical bus, Ruling C3).
	NATSUrl string

	// HTTPPort serves the Ingest API, the GraphQL Query API, admin REST and
	// the health endpoints (compose maps 8082).
	HTTPPort int

	// GatekeeperJWKSURL is the gatekeeper JWKS endpoint used by the ingest
	// Scope Token re-verification (defense in depth, doc 09 §2.2 — dp never
	// grants, it re-verifies gatekeeper's grant; Ruling B).
	GatekeeperJWKSURL string

	// S3 (MinIO at MVP-A): token manifests (doc 11 §3.2) and evidence blobs.
	S3Endpoint  string
	S3AccessKey string
	S3SecretKey string
	S3UseTLS    bool
	// ManifestBucket overrides the token manifest bucket (default
	// "token-manifests").
	ManifestBucket string
	// EvidenceBucket holds finding evidence blobs (default "evidence").
	EvidenceBucket string

	// AdminPrincipals is the MVP admin shim: identities allowed to call the
	// /v1/admin/* tenant/grant bootstrap endpoints (empty = admin API
	// disabled, fail-closed). Platform-wide RBAC is gatekeeper rbac-service
	// (doc 11); this only governs dp tenancy bootstrap.
	AdminPrincipals []string

	// EventSpillFile is the local spill for dp.* change events when JetStream
	// is down (doc 09 §8: ingest writes to a local spill file; a relay replays
	// in order on recovery). Empty disables spilling (publish errors are then
	// only logged).
	EventSpillFile string
	// EventRelayTick is how often the spill relay retries.
	EventRelayTick time.Duration

	// AuditForwardTick is how often the audit-outbox forwarder drains
	// dp.audit_outbox → audit.events (gatekeeper audit of record, doc 09 §4.4).
	AuditForwardTick time.Duration

	// RetentionTick enables the in-process retention purge loop (doc 09 §10;
	// MVP default is the manual `purge-retention` subcommand — 0 disables the
	// loop).
	RetentionTick time.Duration

	// EnableConsumers starts the JetStream consumers (detect.findings,
	// monitor.assets.new, hub.discover.asset.changed).
	EnableConsumers bool

	// MaxQueryPage is the GraphQL page cap (doc 09 §2.3: max page 500).
	MaxQueryPage int
	// MaxTraversalDepth is the assetNeighborhood depth cap (doc 09 §2.3: ≤ 4).
	MaxTraversalDepth int

	// InstanceID identifies this service instance in audit actors.
	InstanceID string
}

// FromEnv loads Config from the process environment.
func FromEnv() (*Config, error) {
	c := &Config{
		DatabaseURL:  os.Getenv("DATABASE_URL"),
		DBSearchPath: getenv("DB_SEARCH_PATH", "dp,tenancy"),
		NATSUrl:      getenv("NATS_URL", "nats://localhost:4222"),
		HTTPPort:     getenvInt("DP_HTTP_PORT", 8082),
		GatekeeperJWKSURL: getenv("GATEKEEPER_JWKS_URL",
			"http://localhost:8080/.well-known/gatekeeper-jwks.json"),

		S3Endpoint:     getenv("S3_ENDPOINT", "localhost:9000"),
		S3AccessKey:    getenv("S3_ACCESS_KEY", "aegisbastion"),
		S3SecretKey:    getenv("S3_SECRET_KEY", "aegisbastion-dev-secret"),
		S3UseTLS:       getenvBool("S3_USE_TLS", false),
		ManifestBucket: getenv("DP_MANIFEST_BUCKET", "token-manifests"),
		EvidenceBucket: getenv("DP_EVIDENCE_BUCKET", "evidence"),

		AdminPrincipals: splitCSV(os.Getenv("DP_ADMIN_PRINCIPALS")),

		EventSpillFile:   getenv("DP_EVENT_SPILL_FILE", "/tmp/dp-events-spill.jsonl"),
		EventRelayTick:   getenvDur("DP_EVENT_RELAY_TICK", 5*time.Second),
		AuditForwardTick: getenvDur("DP_AUDIT_FORWARD_TICK", 2*time.Second),
		RetentionTick:    getenvDur("DP_RETENTION_TICK", 0),

		EnableConsumers:   getenvBool("DP_ENABLE_CONSUMERS", true),
		MaxQueryPage:      getenvInt("DP_MAX_QUERY_PAGE", 500),
		MaxTraversalDepth: getenvInt("DP_MAX_TRAVERSAL_DEPTH", 4),

		InstanceID: getenv("DP_INSTANCE_ID", ""),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if c.InstanceID == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "unknown"
		}
		c.InstanceID = "data-platform-" + host
	}
	return c, nil
}

// AdminAllowed reports whether identity may call the /v1/admin/* bootstrap
// endpoints under the MVP admin shim.
func (c *Config) AdminAllowed(identity string) bool {
	for _, p := range c.AdminPrincipals {
		if p == identity {
			return true
		}
	}
	return false
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getenvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func getenvDur(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func getenvBool(key string, fallback bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return fallback
}

func splitCSV(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
