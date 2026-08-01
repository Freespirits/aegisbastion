// Package config is the discover module's env-driven configuration (MVP-A
// Compose contract — deploy/docker-compose.yml). Every binary (orchestrator,
// workers, discover-mcp) loads the same struct and uses what it needs.
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the module configuration.
type Config struct {
	// Postgres working store (schema discover).
	DatabaseURL string
	SearchPath  string

	// NATS JetStream.
	NATSURL string

	// Gatekeeper (single PDP — PEP client only, Ruling B).
	GatekeeperGRPCAddr string // e.g. gatekeeper:50051
	GatekeeperJWKSURL  string // e.g. http://gatekeeper:8080/.well-known/gatekeeper-jwks.json

	// Data platform Ingest API (Ruling C4); empty ⇒ offline (local store only).
	DPIngestURL string
	DPPrincipal string // TPEL X-DP-Principal; grant role service_discover

	// Object store (evidence + token manifests).
	S3Endpoint string
	S3Region   string
	S3Access   string
	S3Secret   string
	S3UseTLS   bool

	// HTTP surfaces.
	HTTPAddr string // orchestrator REST (+ worker health endpoints)
	MCPAddr  string // discover-mcp

	// Offline/fixture mode: connectors replay recorded responses; no DP
	// ingest, no evidence archiving, no live egress (doc 02 §9 — tests run
	// without internet).
	Offline     bool
	FixturesDir string

	// Connector manifest + credential files.
	ConnectorsFile string
	SourceKeysFile string // JSON: tenant → connector → api key
	CloudCredsFile string // JSON: tenant → account-ref → cloud.Credentials

	// Safety knobs.
	AuditSpoolMax      int64         // spool full ⇒ R1+ intake pauses (doc 02 §6.4)
	AssetTTL           time.Duration // expiry sweeper; 0 disables
	AllowPrivateEgress bool          // TEST HOOK ONLY (netguard.Config.AllowPrivate)
	StatusHeartbeat    time.Duration // RUNNING status re-emit cadence (doc 02 §3.3: 15 s)
}

// Load reads the environment.
func Load() (*Config, error) {
	c := &Config{
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		SearchPath:         envOr("DB_SEARCH_PATH", "discover"),
		NATSURL:            envOr("NATS_URL", "nats://localhost:4222"),
		GatekeeperGRPCAddr: envOr("GATEKEEPER_GRPC_ADDR", "localhost:50051"),
		GatekeeperJWKSURL:  envOr("GATEKEEPER_JWKS_URL", "http://localhost:8080/.well-known/gatekeeper-jwks.json"),
		DPIngestURL:        os.Getenv("DP_INGEST_URL"),
		DPPrincipal:        envOr("DP_PRINCIPAL", "svc-discover"),
		S3Endpoint:         os.Getenv("S3_ENDPOINT"),
		S3Region:           envOr("S3_REGION", "us-east-1"),
		S3Access:           os.Getenv("S3_ACCESS_KEY"),
		S3Secret:           os.Getenv("S3_SECRET_KEY"),
		S3UseTLS:           os.Getenv("S3_USE_TLS") == "true",
		HTTPAddr:           envOr("DISCOVER_HTTP_ADDR", ":8083"),
		MCPAddr:            envOr("DISCOVER_MCP_ADDR", ":8087"),
		Offline:            os.Getenv("DISCOVER_OFFLINE") == "true",
		FixturesDir:        envOr("DISCOVER_FIXTURES_DIR", "testdata/fixtures"),
		ConnectorsFile:     os.Getenv("DISCOVER_CONNECTORS_FILE"),
		SourceKeysFile:     os.Getenv("DISCOVER_SOURCE_KEYS_FILE"),
		CloudCredsFile:     os.Getenv("DISCOVER_CLOUD_CREDS_FILE"),
		AuditSpoolMax:      envInt64("DISCOVER_AUDIT_SPOOL_MAX", 10000),
		StatusHeartbeat:    envDur("DISCOVER_STATUS_HEARTBEAT", 15*time.Second),
	}
	if c.DPIngestURL == "" {
		c.DPIngestURL = envOr("DP_HTTP_URL", "")
	}
	if v := os.Getenv("DISCOVER_ASSET_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return nil, fmt.Errorf("DISCOVER_ASSET_TTL: %w", err)
		}
		c.AssetTTL = d
	} else {
		c.AssetTTL = 720 * time.Hour // 30 d default expiry sweeper
	}
	c.AllowPrivateEgress = os.Getenv("DISCOVER_ALLOW_PRIVATE_EGRESS") == "true"
	if !c.Offline {
		if c.DatabaseURL == "" {
			return nil, fmt.Errorf("DATABASE_URL is required")
		}
	}
	return c, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt64(key string, def int64) int64 {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
