// Package config loads gatekeeper configuration from the environment
// (compose sets these; see deploy/docker-compose.yml + .env.example).
package config

import (
	"fmt"
	"os"
	"time"
)

// Config is the full runtime configuration.
type Config struct {
	DatabaseURL  string // DATABASE_URL (required)
	DBSearchPath string // DB_SEARCH_PATH (default "gatekeeper")
	NATSURL      string // NATS_URL (required)

	S3Endpoint  string // S3_ENDPOINT (MinIO host:port)
	S3AccessKey string // S3_ACCESS_KEY
	S3SecretKey string // S3_SECRET_KEY
	S3UseTLS    bool   // S3_USE_TLS

	SigningKeyFile       string // GATEKEEPER_SIGNING_KEY_FILE (MVP-A sealed file key, doc 00 §5 Q1)
	SigningKeyPassphrase string // GATEKEEPER_SIGNING_KEY_PASSPHRASE (optional; seals the file key at rest)

	TokenIssuer   string        // TOKEN_ISSUER (default "gatekeeper.platform")
	TokenAudience string        // TOKEN_AUDIENCE (default "aegisbastion.modules")
	TokenTTL      time.Duration // TOKEN_TTL (default 15m; hard-capped at 15m per Ruling C5)

	ManifestBucket    string // MANIFEST_BUCKET (default "token-manifests")
	ManifestURIPrefix string // MANIFEST_URI_PREFIX (default "blob://")

	GRPCAddr string // GATEKEEPER_GRPC_LISTEN (default ":50051")
	HTTPAddr string // GATEKEEPER_HTTP_LISTEN (default ":8080")

	// DPInventoryURL is module 09's query endpoint for the R2/R3 verified-
	// inventory check (pipeline step 4). Empty at Phase 0 → the check is
	// skipped (documented Phase-0 deviation); once data-platform lands, set
	// this to re-enable fail-closed inventory verification.
	DPInventoryURL string // DP_INVENTORY_URL

	// CapabilityRegistryFile optionally extends/overrides the built-in
	// capability → risk-class registry.
	CapabilityRegistryFile string // CAPABILITY_REGISTRY_FILE
}

// MaxTokenTTL is the Ruling C5 hard cap: 15 minutes for ALL active classes R1–R3.
const MaxTokenTTL = 15 * time.Minute

// Load reads the environment.
func Load() (*Config, error) {
	c := &Config{
		DatabaseURL:            os.Getenv("DATABASE_URL"),
		DBSearchPath:           getenv("DB_SEARCH_PATH", "gatekeeper"),
		NATSURL:                os.Getenv("NATS_URL"),
		S3Endpoint:             os.Getenv("S3_ENDPOINT"),
		S3AccessKey:            os.Getenv("S3_ACCESS_KEY"),
		S3SecretKey:            os.Getenv("S3_SECRET_KEY"),
		S3UseTLS:               os.Getenv("S3_USE_TLS") == "true",
		SigningKeyFile:         os.Getenv("GATEKEEPER_SIGNING_KEY_FILE"),
		SigningKeyPassphrase:   os.Getenv("GATEKEEPER_SIGNING_KEY_PASSPHRASE"),
		TokenIssuer:            getenv("TOKEN_ISSUER", "gatekeeper.platform"),
		TokenAudience:          getenv("TOKEN_AUDIENCE", "aegisbastion.modules"),
		ManifestBucket:         getenv("MANIFEST_BUCKET", "token-manifests"),
		ManifestURIPrefix:      getenv("MANIFEST_URI_PREFIX", "blob://"),
		GRPCAddr:               getenv("GATEKEEPER_GRPC_LISTEN", ":50051"),
		HTTPAddr:               getenv("GATEKEEPER_HTTP_LISTEN", ":8080"),
		DPInventoryURL:         os.Getenv("DP_INVENTORY_URL"),
		CapabilityRegistryFile: os.Getenv("CAPABILITY_REGISTRY_FILE"),
	}
	ttl := getenv("TOKEN_TTL", "15m")
	d, err := time.ParseDuration(ttl)
	if err != nil {
		return nil, fmt.Errorf("config: TOKEN_TTL %q: %w", ttl, err)
	}
	if d <= 0 || d > MaxTokenTTL {
		return nil, fmt.Errorf("config: TOKEN_TTL %v violates the Ruling C5 hard cap (0 < ttl <= %v)", d, MaxTokenTTL)
	}
	c.TokenTTL = d
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("config: DATABASE_URL is required")
	}
	if c.NATSURL == "" {
		return nil, fmt.Errorf("config: NATS_URL is required")
	}
	return c, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
