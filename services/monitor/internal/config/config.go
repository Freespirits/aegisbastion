// Package config is the monitor service's environment configuration
// (12-factor env, mirroring the sibling services' patterns).
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config wires the monitor service.
type Config struct {
	// Postgres (schema-per-context; DB_SEARCH_PATH=monitor).
	DatabaseURL  string
	DBSearchPath string

	// Bus.
	NATSURL string

	// gRPC endpoints.
	RegistryAddr   string // platform-core AgentService (:50052)
	GatekeeperAddr string // gatekeeper (:50051)
	JWKSURL        string // optional HTTP JWKS override

	// MinIO (token-manifests + monitor-raw buckets).
	S3Endpoint  string
	S3AccessKey string
	S3SecretKey string
	S3UseTLS    bool
	RawBucket   string // monitor-raw

	// HTTP (mgmt API + health, doc 03 §13).
	HTTPPort int

	// Identity.
	WorkerID string
	Region   string

	// Worker pool / egress (doc 03 §9.3 layer c).
	WorkerConcurrency  int
	EgressCapPerMinute int

	// Scheduler.
	SchedulerInterval    time.Duration
	WatchSetSyncInterval time.Duration

	// CT poller (M7).
	CTEnabled  bool
	CTBaseURL  string
	CTInterval time.Duration
}

// FromEnv loads the configuration from the environment.
func FromEnv() (*Config, error) {
	c := &Config{
		DatabaseURL:          os.Getenv("DATABASE_URL"),
		DBSearchPath:         getenv("DB_SEARCH_PATH", "monitor"),
		NATSURL:              getenv("NATS_URL", "nats://localhost:4222"),
		RegistryAddr:         getenv("REGISTRY_ADDR", "localhost:50052"),
		GatekeeperAddr:       getenv("GATEKEEPER_GRPC_ADDR", "localhost:50051"),
		JWKSURL:              os.Getenv("GATEKEEPER_JWKS_URL"),
		S3Endpoint:           getenv("S3_ENDPOINT", "localhost:9000"),
		S3AccessKey:          os.Getenv("S3_ACCESS_KEY"),
		S3SecretKey:          os.Getenv("S3_SECRET_KEY"),
		S3UseTLS:             os.Getenv("S3_USE_TLS") == "true",
		RawBucket:            getenv("MONITOR_RAW_BUCKET", "monitor-raw"),
		HTTPPort:             intEnv("HTTP_PORT", 8084),
		WorkerID:             getenv("WORKER_ID", hostname()),
		Region:               os.Getenv("REGION"),
		WorkerConcurrency:    intEnv("MONITOR_WORKERS", 8),
		EgressCapPerMinute:   intEnv("MONITOR_EGRESS_CAP_PER_MINUTE", 200),
		SchedulerInterval:    durEnv("MONITOR_SCHEDULER_INTERVAL", 15*time.Second),
		WatchSetSyncInterval: durEnv("MONITOR_WATCHSET_SYNC_INTERVAL", time.Minute),
		CTEnabled:            getenv("MONITOR_CT_ENABLED", "true") == "true",
		CTBaseURL:            os.Getenv("MONITOR_CT_BASE_URL"),
		CTInterval:           durEnv("MONITOR_CT_INTERVAL", 5*time.Minute),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("config: DATABASE_URL is required")
	}
	return c, nil
}

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func intEnv(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func durEnv(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "mon-w-local"
	}
	return h
}
