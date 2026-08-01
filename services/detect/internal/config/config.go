// Package config loads the Detect module configuration from the environment.
// All knobs are env-driven (doc 01 §14: single Compose host, 12-factor style).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Scanner modes (doc 04 §5.3: fixture/mock is the default for tests; real
// binaries are wired via config).
const (
	ScannerModeFixture = "fixture"
	ScannerModeExec    = "exec"
)

// EVS runner kinds (doc 04 §7.1: gVisor at MVP where available, else the
// process-isolated local runner).
const (
	EVSRunnerAuto   = "auto"
	EVSRunnerLocal  = "local"
	EVSRunnerGVisor = "gvisor"
)

// Config is the resolved Detect configuration.
type Config struct {
	// DatabaseURL is the Postgres DSN (one DB "aegisbastion", schema-per-context).
	DatabaseURL string
	// DBSearchPath selects the schema (default "detect").
	DBSearchPath string

	// NATSUrl is the JetStream bus address.
	NATSUrl string

	// RegistryAddr is the platform-core AgentService gRPC address.
	RegistryAddr string
	// GatekeeperGRPCAddr is the gatekeeper.v1 gRPC endpoint (TokenService —
	// Ruling C9 token exchange + JWKS).
	GatekeeperGRPCAddr string
	// GatekeeperJWKSURL is the optional HTTP JWKS override (takes precedence
	// over the gRPC GetJWKS source).
	GatekeeperJWKSURL string

	// S3 object storage (MinIO at MVP-A) — token-manifests fetch + evidence.
	S3Endpoint  string
	S3AccessKey string
	S3SecretKey string
	S3UseTLS    bool
	S3Region    string

	// HTTPPort serves /healthz /readyz and the OOB admin surface.
	HTTPPort int

	// OOBAddr is the OOB interaction service listen address (doc 04 D7).
	OOBAddr string
	// OOBPublicBase is the base URL embedded into canary URLs
	// (e.g. "http://detect:8090" in compose).
	OOBPublicBase string

	// TenantID scopes fallback-store rows (MVP single-cohort; nil UUID default).
	TenantID string
	// OrgID populates AlertEvent v1 org_id (doc 05 §5.2; MVP single-cohort).
	OrgID string

	// FindingsFallback forces the local detect.findings_fallback store instead
	// of the data-platform Ingest API (doc 04 §13; compose sets "true" until
	// 09 ships).
	FindingsFallback bool
	// DPIngestURL is the data-platform Ingest API base (doc 09 §2.2).
	DPIngestURL string
	// DPIngestTimeout bounds one ingest batch call.
	DPIngestTimeout time.Duration

	// AlertTierThreshold is the minimum risk tier (P1..P5) mapped to
	// detect.alert (Ruling C8; default "P2"; CONFIRMED verdicts only).
	AlertTierThreshold string

	// ScannerMode selects fixture (default, tests) or exec (real binaries).
	ScannerMode string
	// NucleiBin / NmapBin are the scanner binary paths for exec mode.
	NucleiBin string
	NmapBin   string
	// FixtureDir holds the canned scanner outputs for fixture mode.
	FixtureDir string
	// WorkersPerAdapter is the in-process worker concurrency per adapter
	// (doc 04 §11: M concurrent jobs per worker, default 2).
	WorkersPerAdapter int

	// EVSEnabled toggles the Exploit-Verification Sandbox path (doc 04 §7.1).
	EVSEnabled bool
	// EVSRunner selects the sandbox runner (auto|local|gvisor).
	EVSRunner string
	// EVSImage is the detect image the gVisor runner launches (evs-run).
	EVSImage string
	// EVSPoCPublicKey is the hex Ed25519 public key verifying signed PoC packs
	// (doc 04 §7.1; empty = the embedded dev key, local-dev only).
	EVSPoCPublicKey string
	// EVSMaxConcurrent caps parallel sandbox verifications (doc 04 §11: 8).
	EVSMaxConcurrent int
	// EVSTimeout is the hard cap per verification (doc 04 §7.1: 10 min).
	EVSTimeout time.Duration

	// IntelEnabled turns on the EPSS/KEV mirror refresh cron (doc 04 §8).
	IntelEnabled bool
	// IntelEPSSURL / IntelKEVURL are the mirror sources (FIRST EPSS CSV,
	// CISA KEV JSON). Empty URLs keep the seeded mirror only.
	IntelEPSSURL string
	IntelKEVURL  string
	// IntelSeedFile loads an initial mirror snapshot (JSON) at startup.
	IntelSeedFile string
	// IntelRefreshInterval is the cron cadence (doc 04 §8: daily).
	IntelRefreshInterval time.Duration

	// AgentVersion is the semantic version reported at registration.
	AgentVersion string
	// MaxConcurrentTasks bounds parallel task executions (doc 04 §11: 4).
	MaxConcurrentTasks int

	// JobAckWait is the JetStream ack wait for detect.jobs.* consumers.
	JobAckWait time.Duration
	// ExchangeTimeout bounds one gatekeeper token-exchange call (Ruling C9).
	ExchangeTimeout time.Duration
	// ExchangeRetryInterval paces token-exchange retries while gatekeeper is
	// unreachable (jobs hold, fail-closed — doc 04 §12).
	ExchangeRetryInterval time.Duration
}

// FromEnv loads Config from the process environment.
func FromEnv() (*Config, error) {
	c := &Config{
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		DBSearchPath:       getenv("DB_SEARCH_PATH", "detect"),
		NATSUrl:            getenv("NATS_URL", "nats://localhost:4222"),
		RegistryAddr:       getenv("REGISTRY_ADDR", "localhost:50052"),
		GatekeeperGRPCAddr: getenv("GATEKEEPER_GRPC_ADDR", "localhost:50051"),
		GatekeeperJWKSURL:  os.Getenv("GATEKEEPER_JWKS_URL"),

		S3Endpoint:  getenv("S3_ENDPOINT", "localhost:9000"),
		S3AccessKey: os.Getenv("S3_ACCESS_KEY"),
		S3SecretKey: os.Getenv("S3_SECRET_KEY"),
		S3UseTLS:    getenvBool("S3_USE_TLS", false),
		S3Region:    getenv("S3_REGION", "us-east-1"),

		HTTPPort:      getenvInt("DETECT_HTTP_PORT", 8085),
		OOBAddr:       getenv("DETECT_OOB_ADDR", ":8090"),
		OOBPublicBase: getenv("DETECT_OOB_PUBLIC_BASE", "http://localhost:8090"),

		TenantID: getenv("DETECT_TENANT_ID", "00000000-0000-0000-0000-000000000000"),
		OrgID:    getenv("DETECT_ORG_ID", "org_aegisbastion"),

		FindingsFallback: getenvBool("DETECT_FINDINGS_FALLBACK", true),
		DPIngestURL:      getenv("DP_INGEST_URL", "http://localhost:8082"),
		DPIngestTimeout:  getenvDur("DETECT_DP_INGEST_TIMEOUT", 10*time.Second),

		AlertTierThreshold: getenv("DETECT_ALERT_TIER_THRESHOLD", "P2"),

		ScannerMode:       getenv("DETECT_SCANNER_MODE", ScannerModeFixture),
		NucleiBin:         getenv("DETECT_NUCLEI_BIN", "nuclei"),
		NmapBin:           getenv("DETECT_NMAP_BIN", "nmap"),
		FixtureDir:        getenv("DETECT_FIXTURE_DIR", "internal/scanner/testdata"),
		WorkersPerAdapter: getenvInt("DETECT_WORKERS_PER_ADAPTER", 2),

		EVSEnabled:       getenvBool("DETECT_EVS_ENABLED", true),
		EVSRunner:        getenv("DETECT_EVS_RUNNER", EVSRunnerAuto),
		EVSImage:         os.Getenv("DETECT_EVS_IMAGE"),
		EVSPoCPublicKey:  os.Getenv("DETECT_EVS_POC_PUBLIC_KEY"),
		EVSMaxConcurrent: getenvInt("DETECT_EVS_MAX_CONCURRENT", 8),
		EVSTimeout:       getenvDur("DETECT_EVS_TIMEOUT", 10*time.Minute),

		IntelEnabled:         getenvBool("DETECT_INTEL_ENABLED", false),
		IntelEPSSURL:         os.Getenv("DETECT_INTEL_EPSS_URL"),
		IntelKEVURL:          os.Getenv("DETECT_INTEL_KEV_URL"),
		IntelSeedFile:        os.Getenv("DETECT_INTEL_SEED_FILE"),
		IntelRefreshInterval: getenvDur("DETECT_INTEL_REFRESH_INTERVAL", 24*time.Hour),

		AgentVersion:       getenv("DETECT_AGENT_VERSION", "0.1.0"),
		MaxConcurrentTasks: getenvInt("DETECT_MAX_CONCURRENT_TASKS", 4),

		JobAckWait:            getenvDur("DETECT_JOB_ACK_WAIT", 5*time.Minute),
		ExchangeTimeout:       getenvDur("DETECT_EXCHANGE_TIMEOUT", 10*time.Second),
		ExchangeRetryInterval: getenvDur("DETECT_EXCHANGE_RETRY_INTERVAL", 5*time.Second),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	switch c.ScannerMode {
	case ScannerModeFixture, ScannerModeExec:
	default:
		return nil, fmt.Errorf("DETECT_SCANNER_MODE %q invalid (want fixture|exec)", c.ScannerMode)
	}
	switch c.EVSRunner {
	case EVSRunnerAuto, EVSRunnerLocal, EVSRunnerGVisor:
	default:
		return nil, fmt.Errorf("DETECT_EVS_RUNNER %q invalid (want auto|local|gvisor)", c.EVSRunner)
	}
	switch c.AlertTierThreshold {
	case "P1", "P2", "P3", "P4", "P5":
	default:
		return nil, fmt.Errorf("DETECT_ALERT_TIER_THRESHOLD %q invalid (want P1..P5)", c.AlertTierThreshold)
	}
	return c, nil
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

// SplitCSV splits a comma-separated env value (empty → nil).
func SplitCSV(v string) []string {
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
