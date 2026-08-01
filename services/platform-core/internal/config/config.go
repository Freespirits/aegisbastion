// Package config loads platform-core configuration from the environment.
// All knobs are env-driven (doc 01 §14: single Compose host, 12-factor style).
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config is the resolved platform-core configuration.
type Config struct {
	// DatabaseURL is the Postgres DSN (one DB "aegisbastion", schema-per-context).
	DatabaseURL string
	// DBSearchPath selects the schema (default "platform", doc 01 §11).
	DBSearchPath string

	// NATSUrl is the JetStream bus address.
	NATSUrl string

	// GatekeeperGRPCAddr is the gatekeeper.v1 gRPC endpoint (the single PDP,
	// doc 11; the dispatch PEP calls it fail-closed, Ruling B).
	GatekeeperGRPCAddr string
	// GatekeeperDialTimeout bounds each PEP call attempt.
	GatekeeperDialTimeout time.Duration

	// GRPCPort serves MissionService + PlannerService + AgentService.
	GRPCPort int
	// RESTPort serves the Mission API REST gateway + health endpoints.
	RESTPort int

	// Operators is the MVP operator RBAC shim: identities allowed to call
	// mutating Mission API endpoints (empty = dev mode, allow all). Real RBAC
	// is gatekeeper rbac-service (doc 11); wired in a later wave.
	Operators []string

	// SchedulerTick is the dispatch-loop interval.
	SchedulerTick time.Duration
	// ReaperTick is the stale-dispatch/deadline sweep interval.
	ReaperTick time.Duration
	// AckTimeout is how long a DISPATCHED task may go un-ACKed before
	// redelivery (doc 01 §9 item 3: 10 s).
	AckTimeout time.Duration
	// AgentHeartbeatTTL is the registry presence TTL (doc 01 §8.1: 30 s).
	AgentHeartbeatTTL time.Duration
	// QueueTTL is how long a task may sit QUEUED before EXPIRED.
	QueueTTL time.Duration
	// CommanderQuota is the per-commander in-flight task budget (doc 01 §4.2
	// rule 4: default 50).
	CommanderQuota int
	// DefaultMaxConcurrentIntrusive is the per-RoE intrusive concurrency cap
	// used when the RoE declares none (doc 01 §5.4 example: 4).
	DefaultMaxConcurrentIntrusive int
	// DefaultR1MaxRPS is the default rate cap for R1 work (doc 01 §5.3: 100
	// rps/target).
	DefaultR1MaxRPS int

	// AuditSpillFile is the last-resort local spill for audit events when the
	// DB write fails on the dispatch critical path (doc 01 §13: fsync before
	// dispatch). Empty disables spilling (dispatch then blocks).
	AuditSpillFile string

	// ArtifactBucket is the MinIO bucket for task evidence (doc 01 §5.6).
	ArtifactBucket string

	// EnableEchoPlanner runs the deterministic in-process commander stub.
	EnableEchoPlanner bool
	// EchoPlannerCapability is the capability the echo planner requests
	// (must be registered for its plans to pass validation).
	EchoPlannerCapability string
	// EchoPlannerTargets are the echo planner's plan targets (must be inside
	// the mission RoE scope to pass validation).
	EchoPlannerTargets []string

	// InstanceID identifies this orchestrator instance in audit actors.
	InstanceID string
}

// FromEnv loads Config from the process environment.
func FromEnv() (*Config, error) {
	c := &Config{
		DatabaseURL:        os.Getenv("DATABASE_URL"),
		DBSearchPath:       getenv("DB_SEARCH_PATH", "platform"),
		NATSUrl:            getenv("NATS_URL", "nats://localhost:4222"),
		GatekeeperGRPCAddr: getenv("GATEKEEPER_GRPC_ADDR", "localhost:50051"),
		GRPCPort:           getenvInt("PLATFORM_GRPC_PORT", 50052),
		RESTPort:           getenvInt("PLATFORM_REST_PORT", 8081),
		Operators:          splitCSV(os.Getenv("PLATFORM_OPERATORS")),

		SchedulerTick:     getenvDur("PLATFORM_SCHEDULER_TICK", 500*time.Millisecond),
		ReaperTick:        getenvDur("PLATFORM_REAPER_TICK", 5*time.Second),
		AckTimeout:        getenvDur("PLATFORM_ACK_TIMEOUT", 10*time.Second),
		AgentHeartbeatTTL: getenvDur("PLATFORM_AGENT_HEARTBEAT_TTL", 30*time.Second),
		QueueTTL:          getenvDur("PLATFORM_QUEUE_TTL", 24*time.Hour),

		CommanderQuota:                getenvInt("PLATFORM_COMMANDER_QUOTA", 50),
		DefaultMaxConcurrentIntrusive: getenvInt("PLATFORM_DEFAULT_MAX_CONCURRENT_INTRUSIVE", 4),
		DefaultR1MaxRPS:               getenvInt("PLATFORM_DEFAULT_R1_MAX_RPS", 100),
		GatekeeperDialTimeout:         getenvDur("PLATFORM_GATEKEEPER_TIMEOUT", 5*time.Second),

		AuditSpillFile: os.Getenv("PLATFORM_AUDIT_SPILL_FILE"),
		ArtifactBucket: getenv("PLATFORM_ARTIFACT_BUCKET", "artifacts"),

		EnableEchoPlanner:     getenvBool("ENABLE_ECHO_PLANNER", false),
		EchoPlannerCapability: getenv("ECHO_PLANNER_CAPABILITY", "monitor.feed.sync"),
		EchoPlannerTargets:    splitCSV(getenv("ECHO_PLANNER_TARGETS", "localhost")),

		InstanceID: getenv("PLATFORM_INSTANCE_ID", ""),
	}
	if c.DatabaseURL == "" {
		return nil, fmt.Errorf("DATABASE_URL is required")
	}
	if c.InstanceID == "" {
		host, _ := os.Hostname()
		if host == "" {
			host = "unknown"
		}
		c.InstanceID = "platform-core-" + host
	}
	return c, nil
}

// OperatorAllowed reports whether identity may call mutating Mission API
// endpoints under the MVP RBAC shim.
func (c *Config) OperatorAllowed(identity string) bool {
	if len(c.Operators) == 0 {
		return true
	}
	for _, op := range c.Operators {
		if op == identity {
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
