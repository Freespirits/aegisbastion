// Package agentsdk is the platform Go agent SDK (doc 01 §9.1) merged with
// gatekeeper's pep-sdk (Ruling B.2 PEP-2 — one library, two names). It wraps:
// registration, heartbeats, bus/gRPC transport, Scope Token verification
// (cached JWKS), per-request target checking (manifest membership, or
// canonicalized scope evaluation with exclusions-first for scope-bound watch
// tokens), rate limiting, the revocation cache, kill-switch handling,
// mid-run re-authorization, manifest fetch/verify, and audit emission.
//
// Module teams implement one interface — Module{Plan, Run, Abort} (doc 01
// §9.1); contract items 3–8 of doc 01 §9 are library calls.
package agentsdk

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
	"github.com/aegisbastion/aegisbastion/sdks/go/bus"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/pep"
	"github.com/aegisbastion/aegisbastion/sdks/go/registry"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"
)

// Config wires an Agent. Zero-value durations pick the doc-mandated
// defaults (10 s heartbeats, re-authorization at 60% of token TTL).
type Config struct {
	// Manifest — registration record (doc 01 §5.8). AgentId empty on first
	// registration; the assigned id is written back into the manifest.
	Manifest *platformv1.AgentManifest

	// NATSURL — the bus (e.g. "nats://localhost:4222").
	NATSURL string
	// NATSOptions — extra nats options (auth, TLS).
	NATSOptions []nats.Option

	// RegistryAddr — AgentService gRPC address (e.g. "localhost:50052").
	RegistryAddr string
	// GatekeeperAddr — gatekeeper gRPC address (TokenService: JWKS +
	// RefreshToken mid-run re-authorization).
	GatekeeperAddr string
	// DialOptions — gRPC transport credentials for registry + gatekeeper.
	// Pass mTLS credentials in deployments; registry.InsecureDialOption()
	// for local Docker-Compose dev.
	DialOptions []grpc.DialOption
	// JWKSURL — optional HTTP JWKS endpoint override (takes precedence over
	// the gRPC GetJWKS source).
	JWKSURL string

	// S3 — MinIO manifest fetch (token-manifests bucket).
	S3 manifest.S3Config

	// UseStreamTasks selects the gRPC long-poll transport instead of bus
	// subscription (doc 01 §8.3 — same TaskAssignment payload either way).
	UseStreamTasks bool

	// AuditSubject — override for the audit sink (default "audit.events").
	AuditSubject string

	// HeartbeatInterval — default 10 s (doc 01 §8.1; Registry TTL 30 s).
	HeartbeatInterval time.Duration
	// RefreshFraction — fraction of token TTL after which mid-run
	// re-authorization fires; default 0.6 (doc 01 §5.5, doc 11 §3.2).
	RefreshFraction float64
	// AckWait — JetStream ack wait for task.assign consumption
	// (default 5 min; the runtime pings InProgress while tasks run).
	AckWait time.Duration
	// Logger — structured logging (default slog.Default()).
	Logger *slog.Logger
}

// Agent is the platform agent runtime (doc 01 §9.1). Build with New, run
// with Run.
type Agent struct {
	cfg Config
	mod Module
	log *slog.Logger

	bus         *bus.Client
	reg         *registry.Client
	tokens      gatekeeperv1.TokenServiceClient
	gkConn      *grpc.ClientConn
	verifier    *token.Verifier
	fetcher     manifest.Fetcher
	emitter     audit.Emitter
	revocations *pep.RevocationCache

	mu      sync.Mutex
	running map[string]*runningTask
	killed  bool // kill engaged — reject new assignments
}

// New builds the Agent: connects the bus, dials registry + gatekeeper, and
// prepares the PEP machinery. Registration happens in Run.
func New(cfg Config, mod Module) (*Agent, error) {
	if cfg.Manifest == nil {
		return nil, errors.New("agentsdk: Config.Manifest is required")
	}
	if mod == nil {
		return nil, errors.New("agentsdk: a Module implementation is required")
	}
	if cfg.NATSURL == "" {
		return nil, errors.New("agentsdk: Config.NATSURL is required")
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = registry.HeartbeatInterval
	}
	if cfg.RefreshFraction <= 0 || cfg.RefreshFraction >= 1 {
		cfg.RefreshFraction = 0.6
	}
	if cfg.AckWait <= 0 {
		cfg.AckWait = 5 * time.Minute
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	if len(cfg.DialOptions) == 0 {
		return nil, errors.New("agentsdk: Config.DialOptions is required (mTLS creds, or registry.InsecureDialOption() for local dev)")
	}

	bc, err := bus.Connect(cfg.NATSURL, cfg.NATSOptions...)
	if err != nil {
		return nil, err
	}
	reg, err := registry.Dial(cfg.RegistryAddr, cfg.DialOptions...)
	if err != nil {
		bc.Close()
		return nil, err
	}
	gkConn, err := grpc.NewClient(cfg.GatekeeperAddr, cfg.DialOptions...)
	if err != nil {
		bc.Close()
		_ = reg.Close()
		return nil, fmt.Errorf("agentsdk: dial gatekeeper %s: %w", cfg.GatekeeperAddr, err)
	}
	tokens := gatekeeperv1.NewTokenServiceClient(gkConn)

	var src token.KeySource = token.NewGRPCKeysSource(tokens)
	if cfg.JWKSURL != "" {
		src = token.NewHTTPKeySource(cfg.JWKSURL, nil)
	}

	subject := cfg.AuditSubject
	if subject == "" {
		subject = audit.Subject
	}
	a := &Agent{
		cfg:         cfg,
		mod:         mod,
		log:         log,
		bus:         bc,
		reg:         reg,
		tokens:      tokens,
		gkConn:      gkConn,
		verifier:    token.NewVerifier(token.NewKeyCache(src)),
		fetcher:     manifest.NewS3Fetcher(cfg.S3),
		revocations: pep.NewRevocationCache(),
		running:     map[string]*runningTask{},
	}
	a.emitter = audit.EmitterFunc(func(ctx context.Context, evt *platformv1.AuditEvent) error {
		_, err := bc.Publish(ctx, subject, evt, bus.PublishOptions{
			MissionID: evt.GetSubject().GetMissionId(),
			EventID:   evt.GetEventId(),
		})
		return err
	})
	return a, nil
}

// AgentID returns the registered agent id (valid after Run registers).
func (a *Agent) AgentID() string { return a.reg.AgentID() }

// Close releases all connections.
func (a *Agent) Close() {
	a.bus.Close()
	_ = a.reg.Close()
	_ = a.gkConn.Close()
}

// Run registers the agent, starts heartbeats, the revocation/kill watchers,
// and the assignment transport, then blocks until ctx is done.
//
// Fail-safe posture (doc 01 §13): bus/registry/gatekeeper outages stop NEW
// target contact (in-flight tasks run to their token expiry, ≤ 15 min);
// revocation or kill halts target contact ≤ 5 s.
func (a *Agent) Run(ctx context.Context) error {
	if err := a.registerWithRetry(ctx); err != nil {
		return err
	}
	a.log.Info("agent registered", "agent_id", a.AgentID())

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Revocation watcher (tasks.revocations.v1, durable) → cache + ≤ 5 s halt.
	revSub, err := a.bus.Consume(bus.StreamGatekeeper, bus.SubjectRevocations,
		"sdk-revocations-"+a.AgentID(), time.Minute,
		func(_ context.Context, env *platformv1.Envelope, _ *bus.MessageControl) bus.Disposition {
			msg, err := bus.UnpackPayload(env)
			if err != nil {
				a.log.Warn("revocation envelope without decodable payload", "error", err)
				return bus.Ack
			}
			evt, ok := msg.(*gatekeeperv1.RevocationEvent)
			if !ok {
				return bus.Ack
			}
			a.revocations.ApplyEvent(evt)
			a.haltMatching("revocation " + evt.GetRevocation().GetRevocationId())
			return bus.Ack
		})
	if err != nil {
		return fmt.Errorf("agentsdk: subscribe %s: %w", bus.SubjectRevocations, err)
	}
	defer revSub.Unsubscribe()

	// Kill-switch watcher (control.kill — core NATS broadcast, no stream).
	killSub, err := a.bus.SubscribeCore(bus.SubjectControlKill,
		func(_ context.Context, env *platformv1.Envelope, _ *bus.MessageControl) bus.Disposition {
			if kill, reason := pep.KillDecision(env, ""); kill {
				a.log.Warn("kill switch engaged", "reason", reason)
				a.haltMatching("kill: " + reason)
			}
			a.mu.Lock()
			for _, rt := range a.running {
				if kill, reason := pep.KillDecision(env, rt.mission); kill {
					a.log.Warn("mission kill engaged", "task_id", rt.taskID, "reason", reason)
					a.haltTask(rt, "mission kill: "+reason)
				}
			}
			a.mu.Unlock()
			return bus.Ack
		})
	if err != nil {
		return fmt.Errorf("agentsdk: subscribe %s: %w", bus.SubjectControlKill, err)
	}
	defer killSub.Unsubscribe()

	// Heartbeat loop (kill_active is the per-agent kill backstop).
	go a.heartbeatLoop(ctx)

	// Assignment transport (bus by default; StreamTasks long-poll on request —
	// same TaskAssignment payload either way, doc 01 §8.3).
	if a.cfg.UseStreamTasks {
		return a.reg.StreamTasks(ctx, func(hctx context.Context, as *platformv1.TaskAssignment) error {
			a.dispatch(hctx, as, nil)
			return nil
		})
	}
	sub, err := a.bus.Consume(bus.StreamTaskAssign, bus.SubjectTaskAssign(a.AgentID()),
		"sdk-assign-"+a.AgentID(), a.cfg.AckWait,
		func(hctx context.Context, env *platformv1.Envelope, ctl *bus.MessageControl) bus.Disposition {
			msg, err := bus.UnpackPayload(env)
			if err != nil {
				a.log.Warn("assignment envelope without decodable payload", "error", err)
				return bus.Term
			}
			as, ok := msg.(*platformv1.TaskAssignment)
			if !ok {
				a.log.Warn("unexpected payload on task.assign", "type", env.GetType())
				return bus.Term
			}
			return a.dispatch(hctx, as, ctl)
		})
	if err != nil {
		return fmt.Errorf("agentsdk: subscribe %s: %w", bus.SubjectTaskAssign(a.AgentID()), err)
	}
	defer sub.Unsubscribe()

	<-ctx.Done()
	return ctx.Err()
}

func (a *Agent) registerWithRetry(ctx context.Context) error {
	backoff := time.Second
	for {
		_, err := a.reg.Register(ctx, a.cfg.Manifest)
		if err == nil {
			a.cfg.Manifest.AgentId = a.reg.AgentID()
			return nil
		}
		a.log.Warn("registration failed, retrying", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	t := time.NewTicker(a.cfg.HeartbeatInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		a.mu.Lock()
		ids := make([]string, 0, len(a.running))
		for id := range a.running {
			ids = append(ids, id)
		}
		a.mu.Unlock()
		hctx, cancel := context.WithTimeout(ctx, a.cfg.HeartbeatInterval/2)
		kill, err := a.reg.Heartbeat(hctx, ids)
		cancel()
		if err != nil {
			a.log.Warn("heartbeat failed", "error", err)
			continue
		}
		if kill {
			a.log.Warn("kill_active in heartbeat response — halting")
			a.haltMatching("heartbeat kill_active")
		}
	}
}

// dispatch handles one assignment: ACK ≤ 10 s (doc 01 §9 item 3), then
// execute in a goroutine so the transport keeps flowing.
func (a *Agent) dispatch(ctx context.Context, as *platformv1.TaskAssignment, ctl *bus.MessageControl) bus.Disposition {
	log := a.log.With("task_id", as.GetTaskId(), "capability", as.GetCapability())

	a.mu.Lock()
	killed := a.killed
	a.mu.Unlock()
	if killed {
		log.Warn("agent halted by kill switch — nacking assignment")
		return bus.Nak // redeliver after the kill clears
	}

	ackCtx, ackCancel := context.WithTimeout(ctx, 10*time.Second)
	err := a.reg.AckTask(ackCtx, as.GetTaskId())
	ackCancel()
	if err != nil {
		log.Error("AckTask failed — nacking for redelivery", "error", err)
		return bus.Nak
	}
	if ctl != nil {
		_ = ctl.InProgress()
	}

	go a.execute(ctx, as, ctl, log)
	return bus.Ack
}
