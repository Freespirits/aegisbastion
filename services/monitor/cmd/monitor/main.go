// Command monitor is the AegisBastion Monitor module (doc 03): 24/7 continuous
// monitoring — change detection, snapshot diffing, config drift, new-asset
// and exposure detection, event streaming. One binary hosts M1–M7 (doc 03
// §3.1): the Coordinator (agentsdk.Module for monitor.watch/monitor.rescan/
// monitor.baseline.set/monitor.feed.sync), the embedded scheduler, the probe
// worker pool (dns/tls/http with per-job scope-bound token verification),
// the diff + rules engines, the event streamer (monitor.changes /
// monitor.alert / monitor.assets.new), and the CT feed poller.
//
// Subcommands:
//
//	serve    run everything (agent runtime + workers + mgmt API)
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	agentsdk "github.com/aegisbastion/aegisbastion/sdks/go"
	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
	sdkbus "github.com/aegisbastion/aegisbastion/sdks/go/bus"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/pep"
	"github.com/aegisbastion/aegisbastion/sdks/go/registry"
	"github.com/aegisbastion/aegisbastion/sdks/go/token"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/config"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/coordinator"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/ctlog"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/executor"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/jobs"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/mgmt"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/probes"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/rawstore"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/store"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/streamer"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/worker"
)

// ctAdvisoryLockKey elects the single M7 poller replica (doc 03 §3.1).
const ctAdvisoryLockKey int64 = 0x4D4F4E49544F52 // "MONITOR"

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(log)

	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve(log)
	default:
		err = errors.New("unknown subcommand " + cmd + " (want serve)")
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// busPublisher adapts the SDK bus client to streamer.Publisher.
type busPublisher struct{ c *sdkbus.Client }

func (b busPublisher) PublishRaw(ctx context.Context, subject, msgID string, data []byte) error {
	msg := nats.NewMsg(subject)
	msg.Header.Set(nats.MsgIdHdr, msgID)
	msg.Data = data
	return b.c.PublishMsg(ctx, msg)
}

func serve(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	// Postgres (monitor schema) + service-local DDL.
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.DBSearchPath)
	if err != nil {
		return err
	}
	defer st.Close()
	if err := st.Bootstrap(ctx); err != nil {
		return err
	}

	// Bus (module-side connection: scan jobs, streamer relay, audit,
	// revocations — the agent runtime keeps its own).
	bc, err := sdkbus.Connect(cfg.NATSURL)
	if err != nil {
		return err
	}
	defer bc.Close()

	// Gatekeeper gRPC (TokenService: JWKS + RefreshToken; planner dials
	// platform-core separately).
	dialOpts := []grpc.DialOption{registry.InsecureDialOption()}
	gkConn, err := grpc.NewClient(cfg.GatekeeperAddr, dialOpts...)
	if err != nil {
		return err
	}
	defer gkConn.Close()
	tokens := gatekeeperv1.NewTokenServiceClient(gkConn)

	var keySrc token.KeySource = token.NewGRPCKeysSource(tokens)
	if cfg.JWKSURL != "" {
		keySrc = token.NewHTTPKeySource(cfg.JWKSURL, nil)
	}
	verifier := token.NewVerifier(token.NewKeyCache(keySrc))

	// Manifests (token-manifests) + raw bodies (monitor-raw).
	s3cfg := manifest.S3Config{
		Endpoint: cfg.S3Endpoint, AccessKeyID: cfg.S3AccessKey,
		SecretAccessKey: cfg.S3SecretKey, UseTLS: cfg.S3UseTLS,
	}
	fetcher := manifest.NewS3Fetcher(s3cfg)
	rawUp := rawstore.NewS3(rawstore.Config{
		Endpoint: cfg.S3Endpoint, AccessKeyID: cfg.S3AccessKey,
		SecretAccessKey: cfg.S3SecretKey, UseTLS: cfg.S3UseTLS,
		Bucket: cfg.RawBucket,
	})

	// Audit sink (audit.events; never sampled).
	auditEmitter := audit.EmitterFunc(func(ctx context.Context, evt *platformv1.AuditEvent) error {
		_, err := bc.Publish(ctx, audit.Subject, evt, sdkbus.PublishOptions{
			MissionID: evt.GetSubject().GetMissionId(),
			EventID:   evt.GetEventId(),
		})
		return err
	})

	// Revocation cache for the worker pool (≤ 5 s halt, doc 11 §7).
	revocations := pep.NewRevocationCache()
	revSub, err := bc.Consume(sdkbus.StreamGatekeeper, sdkbus.SubjectRevocations,
		"monitor-revocations-"+cfg.WorkerID, time.Minute,
		func(_ context.Context, env *platformv1.Envelope, _ *sdkbus.MessageControl) sdkbus.Disposition {
			msg, err := sdkbus.UnpackPayload(env)
			if err != nil {
				return sdkbus.Ack
			}
			if evt, ok := msg.(*gatekeeperv1.RevocationEvent); ok {
				revocations.ApplyEvent(evt)
			}
			return sdkbus.Ack
		})
	if err != nil {
		return err
	}
	defer revSub.Unsubscribe()

	// M6 streamer + outbox relay.
	sm := streamer.New(st, streamer.Config{}, nil)
	go sm.RunRelay(ctx, busPublisher{bc}, time.Second)

	// M3 probe executors (production: network; tests inject fixtures).
	probeSet := []probes.Probe{
		&probes.DNSProbe{Resolvers: []string{"1.1.1.1:53", "8.8.8.8:53", "9.9.9.9:53"}},
		&probes.TLSProbe{},
		&probes.HTTPProbe{},
	}

	// M3+M4+M5 executor.
	exec := executor.New(executor.Config{WorkerID: cfg.WorkerID, Region: cfg.Region},
		st, probeSet, rawUp, sm)

	// M1 coordinator (module + sinks).
	feeds := ctlog.NewFeedRegistry()
	coord := coordinator.New(coordinator.Config{
		AgentID:              "", // set post-registration below
		WorkerID:             cfg.WorkerID,
		Region:               cfg.Region,
		SchedulerInterval:    cfg.SchedulerInterval,
		WatchSetSyncInterval: cfg.WatchSetSyncInterval,
		Logger:               log,
	}, coordinator.Deps{
		Store: st, Streamer: sm, Jobs: jobs.NewPublisher(bc.JetStream()),
		Executor: exec, Feeds: feeds, Tokens: tokens,
		Verifier: verifier, Fetcher: fetcher, Emitter: auditEmitter,
	})
	sm.SetAuditSink(coord)

	// M3 worker pool (per-job token verification, doc 03 §9.2).
	w := worker.New(worker.Config{
		AgentID: cfg.WorkerID, Verifier: verifier, Fetcher: fetcher,
		Revocations: revocations, Emitter: auditEmitter,
		Executor: exec, Store: st,
		EgressCapPerMinute: cfg.EgressCapPerMinute, Logger: log,
	}, coord)
	sem := make(chan struct{}, cfg.WorkerConcurrency)
	jobSub, err := jobs.Consume(bc.JetStream(), func(hctx context.Context, j *jobs.Job, deliveries int) jobs.Disposition {
		sem <- struct{}{} // backpressure at pool capacity
		defer func() { <-sem }()
		return w.Handle(hctx, j, deliveries)
	})
	if err != nil {
		return err
	}
	defer jobSub.Unsubscribe()

	// M7 CT poller (passive R0; leader-elected via PG advisory lock).
	if cfg.CTEnabled {
		poller := ctlog.NewPoller(&ctlog.CRTSh{BaseURL: cfg.CTBaseURL}, st, feeds, coord)
		poller.Interval = cfg.CTInterval
		poller.TryLock = func(lctx context.Context) (func(), bool, error) {
			tx, ok, err := st.TryAdvisoryLock(lctx, ctAdvisoryLockKey)
			if !ok || err != nil {
				return func() {}, ok, err
			}
			return func() { _ = tx.Rollback(context.Background()) }, true, nil
		}
		go func() {
			if err := poller.Run(ctx); err != nil && ctx.Err() == nil {
				log.Error("ct poller exited", "err", err)
			}
		}()
	}

	// Agent runtime (doc 01 §9.1): registration, heartbeats, transport,
	// guardrails, re-auth, kill handling.
	agent, err := agentsdk.New(agentsdk.Config{
		Manifest: &platformv1.AgentManifest{
			AgentType: platformv1.AgentType_AGENT_TYPE_MONITOR,
			Version:   "0.1.0",
			Capabilities: []*platformv1.Capability{
				{Name: coordinator.CapWatch, RiskClassMax: platformv1.RiskClass_RISK_CLASS_R1, SchemaVersion: "v1"},
				{Name: coordinator.CapRescan, RiskClassMax: platformv1.RiskClass_RISK_CLASS_R1, SchemaVersion: "v1"},
				{Name: coordinator.CapBaselineSet, RiskClassMax: platformv1.RiskClass_RISK_CLASS_R0, SchemaVersion: "v1"},
				{Name: coordinator.CapFeedSync, RiskClassMax: platformv1.RiskClass_RISK_CLASS_R0, SchemaVersion: "v1"},
			},
			Limits: &platformv1.AgentLimits{MaxConcurrentTasks: 8},
		},
		NATSURL:        cfg.NATSURL,
		RegistryAddr:   cfg.RegistryAddr,
		GatekeeperAddr: cfg.GatekeeperAddr,
		DialOptions:    dialOpts,
		JWKSURL:        cfg.JWKSURL,
		S3:             s3cfg,
		Logger:         log,
	}, coord)
	if err != nil {
		return err
	}
	defer agent.Close()

	// Planner client (mgmt rescan routed through the Orchestrator).
	plannerConn, err := grpc.NewClient(cfg.RegistryAddr, dialOpts...)
	if err != nil {
		return err
	}
	defer plannerConn.Close()

	// Mgmt API + health (doc 03 §13).
	httpSrv := &http.Server{
		Addr: ":" + itoa(cfg.HTTPPort),
		Handler: mgmt.Handler(mgmt.Deps{
			Store: st, Coordinator: coord, Streamer: sm,
			Planner: platformv1.NewPlannerServiceClient(plannerConn),
			Ready: func(rctx context.Context) (bool, map[string]string) {
				details := map[string]string{}
				ok := true
				if err := st.Ping(rctx); err != nil {
					details["postgres"] = "down: " + err.Error()
					ok = false
				} else {
					details["postgres"] = "up"
				}
				if !bc.Conn().IsConnected() {
					details["nats"] = "down"
					ok = false
				} else {
					details["nats"] = "up"
				}
				return ok, details
			},
			AuditHook: func(rctx context.Context, action string, detail map[string]any) {
				evt, err := audit.NewEvent(platformv1.AuditEventType_AUDIT_EVENT_TYPE_UNSPECIFIED,
					audit.Ident{AgentID: cfg.WorkerID}, mergeKind(action, detail))
				if err == nil {
					_ = auditEmitter.Emit(rctx, evt)
				}
			},
		}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info("mgmt API serving", "port", cfg.HTTPPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http serve", "err", err)
			stop()
		}
	}()

	log.Info("monitor serving",
		"worker_id", cfg.WorkerID, "http", cfg.HTTPPort, "ct_poller", cfg.CTEnabled)

	// Run the agent (blocks until ctx done).
	agentErr := make(chan error, 1)
	go func() { agentErr <- agent.Run(ctx) }()

	select {
	case <-ctx.Done():
	case err := <-agentErr:
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return nil
}

func mergeKind(action string, detail map[string]any) map[string]any {
	out := map[string]any{"kind": action}
	for k, v := range detail {
		out[k] = v
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "8084"
	}
	return strconv.Itoa(n)
}
