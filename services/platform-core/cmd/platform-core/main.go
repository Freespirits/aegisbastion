// Command platform-core is the AegisBastion platform core (doc 01): Mission API
// (REST + gRPC), Task Orchestrator with embedded Scheduler and the dispatch
// PEP, Agent Registry, and the kill switch — one binary, subcommand-driven.
//
// Subcommands:
//
//	serve              run everything (Mission API + Orchestrator + Registry)
//	echo-planner       run the deterministic commander stub against a running core
//	verify-audit-chain recompute the platform audit hash chain and exit
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/reflection"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bootstrap"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/config"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/echoplanner"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/gatekeeper"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/leases"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/missionapi"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/orchestrator"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/pep"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/registry"
	"github.com/aegisbastion/aegisbastion/services/platform-core/internal/store"
)

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
		err = cmdServe(log)
	case "echo-planner":
		err = cmdEchoPlanner(log)
	case "verify-audit-chain":
		err = cmdVerifyAuditChain(log)
	default:
		err = fmt.Errorf("unknown subcommand %q (want serve | echo-planner | verify-audit-chain)", cmd)
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// wiring bundles the shared components.
type wiring struct {
	cfg *config.Config
	st  *store.Store
	gk  *gatekeeper.Client
	b   *bus.Bus
	al  *audit.Logger
	o   *orchestrator.Orchestrator
}

func wire(ctx context.Context, log *slog.Logger) (*wiring, error) {
	cfg, err := config.FromEnv()
	if err != nil {
		return nil, err
	}
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.DBSearchPath)
	if err != nil {
		return nil, err
	}
	if err := bootstrap.Ensure(ctx, st.Pool); err != nil {
		st.Close()
		return nil, err
	}
	al := audit.NewLogger(st.Pool, cfg.AuditSpillFile)
	if n, err := al.ReplaySpill(ctx); err != nil {
		log.Warn("audit spill replay incomplete (will retry next start)", "replayed", n, "err", err)
	} else if n > 0 {
		log.Info("audit spill replayed", "events", n)
	}

	// Gatekeeper (the PDP). The connection is lazy; the dispatch PEP is
	// fail-closed while it is unreachable (doc 01 §13).
	gk, err := gatekeeper.Dial(ctx, cfg.GatekeeperGRPCAddr, cfg.GatekeeperDialTimeout)
	if err != nil {
		st.Close()
		return nil, err
	}

	// Bus (JetStream). Retry briefly — compose starts NATS with the app.
	var b *bus.Bus
	deadline := time.Now().Add(60 * time.Second)
	for {
		b, err = bus.Connect(cfg.NATSUrl, "platform-core")
		if err == nil {
			break
		}
		if time.Now().After(deadline) {
			log.Error("NATS unavailable — starting degraded (outbox buffers, no dispatch publishes)", "err", err)
			b = nil
			break
		}
		log.Warn("NATS not ready, retrying", "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	p := pep.New(gk, gk, cfg.InstanceID)
	var leaseStore leases.Store
	if b != nil && b.Leases != nil {
		leaseStore = leases.NewKVStore(b.Leases)
	} else {
		log.Warn("lease KV unavailable — R2/R3 dispatches will defer (fail-safe)")
	}
	o := orchestrator.New(cfg, st, p, gk, leaseStore, b, al, log)
	return &wiring{cfg: cfg, st: st, gk: gk, b: b, al: al, o: o}, nil
}

func (w *wiring) close() {
	if w.b != nil {
		w.b.Close()
	}
	_ = w.gk.Close()
	w.st.Close()
}

func cmdServe(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	w, err := wire(ctx, log)
	if err != nil {
		return err
	}
	defer w.close()

	// Orchestrator loops (scheduler, reaper, outbox relay, bus consumers).
	orchCtx, orchStop := context.WithCancel(ctx)
	defer orchStop()
	go w.o.Run(orchCtx)

	// In-process echo planner (commander stub for testing).
	if w.cfg.EnableEchoPlanner {
		planner := orchestrator.NewPlannerService(w.o)
		stub := echoplanner.New(&echoplanner.LocalAdapter{Srv: planner},
			w.cfg.EchoPlannerCapability, w.cfg.EchoPlannerTargets,
			platformv1.RiskClass_RISK_CLASS_R0, log)
		go func() {
			// The stub subscribes per-mission on activation; at MVP-A it is
			// driven by missions activated after startup.
			log.Info("echo planner enabled", "capability", w.cfg.EchoPlannerCapability)
			<-orchCtx.Done()
			_ = stub
		}()
		// Register the stub against every future mission activation via the
		// mission-event broker by watching all missions it is pointed at.
		go runEchoPlanner(orchCtx, w, stub, log)
	}

	// gRPC server: MissionService + PlannerService + AgentService.
	grpcSrv := grpc.NewServer()
	platformv1.RegisterMissionServiceServer(grpcSrv,
		missionapi.New(w.cfg, w.st, w.o, w.gk, w.gk, w.al))
	platformv1.RegisterPlannerServiceServer(grpcSrv, orchestrator.NewPlannerService(w.o))
	platformv1.RegisterAgentServiceServer(grpcSrv, registry.New(w.st, w.o))
	reflection.Register(grpcSrv)

	grpcLis, err := net.Listen("tcp", fmt.Sprintf(":%d", w.cfg.GRPCPort))
	if err != nil {
		return fmt.Errorf("grpc listen: %w", err)
	}
	go func() {
		log.Info("gRPC serving", "port", w.cfg.GRPCPort)
		if err := grpcSrv.Serve(grpcLis); err != nil {
			log.Error("grpc serve", "err", err)
			stop()
		}
	}()

	// REST gateway + health.
	ready := func(ctx context.Context) (bool, map[string]string) {
		details := map[string]string{}
		ok := true
		if err := w.st.Pool.Ping(ctx); err != nil {
			details["postgres"] = "down: " + err.Error()
			ok = false
		} else {
			details["postgres"] = "up"
		}
		if w.b == nil || !w.b.NC.IsConnected() {
			details["nats"] = "down"
			ok = false
		} else {
			details["nats"] = "up"
		}
		// Informational only: gatekeeper outages fail the dispatch gate
		// closed, not the service (doc 01 §13).
		gctx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
		_, gerr := w.gk.GetROE(gctx, "healthcheck-nonexistent", 0)
		cancel()
		if gerr == nil {
			details["gatekeeper"] = "up"
		} else {
			details["gatekeeper"] = "reachable-check: " + gerr.Error()
		}
		return ok, details
	}
	rest := missionapi.NewRESTGateway(
		missionapi.New(w.cfg, w.st, w.o, w.gk, w.gk, w.al), ready)
	httpSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", w.cfg.RESTPort),
		Handler:           rest.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info("REST serving", "port", w.cfg.RESTPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("rest serve", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	grpcSrv.GracefulStop()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return nil
}

// runEchoPlanner subscribes to mission activations for missions it can see.
// Since the broker is per-mission, the stub subscribes lazily: it polls the
// DB for ACTIVE missions every few seconds and subscribes once per mission —
// activation events emitted after subscription drive plan submission. For
// the MVP stub this is sufficient (deterministic, test-only).
func runEchoPlanner(ctx context.Context, w *wiring, stub *echoplanner.Stub, log *slog.Logger) {
	seen := map[string]bool{}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		rows, err := w.st.Pool.Query(ctx,
			`SELECT mission_id FROM platform.missions
			 WHERE state IN ('DRAFT','ACTIVE','PAUSED','PLANNER_DEGRADED')`)
		if err != nil {
			continue
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		for _, id := range ids {
			if seen[id] {
				continue
			}
			seen[id] = true
			ch, unsub := w.o.SubscribeMissionEvents(id)
			mid := id
			go func() {
				defer unsub()
				for {
					select {
					case <-ctx.Done():
						return
					case ev, ok := <-ch:
						if !ok {
							return
						}
						stub.HandleMissionEvent(ctx, ev)
					}
				}
			}()
			log.Info("echo planner watching mission", "mission", mid)
		}
	}
}

// cmdEchoPlanner runs the commander stub as a separate process against a
// running platform-core (uses the real PlannerService gRPC contract).
func cmdEchoPlanner(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	addr := os.Getenv("PLATFORM_GRPC_ADDR")
	if addr == "" {
		addr = fmt.Sprintf("localhost:%d", cfg.GRPCPort)
	}
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return fmt.Errorf("dial platform-core %s: %w", addr, err)
	}
	defer conn.Close()
	client := platformv1.NewPlannerServiceClient(conn)
	stub := echoplanner.New(client, cfg.EchoPlannerCapability, cfg.EchoPlannerTargets,
		platformv1.RiskClass_RISK_CLASS_R0, log)

	missionID := os.Getenv("ECHO_PLANNER_MISSION_ID")
	if missionID == "" {
		return fmt.Errorf("ECHO_PLANNER_MISSION_ID is required in echo-planner mode")
	}
	stream, err := client.StreamMissionEvents(ctx, &platformv1.StreamMissionEventsRequest{
		Mission: &platformv1.MissionRef{MissionId: missionID},
	})
	if err != nil {
		return fmt.Errorf("stream mission events: %w", err)
	}
	log.Info("echo planner listening", "mission", missionID, "addr", addr)
	for {
		ev, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("event stream: %w", err)
		}
		stub.HandleMissionEvent(ctx, ev.GetEvent())
	}
}

// cmdVerifyAuditChain recomputes the hash chain (auditor/acceptance helper).
func cmdVerifyAuditChain(log *slog.Logger) error {
	ctx := context.Background()
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.DBSearchPath)
	if err != nil {
		return err
	}
	defer st.Close()
	al := audit.NewLogger(st.Pool, "")
	bad, err := al.VerifyChain(ctx)
	if err != nil {
		return err
	}
	if bad != 0 {
		return fmt.Errorf("audit chain INVALID — first failing seq %d", bad)
	}
	fmt.Println("audit chain valid")
	return nil
}
