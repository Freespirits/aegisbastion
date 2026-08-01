// cai is the CAI commander adapter (doc 01 §4.1, §7.1) — a
// bring-your-own-license (BYO) integration. The default planner is a
// built-in, clearly-marked STUB: it accepts mission intents over REST,
// answers with a fixed deterministic Discover-passive plan, and submits it
// to the Orchestrator — so the end-to-end mission → plan → verdict flow runs
// with no CAI installation at all.
//
// LICENSING: CAI (Alias Robotics S.L.) is research-use
// only. Commercial/production use against a real CAI backend requires the
// operator to hold a valid Alias Robotics commercial license; that backend
// plugs in behind the app.Planner interface. AegisBastion vendors no CAI
// code.
//
// All configuration is env-driven:
//
//	PLANNER_ADDR     Orchestrator PlannerService gRPC host:port (default 127.0.0.1:50052)
//	CAI_MODE         planner mode; only "stub" (default demo planner) exists — anything else fails fast
//	CAI_LISTEN_ADDR  REST listen address (default :8082)
//
// Endpoints: POST /v1/intents, POST /v1/plans, GET /v1/missions/{id},
// GET /v1/capabilities, GET /healthz, GET /readyz.
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegisbastion/aegisbastion/adapters/cai/app"
	"github.com/aegisbastion/aegisbastion/adapters/internal/config"
	"github.com/aegisbastion/aegisbastion/adapters/internal/health"
	"github.com/aegisbastion/aegisbastion/adapters/internal/plannerclient"
)

const serviceName = "aegisbastion-cai-adapter"

func main() {
	log.SetPrefix("[cai] ")
	if err := run(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		plannerAddr = config.Getenv("PLANNER_ADDR", "127.0.0.1:50052")
		listenAddr  = config.Getenv("CAI_LISTEN_ADDR", ":8082")
		mode        = config.Getenv("CAI_MODE", "stub")
	)

	planner, err := app.NewPlanner(mode)
	if err != nil {
		return err
	}
	log.Printf("planner mode=%s (stub plans are clearly marked; real CAI integration drops in behind app.Planner)", mode)

	pc, err := plannerclient.Dial(plannerAddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	log.Printf("planner service at %s", plannerAddr)

	srv := app.NewServer(planner, pc.API)
	srv.Mount("/", health.Handler(serviceName, func(ctx context.Context) error {
		return plannerclient.Ready(ctx, pc.API)
	}))

	httpSrv := &http.Server{Handler: srv.Handler(), ReadHeaderTimeout: 5 * time.Second}
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	log.Printf("REST endpoints on %s (/v1/intents, /v1/plans, /v1/missions/{id}, /v1/capabilities, /healthz, /readyz)", ln.Addr())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- httpSrv.Serve(ln) }()

	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
		log.Printf("shutdown signal received")
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutCtx)
	}
}
