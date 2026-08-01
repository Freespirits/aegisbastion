// strix is the Strix commander adapter (doc 01 §4.1, §7.1): an MCP server
// (stdio) that fronts the local Strix installation as an AegisBastion
// platform commander. It submits TaskPlans to the Orchestrator's
// PlannerService, streams verdicts back, and translates only
// Orchestrator-accepted tasks into Strix scans.
//
// All configuration is env-driven:
//
//	PLANNER_ADDR    Orchestrator PlannerService gRPC host:port (default 127.0.0.1:50052)
//	STRIX_MODE      mock | live (default mock — runs with no Strix install)
//	STRIX_BIN       strix CLI executable in live mode (default "strix")
//	STRIX_WORK_DIR  parent dir for per-scan working dirs in live mode (default "strix_work")
//	HEALTH_ADDR     health endpoint listen address (default :8087)
//
// stdout is reserved for the MCP protocol; logs go to stderr.
package main

import (
	"context"
	"errors"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/mcp"
	"github.com/aegisbastion/aegisbastion/adapters/internal/config"
	"github.com/aegisbastion/aegisbastion/adapters/internal/health"
	"github.com/aegisbastion/aegisbastion/adapters/internal/plannerclient"
	"github.com/aegisbastion/aegisbastion/adapters/strix/app"
	"github.com/aegisbastion/aegisbastion/adapters/strix/strixcli"
)

const (
	serverName    = "aegisbastion-strix-adapter"
	serverVersion = "0.1.0"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("[strix] ")
	if err := run(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		plannerAddr = config.Getenv("PLANNER_ADDR", "127.0.0.1:50052")
		healthAddr  = config.Getenv("HEALTH_ADDR", ":8087")
		strixBin    = config.Getenv("STRIX_BIN", "strix")
		strixWork   = config.Getenv("STRIX_WORK_DIR", "strix_work")
	)
	mode, err := config.RequireMode("STRIX_MODE", "mock", "mock", "live")
	if err != nil {
		return err
	}

	// Strix client: mock is the default so the adapter always runs; live
	// shells out to the real strix CLI.
	var strixClient strixcli.Client
	switch mode {
	case "mock":
		strixClient = strixcli.NewMockClient()
	case "live":
		strixClient, err = strixcli.NewCLIClient(strixBin, strixWork)
		if err != nil {
			return err
		}
	}
	log.Printf("strix mode=%s bin=%s work_dir=%s", mode, strixBin, strixWork)

	// PlannerService client (Orchestrator). gRPC dials lazily; readiness is
	// reported via /readyz.
	pc, err := plannerclient.Dial(plannerAddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	log.Printf("planner service at %s", plannerAddr)

	// Health surface: ready when both the PlannerService and (in live mode)
	// the strix binary answer.
	hs := health.New(healthAddr, serverName, func(ctx context.Context) error {
		if err := plannerclient.Ready(ctx, pc.API); err != nil {
			return err
		}
		return strixClient.Health(ctx)
	})
	if err := hs.Start(); err != nil {
		return err
	}
	log.Printf("health endpoints on %s (/healthz, /readyz)", hs.Addr())

	// MCP server on stdio.
	srv := mcp.NewServer(serverName, serverVersion)
	app.RegisterTools(srv, &app.Deps{
		Planner: pc.API,
		Strix:   strixClient,
		Ledger:  app.NewLedger(),
		Now:     time.Now,
	})

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() { errCh <- srv.Serve(ctx, os.Stdin, os.Stdout) }()

	select {
	case err := <-errCh:
		// Clean EOF (client exited) ends the process quietly.
		if err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
		return nil
	case <-ctx.Done():
		log.Printf("shutdown signal received")
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = hs.Shutdown(shutCtx)
		return nil
	}
}
