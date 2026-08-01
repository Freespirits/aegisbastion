// hexstrike-mcp is the HexStrike commander adapter (doc 01 §4.1, §7.1): an
// MCP server (stdio) that fronts the local HexStrike AI installation as a
// AegisBastion platform commander. It submits TaskPlans to the Orchestrator's
// PlannerService, streams verdicts back, and translates only
// Orchestrator-accepted tasks into HexStrike MCP tool calls.
//
// All configuration is env-driven:
//
//	PLANNER_ADDR          Orchestrator PlannerService gRPC host:port (default 127.0.0.1:50052)
//	HEXSTRIKE_MODE        mock | http (default mock — runs with no HexStrike install)
//	HEXSTRIKE_SERVER_URL  HexStrike server base URL in http mode (default http://127.0.0.1:8888)
//	HEALTH_ADDR           health endpoint listen address (default :8081)
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

	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/app"
	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/hx"
	"github.com/aegisbastion/aegisbastion/adapters/hexstrike-mcp/mcp"
	"github.com/aegisbastion/aegisbastion/adapters/internal/config"
	"github.com/aegisbastion/aegisbastion/adapters/internal/health"
	"github.com/aegisbastion/aegisbastion/adapters/internal/plannerclient"
)

const (
	serverName    = "aegisbastion-hexstrike-adapter"
	serverVersion = "0.1.0"
)

func main() {
	log.SetOutput(os.Stderr)
	log.SetPrefix("[hexstrike-mcp] ")
	if err := run(); err != nil {
		log.Printf("fatal: %v", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		plannerAddr = config.Getenv("PLANNER_ADDR", "127.0.0.1:50052")
		healthAddr  = config.Getenv("HEALTH_ADDR", ":8081")
		hxURL       = config.Getenv("HEXSTRIKE_SERVER_URL", "http://127.0.0.1:8888")
	)
	mode, err := config.RequireMode("HEXSTRIKE_MODE", "mock", "mock", "http")
	if err != nil {
		return err
	}

	// HexStrike client: mock is the default so the adapter always runs; http
	// fronts the real local installation.
	var hxClient hx.Client
	switch mode {
	case "mock":
		hxClient = hx.NewMockClient()
	case "http":
		hxClient, err = hx.NewHTTPClient(hxURL)
		if err != nil {
			return err
		}
	}
	log.Printf("hexstrike mode=%s server=%s", mode, hxURL)

	// PlannerService client (Orchestrator). gRPC dials lazily; readiness is
	// reported via /readyz.
	pc, err := plannerclient.Dial(plannerAddr)
	if err != nil {
		return err
	}
	defer pc.Close()
	log.Printf("planner service at %s", plannerAddr)

	// Health surface: ready when both the PlannerService and (in http mode)
	// the HexStrike server answer.
	hs := health.New(healthAddr, serverName, func(ctx context.Context) error {
		if err := plannerclient.Ready(ctx, pc.API); err != nil {
			return err
		}
		return hxClient.Health(ctx)
	})
	if err := hs.Start(); err != nil {
		return err
	}
	log.Printf("health endpoints on %s (/healthz, /readyz)", hs.Addr())

	// MCP server on stdio.
	srv := mcp.NewServer(serverName, serverVersion)
	app.RegisterTools(srv, &app.Deps{
		Planner: pc.API,
		HX:      hxClient,
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
