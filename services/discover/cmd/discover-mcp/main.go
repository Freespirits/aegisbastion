// discover-mcp (doc 02 §3.1): the MCP server surface for HexStrike's
// orchestration runtime — tools discover.submit_order / discover.get_status /
// discover.list_assets / discover.cancel and resources discover://orders/{id},
// discover://scopes/{roe_id}. It wraps the same order service layer as the
// REST API (doc 02 §9: no logic forks).
//
// Transport: JSON-RPC 2.0 over HTTP POST /mcp (streamable-HTTP style, JSON
// responses) on DISCOVER_MCP_ADDR (default :8087).
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/aegisbastion/aegisbastion/services/discover/internal/config"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/runtime"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/service"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/connectors"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/planner"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/queue"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rt, err := runtime.Bootstrap(ctx, cfg, "discover-mcp", log)
	if err != nil {
		return err
	}
	defer rt.Close()
	if err := queue.EnsureStream(rt.JS); err != nil {
		return err
	}

	sources := planner.Sources{
		model.TechniquePassiveDNS:        {connectors.SecurityTrailsName, connectors.VirusTotalName, connectors.ShodanName},
		model.TechniqueCT:                {connectors.CrtSHName, connectors.CensysCTName},
		model.TechniqueSubdomainPassive:  {connectors.SecurityTrailsName, connectors.VirusTotalName, connectors.RapidDNSName, connectors.WaybackName},
		model.TechniqueIPNetblock:        {connectors.BGPViewName, connectors.RIPEstatName, connectors.RDAPName},
		model.TechniqueCloudCredentialed: {"aws_resource_explorer", "azure_resource_graph", "gcp_cloud_asset_inventory"},
	}
	svc := service.New(service.Deps{
		Store:         rt.Store,
		PEP:           rt.PEP,
		Planner:       planner.New(sources),
		JS:            rt.JS,
		Audit:         rt.Audit,
		AuditSpoolMax: cfg.AuditSpoolMax,
		Log:           log,
	})
	rt.StartAuditForwarder(ctx, "discover-mcp")

	mcp := service.NewMCP(svc)
	mux := rt.HealthMux()
	mux.Handle("/mcp", mcp)

	srv := &http.Server{Addr: cfg.MCPAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("discover-mcp listening", "addr", cfg.MCPAddr)
	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
