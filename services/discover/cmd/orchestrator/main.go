// discover-orchestrator (doc 02 §2.2): order intake + authz pre-check +
// planner + queue producer + reducer + status reporter + audit emitter.
//
// Surfaces: REST on DISCOVER_HTTP_ADDR (default :8083). The MCP surface is
// the separate discover-mcp binary over the same service layer.
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

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"

	"github.com/aegisbastion/aegisbastion/services/discover/internal/config"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/runtime"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/service"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/connectors"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/dpingest"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/planner"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/queue"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/reducer"
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

	rt, err := runtime.Bootstrap(ctx, cfg, "discover-orchestrator", log)
	if err != nil {
		return err
	}
	defer rt.Close()

	// Module-internal stream (idempotent — see pkg/queue doc).
	if err := queue.EnsureStream(rt.JS); err != nil {
		return err
	}

	// Planner sources = the full MVP connector set (doc 02 §8); workers
	// enforce per-pool lanes, the planner fans out across them.
	sources := planner.Sources{
		model.TechniquePassiveDNS:        {connectors.SecurityTrailsName, connectors.VirusTotalName, connectors.ShodanName},
		model.TechniqueCT:                {connectors.CrtSHName, connectors.CensysCTName},
		model.TechniqueSubdomainPassive:  {connectors.SecurityTrailsName, connectors.VirusTotalName, connectors.RapidDNSName, connectors.WaybackName},
		model.TechniqueIPNetblock:        {connectors.BGPViewName, connectors.RIPEstatName, connectors.RDAPName},
		model.TechniqueCloudCredentialed: {"aws_resource_explorer", "azure_resource_graph", "gcp_cloud_asset_inventory"},
	}
	pl := planner.New(sources)

	var svc *service.Service
	svc = service.New(service.Deps{
		Store:         rt.Store,
		PEP:           rt.PEP,
		Planner:       pl,
		JS:            rt.JS,
		Audit:         rt.Audit,
		Revoker:       gatekeeperv1.NewRevocationServiceClient(rt.GKConn),
		AuditSpoolMax: cfg.AuditSpoolMax,
		Log:           log,
	})

	// Reducer (in-process, doc 02 §2.2 orchestrator component).
	var dpClient *dpingest.Client
	if cfg.DPIngestURL != "" && !cfg.Offline {
		dpClient = &dpingest.Client{BaseURL: cfg.DPIngestURL, Principal: cfg.DPPrincipal}
	}
	red := reducer.New(reducer.Deps{
		Store:         rt.Store,
		DP:            dpClient,
		Audit:         rt.Audit,
		PublishChange: svc.PublishAssetChange,
		PublishStatus: svc.PublishStatusFor,
		Expand:        svc.ExpandTasks,
		ScopeFor:      svc.ScopeFor,
		Log:           log,
	})
	go runReducer(ctx, rt, red, log)

	// Audit forwarder + revocation feed + janitor + status heartbeat.
	rt.StartAuditForwarder(ctx, "discover-orchestrator")
	if err := rt.StartRevocationFeed(ctx, "orchestrator", func(evt *gatekeeperv1.RevocationEvent) {
		svc.HandleRevocation(ctx, evt)
	}); err != nil {
		return err
	}
	go runJanitor(ctx, svc, cfg, log)

	// REST surface.
	h := service.NewHTTP(svc, func(rctx context.Context) (bool, map[string]string) {
		checks := map[string]string{}
		ok := true
		if err := rt.Store.Ping(rctx); err != nil {
			checks["postgres"] = err.Error()
			ok = false
		} else {
			checks["postgres"] = "ok"
		}
		if !rt.NC.IsConnected() {
			checks["nats"] = "disconnected"
			ok = false
		} else {
			checks["nats"] = "ok"
		}
		return ok, checks
	})
	mux := http.NewServeMux()
	h.Mount(mux)

	srv := &http.Server{Addr: cfg.HTTPAddr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	log.Info("discover-orchestrator listening", "addr", cfg.HTTPAddr, "offline", cfg.Offline)
	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

// runReducer is the discover.results consume loop (ack after store write,
// doc 02 §2.2).
func runReducer(ctx context.Context, rt *runtime.Runtime, red *reducer.Reducer, log *slog.Logger) {
	for {
		cons, err := queue.SubscribeResults(rt.JS)
		if err != nil {
			log.Warn("reducer subscribe failed (retrying)", "error", err)
			if !sleepOrDone(ctx, 3*time.Second) {
				return
			}
			continue
		}
		log.Info("reducer consuming", "subject", model.SubjectResults)
		for {
			msgs, err := cons.Fetch(8, 2*time.Second)
			if err != nil {
				log.Warn("reducer fetch failed", "error", err)
				break
			}
			for _, msg := range msgs {
				m, err := queue.DecodeResult(msg)
				if err != nil {
					_ = msg.Term()
					continue
				}
				switch red.Process(ctx, m, queue.Deliveries(msg)) {
				case reducer.Ack:
					_ = msg.Ack()
				case reducer.Retry:
					_ = msg.NakWithDelay(2 * time.Second)
				}
			}
			select {
			case <-ctx.Done():
				cons.Close()
				return
			default:
			}
		}
		cons.Close()
		if !sleepOrDone(ctx, 3*time.Second) {
			return
		}
	}
}

// runJanitor enforces time budgets + asset expiry, and re-emits RUNNING
// statuses on the doc 02 §3.3 15 s heartbeat cadence.
func runJanitor(ctx context.Context, svc *service.Service, cfg *config.Config, log *slog.Logger) {
	sweep := time.NewTicker(30 * time.Second)
	defer sweep.Stop()
	heartbeat := time.NewTicker(cfg.StatusHeartbeat)
	defer heartbeat.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-sweep.C:
			svc.SweepOnce(ctx, cfg.AssetTTL)
		case <-heartbeat.C:
			heartbeatRunning(ctx, svc, log)
		}
	}
}

func heartbeatRunning(ctx context.Context, svc *service.Service, log *slog.Logger) {
	running, err := svc.RunningOrderIDs(ctx)
	if err != nil {
		log.Warn("status heartbeat sweep failed", "error", err)
		return
	}
	for _, id := range running {
		svc.PublishStatusFor(ctx, id)
	}
}

func sleepOrDone(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}
