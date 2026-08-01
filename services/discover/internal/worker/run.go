// Shared entry point for the discover worker-pool binaries
// (worker-passive, worker-ct, worker-cloud). Each binary registers as its own
// pool (per-lane JetStream durable) and serves /healthz /readyz.
package worker

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/aegisbastion/aegisbastion/services/discover/internal/config"
	"github.com/aegisbastion/aegisbastion/services/discover/internal/runtime"
)

// MainPool is the whole binary lifecycle for one worker pool. actorID is the
// audit/log identity (e.g. "discover-worker-ct"); lane is the module-internal
// subject; pool selects the connector set.
func MainPool(actorID, lane string, pool map[string]bool) {
	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := runPool(actorID, lane, pool, log); err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func runPool(actorID, lane string, pool map[string]bool, log *slog.Logger) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	rt, err := runtime.Bootstrap(ctx, cfg, actorID, log)
	if err != nil {
		return err
	}
	defer rt.Close()

	reg, err := rt.BuildConnectorRegistry(pool)
	if err != nil {
		return err
	}

	// Revocation feed → PEP cache (halt ≤ 5 s posture, doc 02 §6.5).
	if err := rt.StartRevocationFeed(ctx, actorID, nil); err != nil {
		return err
	}
	rt.StartAuditForwarder(ctx, actorID)

	// Health surface (assignment: every binary serves /healthz /readyz).
	healthAddr := os.Getenv("DISCOVER_HEALTH_ADDR")
	if healthAddr == "" {
		healthAddr = ":8090"
	}
	go runtime.ServeHealth(ctx, healthAddr, rt.HealthMux(), log)

	w := New(Deps{
		Lane:     lane,
		JS:       rt.JS,
		Registry: reg,
		PEP:      rt.PEP,
		Store:    rt.Store,
		Audit:    rt.Audit,
		Log:      log,
	})
	log.Info("worker pool starting", "lane", lane, "connectors", reg.Names(), "offline", cfg.Offline)
	err = w.Run(ctx)
	if err == context.Canceled {
		return nil
	}
	return err
}
