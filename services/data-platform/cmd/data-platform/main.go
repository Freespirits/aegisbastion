// Command data-platform is the AegisBastion data platform (doc 09): the Ingest
// API (idempotent batches with defense-in-depth Scope Token re-verification),
// the governed GraphQL Query API behind TPEL tenant scoping, the JetStream
// consumers mirroring module output into the stores, the retention purge
// engine, and the data-access audit forwarder to gatekeeper.
//
// dp is the system of record for assets and findings ONLY (Rulings B/C4): it
// holds no RoE records, scopes, tokens or approvals, and exposes no
// authorization decision API — it re-verifies gatekeeper's grants on R1+
// ingest, never mints its own.
//
// Subcommands:
//
//	serve            run everything (REST + GraphQL + consumers + loops)
//	purge-retention  run one retention sweep (doc 09 §10/§11 manual job) and exit
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"

	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/auditfwd"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/config"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/consumers"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/events"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/httpapi"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/ingest"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/queryapi"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/retention"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/scopeverify"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/store"
	"github.com/aegisbastion/aegisbastion/services/data-platform/internal/tpel"
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
	case "purge-retention":
		err = cmdPurgeRetention(log)
	default:
		err = fmt.Errorf("unknown subcommand %q (want serve | purge-retention)", cmd)
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

// manifestS3 renders the token-manifests S3 config (doc 11 §3.2).
func manifestS3(cfg *config.Config) manifest.S3Config {
	return manifest.S3Config{
		Endpoint:        cfg.S3Endpoint,
		AccessKeyID:     cfg.S3AccessKey,
		SecretAccessKey: cfg.S3SecretKey,
		UseTLS:          cfg.S3UseTLS,
		Bucket:          cfg.ManifestBucket,
	}
}

// connectNATS dials the bus with a bounded retry (compose starts NATS with
// the app). Returns (nil, nil) in degraded mode — events then flow to the
// spill file and the audit outbox accumulates (doc 09 §8).
func connectNATS(ctx context.Context, cfg *config.Config, log *slog.Logger) (*nats.Conn, nats.JetStreamContext) {
	deadline := time.Now().Add(60 * time.Second)
	for {
		nc, err := nats.Connect(cfg.NATSUrl,
			nats.Name("aegisbastion-data-platform"),
			nats.Timeout(5*time.Second),
			nats.RetryOnFailedConnect(false),
		)
		if err == nil {
			js, jerr := nc.JetStream()
			if jerr == nil {
				return nc, js
			}
			err = jerr
			nc.Close()
		}
		if time.Now().After(deadline) {
			log.Error("NATS unavailable — starting degraded (events spill, audit outbox accumulates)", "err", err)
			return nil, nil
		}
		log.Warn("NATS not ready, retrying", "err", err)
		select {
		case <-ctx.Done():
			return nil, nil
		case <-time.After(2 * time.Second):
		}
	}
}

func cmdServe(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.DBSearchPath)
	if err != nil {
		return err
	}
	defer st.Close()

	nc, js := connectNATS(ctx, cfg, log)
	if nc != nil {
		defer nc.Close()
	}

	// Change-event publisher + spill relay (doc 09 §8: no event loss).
	pub := events.New(js, cfg.EventSpillFile, log)
	go pub.RelayLoop(ctx, cfg.EventRelayTick)

	// Ingest engine with the defense-in-depth Scope Token re-verification
	// (doc 09 §2.2 — re-verify gatekeeper's grant, never mint, Ruling B).
	verifier := scopeverify.New(cfg.GatekeeperJWKSURL, manifestS3(cfg), nil)
	engine := ingest.New(st, verifier, pub, log)

	// Bus consumers mirroring module output into the stores.
	if cfg.EnableConsumers && js != nil {
		cons := consumers.New(st, engine, js, log)
		if err := cons.Start(); err != nil {
			return fmt.Errorf("start consumers: %w", err)
		}
		defer cons.Close()
	}

	// Data-access audit forwarder → gatekeeper audit of record (doc 09 §4.4).
	fwd := auditfwd.New(st, js, cfg.InstanceID, log)
	go fwd.Run(ctx, cfg.AuditForwardTick)

	// Retention engine (doc 09 §10): in-process loop when DP_RETENTION_TICK
	// is set; the manual `purge-retention` subcommand is the MVP default.
	ret := retention.New(st, pub, manifest.S3Config{
		Endpoint:        cfg.S3Endpoint,
		AccessKeyID:     cfg.S3AccessKey,
		SecretAccessKey: cfg.S3SecretKey,
		UseTLS:          cfg.S3UseTLS,
	}, cfg.InstanceID, log)
	go ret.Run(ctx, cfg.RetentionTick)
	if _, err := st.EnsureFindingPartitions(ctx, 1); err != nil {
		log.Warn("findings partition maintenance failed (default partition covers inserts)", "err", err)
	}

	// Query API (doc 09 §5) behind TPEL (doc 09 §2.3).
	resolver := tpel.NewResolver(st)
	gql := queryapi.NewHandler(queryapi.NewResolver(st, cfg.MaxQueryPage, cfg.MaxTraversalDepth, log))

	ready := func(rctx context.Context) (bool, map[string]string) {
		details := map[string]string{}
		ok := true
		if err := st.Pool.Ping(rctx); err != nil {
			details["postgres"] = "down: " + err.Error()
			ok = false
		} else {
			details["postgres"] = "up"
		}
		if js == nil || nc == nil || !nc.IsConnected() {
			details["nats"] = "down (degraded: spill + outbox)"
		} else {
			details["nats"] = "up"
		}
		// Informational only: a stale JWKS fails R1+ ingest closed, not the
		// service (doc 09 §8).
		req, rerr := http.NewRequestWithContext(rctx, http.MethodGet, cfg.GatekeeperJWKSURL, nil)
		if rerr == nil {
			hctx, cancel := context.WithTimeout(rctx, 1500*time.Millisecond)
			defer cancel()
			resp, herr := (&http.Client{Timeout: 2 * time.Second}).Do(req.WithContext(hctx))
			if herr == nil {
				_ = resp.Body.Close()
				details["gatekeeper_jwks"] = resp.Status
			} else {
				details["gatekeeper_jwks"] = "unreachable: " + herr.Error()
			}
		}
		return ok, details
	}

	srv := httpapi.NewServer(&httpapi.Deps{
		Cfg: cfg, Store: st, Engine: engine, TPEL: resolver, ReadyFn: ready, Log: log,
	})
	mux := http.NewServeMux()
	srv.Mount(mux, gql)

	httpSrv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Info("data platform serving", "port", cfg.HTTPPort)
		if err := httpSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("http serve", "err", err)
			stop()
		}
	}()

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpSrv.Shutdown(shutdownCtx)
	return nil
}

// cmdPurgeRetention runs one retention sweep (doc 09 §11 MVP: manual purge
// job) and exits. Purge audit records stay in the outbox for the running
// service's forwarder (or the next serve start) to deliver.
func cmdPurgeRetention(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.DBSearchPath)
	if err != nil {
		return err
	}
	defer st.Close()

	nc, js := connectNATS(ctx, cfg, log)
	if nc != nil {
		defer nc.Close()
	}
	pub := events.New(js, cfg.EventSpillFile, log)
	ret := retention.New(st, pub, manifest.S3Config{
		Endpoint:        cfg.S3Endpoint,
		AccessKeyID:     cfg.S3AccessKey,
		SecretAccessKey: cfg.S3SecretKey,
		UseTLS:          cfg.S3UseTLS,
	}, cfg.InstanceID, log)
	if err := ret.Sweep(ctx); err != nil {
		return err
	}
	fmt.Println("retention sweep complete")
	return nil
}
