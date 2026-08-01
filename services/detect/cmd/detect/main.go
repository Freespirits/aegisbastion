// Command detect is the AegisBastion Detect module (doc 04): the Coordinator
// (platform agent, agent_type detect) plus the in-process scanner-worker
// fleet, the Active Validation Engine, the Exploit-Verification Sandbox, the
// OOB interaction service, the risk-v1 scorer, and the detect.findings /
// detect.alert publishers — one binary.
//
// Subcommands:
//
//	serve    run everything (default)
//	evs-run  sandbox child entrypoint (EVS local/gVisor runners; reads one
//	         RunRequest on stdin, writes one RunResult on stdout — invoked by
//	         the module itself, never by operators)
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

	"google.golang.org/grpc"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"

	agentsdk "github.com/aegisbastion/aegisbastion/sdks/go"
	"github.com/aegisbastion/aegisbastion/sdks/go/bus"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"
	"github.com/aegisbastion/aegisbastion/sdks/go/registry"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/config"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/coordinator"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/evidence"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/evs"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/oob"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/publish"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/risk"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/scanner"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/store"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/tokexchange"
	"github.com/aegisbastion/aegisbastion/services/detect/internal/worker"
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
	case "evs-run":
		// Sandbox child: scrubbed environment, request on stdin, result on
		// stdout. NO config load (no DATABASE_URL etc. by design).
		os.Exit(evs.ChildMain(context.Background(), os.Stdin, os.Stdout))
	default:
		err = fmt.Errorf("unknown subcommand %q (want serve | evs-run)", cmd)
	}
	if err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func cmdServe(log *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}

	// --- Postgres (fallback store + fingerprint cache + suppressions) ------
	st, err := store.New(ctx, cfg.DatabaseURL, cfg.DBSearchPath)
	if err != nil {
		return err
	}
	defer st.Close()
	st.TenantID = cfg.TenantID

	// --- Bus (module-internal queue + findings/alert publishers) -----------
	bc, err := connectBus(ctx, cfg.NATSUrl, log)
	if err != nil {
		return err
	}
	defer bc.Close()

	// --- Scanner adapters + worker fleet (D3/D10) ---------------------------
	reg := scanner.NewRegistry()
	fixture := cfg.ScannerMode == config.ScannerModeFixture
	if fixture {
		reg.Register(scanner.NewNuclei("", cfg.FixtureDir))
		reg.Register(scanner.NewNmap("", cfg.FixtureDir))
		log.Info("scanner mode: fixture (canned outputs; no target contact from adapters)")
	} else {
		reg.Register(scanner.NewNuclei(cfg.NucleiBin, ""))
		reg.Register(scanner.NewNmap(cfg.NmapBin, ""))
		log.Info("scanner mode: exec", "nuclei", cfg.NucleiBin, "nmap", cfg.NmapBin)
	}
	for _, adapterName := range reg.Names() {
		w, err := worker.New(worker.Config{
			Adapter: adapterName, Registry: reg, Conn: bc.Conn(),
			Concurrency: cfg.WorkersPerAdapter, AckWait: cfg.JobAckWait, Log: log,
		})
		if err != nil {
			return err
		}
		go func() {
			if err := w.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
				log.Error("worker stopped", "adapter", w.Adapter(), "err", err)
			}
		}()
	}

	// --- OOB interaction service (D7) ---------------------------------------
	oobSvc := oob.New(cfg.OOBPublicBase, time.Hour, log)
	if _, err := oobSvc.ListenAndServe(cfg.OOBAddr); err != nil {
		return fmt.Errorf("oob service: %w", err)
	}
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = oobSvc.Shutdown(sctx)
	}()
	go func() {
		t := time.NewTicker(10 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				oobSvc.GC()
			}
		}
	}()
	log.Info("oob interaction service listening", "addr", cfg.OOBAddr, "public_base", cfg.OOBPublicBase)

	// --- AVE (D4) ------------------------------------------------------------
	aveEngine := ave.NewEngine(
		ave.VersionCVEValidator{},
		ave.XSSValidator{},
		ave.SQLiValidator{TimeBaseSeconds: 2},
		ave.SSRFValidator{WaitWindow: 10 * time.Second, PollInterval: 500 * time.Millisecond},
		ave.TraversalValidator{},
		ave.TLSValidator{},
		ave.HeadersValidator{},
	)

	// --- EVS (D5) -------------------------------------------------------------
	var evsEngine *evs.Engine
	if cfg.EVSEnabled {
		runner, err := evs.SelectRunner(ctx, cfg.EVSRunner, cfg.EVSImage, "docker", log)
		if err != nil {
			return err // explicit gvisor request with no runsc: fail-closed
		}
		packs, err := evs.BuiltinPacks(cfg.EVSPoCPublicKey)
		if err != nil {
			return fmt.Errorf("evs packs (fail-closed): %w", err)
		}
		if cfg.EVSPoCPublicKey == "" {
			log.Warn("evs: using the embedded DEV pack-signing key — set DETECT_EVS_POC_PUBLIC_KEY in any real deployment")
		}
		evsEngine = evs.NewEngine(evs.EngineConfig{
			Runner: runner, OOB: oob.NewClient(oobSvc), OOBBaseURL: cfg.OOBPublicBase,
			Packs: packs, MaxConcurrent: cfg.EVSMaxConcurrent, Timeout: cfg.EVSTimeout, Log: log,
		})
		log.Info("evs enabled", "runner", runner.Kind(), "packs", len(packs))
	}

	// --- Intel mirror (D6 EPSS/KEV) ------------------------------------------
	intel := risk.NewMirror()
	if cfg.IntelSeedFile != "" {
		if err := intel.LoadSeed(cfg.IntelSeedFile); err != nil {
			log.Warn("intel seed load failed (empty mirror)", "err", err)
		}
	}
	if cfg.IntelEnabled {
		go runIntelCron(ctx, intel, cfg, log)
	}

	// --- Findings sink (09 Ingest API or the MVP fallback table) -------------
	var sink publish.FindingSink
	var revalidateStore coordinator.RevalidateStore
	if cfg.FindingsFallback {
		sink = store.NewFallbackSink(st, cfg.TenantID)
		revalidateStore = store.NewRevalidateAdapter(st)
		log.Info("findings sink: local fallback table detect.findings_fallback (doc 04 §13)")
	} else {
		sink = publish.NewIngestSink(
			publish.NewIngestClient(cfg.DPIngestURL, "svc-detect", cfg.TenantID, cfg.DPIngestTimeout),
			cfg.TenantID)
		log.Info("findings sink: data-platform Ingest API", "url", cfg.DPIngestURL)
	}

	// --- Gatekeeper TokenService client (Ruling C9 exchange) -----------------
	gkConn, err := grpc.NewClient(cfg.GatekeeperGRPCAddr, registry.InsecureDialOption())
	if err != nil {
		return fmt.Errorf("dial gatekeeper: %w", err)
	}
	defer gkConn.Close()
	exchanger := tokexchange.New(gatekeeperv1.NewTokenServiceClient(gkConn), cfg.ExchangeTimeout)

	// --- Coordinator (D1) -----------------------------------------------------
	var agent *agentsdk.Agent
	deps := coordinator.Deps{
		Bus:          bc,
		Adapters:     reg,
		AVE:          aveEngine,
		EVS:          evsEngine,
		Exchanger:    exchanger,
		Findings:     publish.NewFindingsPublisher(bc),
		Alerts:       publish.NewAlertMapper(cfg.OrgID, cfg.AlertTierThreshold),
		Sink:         sink,
		KnownView:    st,
		Suppressions: st,
		Revalidate:   revalidateStore,
		Intel:        intel,
		OOB:          oob.NewClient(oobSvc),
		OOBBaseURL:   cfg.OOBPublicBase,
		Evidence: evidence.New(evidence.S3Config{
			Endpoint: cfg.S3Endpoint, Region: cfg.S3Region,
			AccessKeyID: cfg.S3AccessKey, SecretAccessKey: cfg.S3SecretKey, UseTLS: cfg.S3UseTLS,
		}),
		ExchangeRetry: cfg.ExchangeRetryInterval,
		AgentID:       func() string { return agent.AgentID() },
		TenantID:      cfg.TenantID,
		OrgID:         cfg.OrgID,
		Log:           log,
	}
	coord := coordinator.New(deps)

	agent, err = agentsdk.New(agentsdk.Config{
		Manifest: &platformv1.AgentManifest{
			AgentType:    platformv1.AgentType_AGENT_TYPE_DETECT,
			Version:      cfg.AgentVersion,
			Capabilities: coordinator.ManifestCapabilities(),
			Identity:     &platformv1.AgentIdentity{SpiffeId: "spiffe://aegisbastion/agent/detect"},
			Limits:       &platformv1.AgentLimits{MaxConcurrentTasks: uint32(cfg.MaxConcurrentTasks)},
		},
		NATSURL:        cfg.NATSUrl,
		RegistryAddr:   cfg.RegistryAddr,
		GatekeeperAddr: cfg.GatekeeperGRPCAddr,
		DialOptions:    []grpc.DialOption{registry.InsecureDialOption()},
		JWKSURL:        cfg.GatekeeperJWKSURL,
		S3: manifest.S3Config{
			Endpoint: cfg.S3Endpoint, Region: cfg.S3Region,
			AccessKeyID: cfg.S3AccessKey, SecretAccessKey: cfg.S3SecretKey, UseTLS: cfg.S3UseTLS,
		},
		Logger: log,
	}, coord)
	if err != nil {
		return fmt.Errorf("agent init: %w", err)
	}
	defer agent.Close()

	// --- Health surface -------------------------------------------------------
	httpSrv := startHealthServer(cfg, st, bc, oobSvc, log)
	defer func() {
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(sctx)
	}()

	log.Info("detect serving",
		"http", cfg.HTTPPort, "oob", cfg.OOBAddr,
		"scanner_mode", cfg.ScannerMode, "evs", cfg.EVSEnabled,
		"alert_tier_threshold", cfg.AlertTierThreshold)
	if err := agent.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

// connectBus dials NATS with a startup grace window (compose starts NATS
// with the app).
func connectBus(ctx context.Context, url string, log *slog.Logger) (*bus.Client, error) {
	deadline := time.Now().Add(60 * time.Second)
	for {
		bc, err := bus.Connect(url)
		if err == nil {
			return bc, nil
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("bus connect %s: %w", url, err)
		}
		log.Warn("NATS not ready, retrying", "err", err)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// runIntelCron refreshes the EPSS/KEV mirror daily (doc 04 §8/§11: single
// cron writer; scoring itself never touches the internet).
func runIntelCron(ctx context.Context, intel *risk.Mirror, cfg *config.Config, log *slog.Logger) {
	refresh := func() {
		rctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		if err := intel.Refresh(rctx, cfg.IntelEPSSURL, cfg.IntelKEVURL); err != nil {
			log.Warn("intel mirror refresh failed (scoring continues, intel_stale may flag)", "err", err)
		} else {
			log.Info("intel mirror refreshed", "version", intel.Version())
		}
	}
	refresh()
	t := time.NewTicker(cfg.IntelRefreshInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			refresh()
		}
	}
}

// startHealthServer serves /healthz (liveness) and /readyz (dependency
// checks) on the module HTTP port.
func startHealthServer(cfg *config.Config, st *store.Store, bc *bus.Client, oobSvc *oob.Service, log *slog.Logger) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		details := map[string]string{}
		ready := true
		if err := st.Pool.Ping(r.Context()); err != nil {
			details["postgres"] = "down: " + err.Error()
			ready = false
		} else {
			details["postgres"] = "up"
		}
		if !bc.Conn().IsConnected() {
			details["nats"] = "down"
			ready = false
		} else {
			details["nats"] = "up"
		}
		details["oob"] = "up (same process)"
		w.Header().Set("Content-Type", "application/json")
		if !ready {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		fmt.Fprintf(w, `{"ready":%v,"checks":`, ready)
		enc := func() {
			first := true
			fmt.Fprint(w, "{")
			for k, v := range details {
				if !first {
					fmt.Fprint(w, ",")
				}
				first = false
				fmt.Fprintf(w, "%q:%q", k, v)
			}
			fmt.Fprint(w, "}")
		}
		enc()
		fmt.Fprint(w, "}")
	})
	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.HTTPPort),
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("health server failed", "err", err)
		}
	}()
	return srv
}
