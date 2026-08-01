// Package runtime is the shared bootstrap for the discover binaries
// (orchestrator, worker pools, discover-mcp): config, Postgres, NATS,
// gatekeeper gRPC, PEP client, audit spool + forwarder, evidence archiver,
// connector registries, and the revocation feed.
package runtime

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
	"github.com/aegisbastion/aegisbastion/sdks/go/bus"
	"github.com/aegisbastion/aegisbastion/sdks/go/manifest"

	"github.com/aegisbastion/aegisbastion/services/discover/internal/config"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/auditfwd"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/cloud"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/connectors"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/evidence"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/netguard"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/pepclient"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/store"
)

// Runtime bundles the wired dependencies.
type Runtime struct {
	Cfg    *config.Config
	Store  *store.Store
	NC     *nats.Conn
	JS     nats.JetStreamContext
	Bus    *bus.Client
	GKConn *grpc.ClientConn
	PEP    *pepclient.Client
	Audit  *auditfwd.Emitter
	Arch   *evidence.Archiver
	Log    *slog.Logger
}

// Connector sets per worker pool (doc 02 §2.2).
var (
	PoolPassive = map[string]bool{
		connectors.SecurityTrailsName: true, connectors.VirusTotalName: true,
		connectors.ShodanName: true, connectors.RapidDNSName: true,
		connectors.WaybackName: true, connectors.BGPViewName: true,
		connectors.RIPEstatName: true, connectors.RDAPName: true,
	}
	PoolCT = map[string]bool{
		connectors.CrtSHName: true, connectors.CensysCTName: true,
	}
	PoolCloud = map[string]bool{
		cloud.AWSResourceExplorerName: true, cloud.AzureResourceGraphName: true,
		cloud.GCPAssetInventoryName: true,
	}
)

// Bootstrap wires the common dependencies. actorID identifies the binary in
// audit records (e.g. "discover-orchestrator", "discover-worker-ct").
func Bootstrap(ctx context.Context, cfg *config.Config, actorID string, log *slog.Logger) (*Runtime, error) {
	if log == nil {
		log = slog.Default()
	}
	rt := &Runtime{Cfg: cfg, Log: log}

	st, err := store.Connect(ctx, cfg.DatabaseURL, cfg.SearchPath)
	if err != nil {
		return nil, err
	}
	rt.Store = st

	nc, err := nats.Connect(cfg.NATSURL, nats.Name("aegisbastion-"+actorID))
	if err != nil {
		return nil, fmt.Errorf("nats connect: %w", err)
	}
	rt.NC = nc
	rt.JS, err = nc.JetStream()
	if err != nil {
		return nil, fmt.Errorf("jetstream: %w", err)
	}
	rt.Bus, err = bus.FromConn(nc)
	if err != nil {
		return nil, err
	}

	// Gatekeeper gRPC (PEP client only — policy/roe/token/audit/revocation).
	gkConn, err := grpc.NewClient(cfg.GatekeeperGRPCAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("dial gatekeeper %s: %w", cfg.GatekeeperGRPCAddr, err)
	}
	rt.GKConn = gkConn

	fetcher := manifest.NewS3Fetcher(manifest.S3Config{
		Endpoint:        cfg.S3Endpoint,
		Region:          cfg.S3Region,
		AccessKeyID:     cfg.S3Access,
		SecretAccessKey: cfg.S3Secret,
		UseTLS:          cfg.S3UseTLS,
		Bucket:          manifest.DefaultBucket,
	})
	rt.PEP = pepclient.New(gkConn, pepclient.NewVerifier(cfg.GatekeeperJWKSURL), fetcher)
	rt.PEP.ActorID = actorID

	rt.Audit = auditfwd.NewEmitter(st, actorID)
	rt.Arch = evidence.New(evidence.Config{
		Endpoint:        cfg.S3Endpoint,
		Region:          cfg.S3Region,
		AccessKeyID:     cfg.S3Access,
		SecretAccessKey: cfg.S3Secret,
		UseTLS:          cfg.S3UseTLS,
	})
	return rt, nil
}

// Close releases connections (bus first — it owns the NATS drain).
func (rt *Runtime) Close() {
	if rt.Bus != nil {
		rt.Bus.Close()
	}
	if rt.GKConn != nil {
		_ = rt.GKConn.Close()
	}
	if rt.Store != nil {
		rt.Store.Close()
	}
}

// AuditBusEmitter publishes audit events on audit.events via the platform
// bus (gatekeeper's audit-service consumes the same subject, doc 11 §2.1.6).
func (rt *Runtime) AuditBusEmitter() audit.Emitter {
	return audit.EmitterFunc(func(ctx context.Context, evt *platformv1.AuditEvent) error {
		_, err := rt.Bus.Publish(ctx, audit.Subject, evt, bus.PublishOptions{EventID: evt.GetEventId()})
		return err
	})
}

// StartAuditForwarder drains the spool to gatekeeper's audit-service.
func (rt *Runtime) StartAuditForwarder(ctx context.Context, actorID string) {
	fwd := auditfwd.NewForwarder(rt.Store, rt.AuditBusEmitter(), actorID, rt.Log)
	go fwd.Run(ctx, time.Second)
}

// StartRevocationFeed consumes tasks.revocations.v1 into the shared PEP
// revocation cache and invokes onEvent (orchestrator order sweeps). Durable
// per actor so restarts resume.
func (rt *Runtime) StartRevocationFeed(ctx context.Context, actorID string, onEvent func(*gatekeeperv1.RevocationEvent)) error {
	sub, err := rt.Bus.Consume(bus.StreamGatekeeper, bus.SubjectRevocations,
		"discover-revocations-"+actorID, time.Minute,
		func(_ context.Context, env *platformv1.Envelope, _ *bus.MessageControl) bus.Disposition {
			msg, err := bus.UnpackPayload(env)
			if err != nil {
				return bus.Ack
			}
			evt, ok := msg.(*gatekeeperv1.RevocationEvent)
			if !ok {
				return bus.Ack
			}
			rt.PEP.Revocations.ApplyEvent(evt)
			if onEvent != nil {
				onEvent(evt)
			}
			return bus.Ack
		})
	if err != nil {
		return fmt.Errorf("revocation feed: %w", err)
	}
	go func() {
		<-ctx.Done()
		_ = sub.Unsubscribe()
	}()
	return nil
}

// BuildConnectorRegistry constructs the connector registry for one pool,
// honoring offline/fixture mode (doc 02 §9: no live API in tests).
func (rt *Runtime) BuildConnectorRegistry(pool map[string]bool) (*connectors.Registry, error) {
	cfg := rt.Cfg
	var keys connectors.KeyProvider
	if cfg.SourceKeysFile != "" {
		raw, err := os.ReadFile(cfg.SourceKeysFile)
		if err != nil {
			return nil, fmt.Errorf("source keys file: %w", err)
		}
		var sk connectors.StaticKeys
		if err := json.Unmarshal(raw, &sk); err != nil {
			return nil, fmt.Errorf("source keys file %s: %w", cfg.SourceKeysFile, err)
		}
		keys = sk
	}

	var creds cloud.CredentialProvider
	if cfg.CloudCredsFile != "" {
		fc, err := cloud.LoadFileCredentials(cfg.CloudCredsFile)
		if err != nil {
			return nil, err
		}
		creds = fc
	}

	var m *connectors.Manifest
	if cfg.ConnectorsFile != "" {
		var err error
		m, err = connectors.LoadManifest(cfg.ConnectorsFile)
		if err != nil {
			return nil, err
		}
	}

	if cfg.Offline {
		return rt.fixtureRegistry(pool, keys, creds, m)
	}

	guard := netguard.New(netguard.Config{AllowPrivate: cfg.AllowPrivateEgress})
	fetch := connectors.NewHTTPFetcher(guard)
	cat := connectors.NewCatalog(fetch, keys)
	cloud.RegisterCloudConnectors(cat, creds, nil)
	reg, err := cat.BuildRegistryFor(m, pool)
	if err != nil {
		return nil, err
	}
	if rt.Arch != nil {
		reg.SetArchive(func(ctx context.Context, source string, body []byte) string {
			// Task context isn't threaded through the hook; the key carries
			// the connector + timestamp (tenant/order are recorded on the
			// finding row itself).
			uri, err := rt.Arch.Put(ctx, "shared", "evidence", fmt.Sprint(time.Now().UnixNano()), source, body)
			if err != nil {
				rt.Log.Warn("evidence archive failed", "source", source, "error", err)
				return ""
			}
			return uri
		})
	}
	return reg, nil
}

// fixtureRegistry builds the offline registry: per-source fixture fetchers
// (recorded responses from FixturesDir) + fixture cloud providers.
func (rt *Runtime) fixtureRegistry(pool map[string]bool, keys connectors.KeyProvider, creds cloud.CredentialProvider, m *connectors.Manifest) (*connectors.Registry, error) {
	dir := rt.Cfg.FixturesDir
	cat := connectors.NewCatalog(nil, keys)
	for _, name := range []string{
		connectors.CrtSHName, connectors.CensysCTName, connectors.VirusTotalName,
		connectors.SecurityTrailsName, connectors.ShodanName, connectors.RapidDNSName,
		connectors.WaybackName, connectors.BGPViewName, connectors.RIPEstatName,
		connectors.RDAPName,
	} {
		if !pool[name] {
			continue
		}
		name := name
		fetch := fixtureFetcherFor(dir, name)
		cat.Register(name, func() connectors.Connector {
			switch name {
			case connectors.CrtSHName:
				return connectors.NewCrtSH(fetch)
			case connectors.CensysCTName:
				return connectors.NewCensysCT(fetch, keys)
			case connectors.VirusTotalName:
				return connectors.NewVirusTotal(fetch, keys)
			case connectors.SecurityTrailsName:
				return connectors.NewSecurityTrails(fetch, keys)
			case connectors.ShodanName:
				return connectors.NewShodan(fetch, keys)
			case connectors.RapidDNSName:
				return connectors.NewRapidDNS(fetch)
			case connectors.WaybackName:
				return connectors.NewWayback(fetch)
			case connectors.BGPViewName:
				return connectors.NewBGPView(fetch)
			case connectors.RIPEstatName:
				return connectors.NewRIPEstat(fetch)
			case connectors.RDAPName:
				return connectors.NewRDAP(fetch, "", "")
			}
			return nil
		})
	}
	// Fixture cloud providers (cloud_<provider>.json fixtures when present).
	providers := map[string]cloud.Provider{}
	for _, p := range []string{"aws", "azure", "gcp"} {
		providers[p] = fixtureCloudProvider(dir, p)
	}
	cloud.RegisterCloudConnectors(cat, creds, providers)
	return cat.BuildRegistryFor(m, pool)
}

// fixtureFetcherFor replays <FixturesDir>/<source>.json (missing ⇒ source
// unavailable; empty ⇒ no data).
func fixtureFetcherFor(dir, source string) connectors.Fetcher {
	path := filepath.Join(dir, source+".json")
	return connectors.FetcherFunc(func(_ context.Context, _ *connectors.Request) ([]byte, error) {
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%w: no fixture %s", connectors.ErrSourceUnavailable, path)
		}
		if len(body) == 0 {
			return nil, connectors.ErrNotFound
		}
		return body, nil
	})
}

type cloudFixture struct {
	Accounts  []cloud.Account  `json:"accounts"`
	Resources []cloud.Resource `json:"resources"`
}

// fixtureCloudProvider replays <FixturesDir>/cloud_<provider>.json (missing
// ⇒ empty inventory).
func fixtureCloudProvider(dir, provider string) cloud.Provider {
	fx := &cloud.FixtureProvider{ProviderName: provider}
	raw, err := os.ReadFile(filepath.Join(dir, "cloud_"+provider+".json"))
	if err == nil {
		var f cloudFixture
		if json.Unmarshal(raw, &f) == nil {
			fx.Accounts = f.Accounts
			fx.Resources = f.Resources
		}
	}
	return fx
}

// HealthMux serves /healthz + /readyz for the worker/mcp binaries (readyz
// checks Postgres + NATS).
func (rt *Runtime) HealthMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		checks := map[string]string{}
		ok := true
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		if err := rt.Store.Ping(ctx); err != nil {
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
		status := "ready"
		code := http.StatusOK
		if !ok {
			status = "not_ready"
			code = http.StatusServiceUnavailable
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		body, _ := json.Marshal(map[string]any{"status": status, "checks": checks})
		_, _ = w.Write(body)
	})
	return mux
}

// ServeHealth runs the health HTTP server until ctx ends (workers/mcp).
func ServeHealth(ctx context.Context, addr string, mux *http.ServeMux, log *slog.Logger) {
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(sctx)
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Error("health server failed", "addr", addr, "error", err)
	}
}
