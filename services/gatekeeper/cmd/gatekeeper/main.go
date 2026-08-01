// Command gatekeeper is the single deployable gatekeeper binary (doc 11 §9,
// doc 00 §3 Phase 0): roe-service, token-service (+JWKS), policy-service
// (the platform's single PDP), rbac-service, approval-service,
// revocation-service and audit-service behind the gatekeeper.v1 gRPC
// contracts, plus the admin REST/JWKS/health HTTP surface.
//
// Subcommands:
//
//	gatekeeper serve                 run the services (default)
//	gatekeeper approvals list        list approvals (--state pending --roe-id …)
//	gatekeeper approvals show --id appr_…
//	gatekeeper approvals approve --id appr_… --approver user_… [--note …]
//	gatekeeper approvals reject  --id appr_… --approver user_… [--note …]
//	gatekeeper revoke --scope global|roe|target|capability [--key …] --by user_… [--reason …]
//
// The CLI talks to the gRPC endpoint (--addr, default localhost:50051).
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/admin"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/approval"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/audit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/bus"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/capreg"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/config"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/inventory"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/keys"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/policy"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/ratelimit"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/rbac"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/revocation"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/roe"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/store"
	"github.com/aegisbastion/aegisbastion/services/gatekeeper/internal/token"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "serve":
			if err := serve(); err != nil {
				fmt.Fprintf(os.Stderr, "gatekeeper: %v\n", err)
				os.Exit(1)
			}
			return
		case "approvals":
			if err := approvalsCLI(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "gatekeeper approvals: %v\n", err)
				os.Exit(1)
			}
			return
		case "revoke":
			if err := revokeCLI(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "gatekeeper revoke: %v\n", err)
				os.Exit(1)
			}
			return
		case "help", "-h", "--help":
			printUsage()
			return
		}
	}
	// Default: serve.
	if err := serve(); err != nil {
		fmt.Fprintf(os.Stderr, "gatekeeper: %v\n", err)
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Print(`gatekeeper — the AegisBastion single PDP (doc 11)

Usage:
  gatekeeper serve                 run all services (default)
  gatekeeper approvals list [--state pending] [--roe-id roe_…] [--addr host:port]
  gatekeeper approvals show --id appr_… [--addr host:port]
  gatekeeper approvals approve --id appr_… --approver user_… [--note …] [--addr host:port]
  gatekeeper approvals reject  --id appr_… --approver user_… [--note …] [--addr host:port]
  gatekeeper revoke --scope global|roe|target|capability [--key …] --by user_… [--reason …] [--addr host:port]
`)
}

// ---------------------------------------------------------------------------
// serve
// ---------------------------------------------------------------------------

func serve() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Signing key (MVP-A sealed file key, doc 00 §5 Q1).
	keyPath := cfg.SigningKeyFile
	if keyPath == "" {
		keyPath = "gatekeeper_ed25519.key"
	}
	key, err := keys.LoadOrCreate(keyPath, cfg.SigningKeyPassphrase)
	if err != nil {
		return err
	}
	fmt.Printf("gatekeeper: signing key kid=%s (file custody, MVP-A)\n", key.KID)

	db, err := store.Connect(ctx, cfg.DatabaseURL, cfg.DBSearchPath)
	if err != nil {
		return err
	}
	defer db.Close()
	fmt.Println("gatekeeper: postgres connected")

	b, err := bus.Connect(ctx, cfg.NATSURL)
	if err != nil {
		return err
	}
	defer b.Close()
	fmt.Println("gatekeeper: NATS connected")

	objects, err := token.NewS3Store(cfg.S3Endpoint, cfg.S3AccessKey, cfg.S3SecretKey, cfg.S3UseTLS)
	if err != nil {
		return err
	}
	if err := objects.EnsureBucket(ctx, cfg.ManifestBucket); err != nil {
		return err
	}
	fmt.Printf("gatekeeper: object store ready (bucket %s)\n", cfg.ManifestBucket)

	registry := capreg.Default()
	if cfg.CapabilityRegistryFile != "" {
		if err := registry.LoadFile(cfg.CapabilityRegistryFile); err != nil {
			return err
		}
	}

	auditSvc := audit.New(db)
	rbacSvc := rbac.New(db)
	revSvc := revocation.New(db, rbacSvc, auditSvc, b)
	roeSvc := roe.New(db, key, rbacSvc, auditSvc, b, revSvc)
	apprSvc := approval.New(db, rbacSvc, auditSvc, b, roeSvc)

	var inv policy.InventoryVerifier
	if cfg.DPInventoryURL != "" {
		inv = inventory.NewHTTPVerifier(cfg.DPInventoryURL)
		fmt.Printf("gatekeeper: R2/R3 inventory verification via %s\n", cfg.DPInventoryURL)
	} else {
		fmt.Println("gatekeeper: WARNING DP_INVENTORY_URL unset — R2/R3 verified-inventory check skipped (Phase-0 deviation)")
	}

	polSvc := policy.New(db, roeSvc, apprSvc, revSvc, rbacSvc, registry, ratelimit.New(), auditSvc, b, inv)
	tokSvc := token.New(db, key, objects, roeSvc, apprSvc, revSvc, auditSvc, cfg)
	tokSvc.SetAuthorizer(polSvc)

	// gRPC surface (internal, plaintext on the compose network; mTLS/SPIFFE
	// arrives with MVP-B per doc 11 §5).
	grpcSrv := grpc.NewServer()
	gatekeeperv1.RegisterPolicyServiceServer(grpcSrv, polSvc)
	gatekeeperv1.RegisterTokenServiceServer(grpcSrv, tokSvc)
	gatekeeperv1.RegisterROEServiceServer(grpcSrv, roeSvc)
	gatekeeperv1.RegisterApprovalServiceServer(grpcSrv, apprSvc)
	gatekeeperv1.RegisterRevocationServiceServer(grpcSrv, revSvc)
	gatekeeperv1.RegisterAuditServiceServer(grpcSrv, auditSvc)

	grpcLis, err := net.Listen("tcp", cfg.GRPCAddr)
	if err != nil {
		return fmt.Errorf("grpc listen %s: %w", cfg.GRPCAddr, err)
	}

	// HTTP surface: JWKS + health + admin-api.
	adminSrv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: admin.NewServer(admin.Deps{
			Key: key, DB: db, ROE: roeSvc, Approval: apprSvc, Revoke: revSvc,
			RBAC: rbacSvc, Audit: auditSvc,
			ReadyChecks: map[string]func(context.Context) error{
				"nats":  func(ctx context.Context) error { return natsCheck(b) },
				"minio": func(ctx context.Context) error { return objects.Ping(ctx) },
			},
		}).Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	// Background: audit bus consumer + RoE expiry sweep.
	errCh := make(chan error, 4)
	go func() {
		fmt.Println("gatekeeper: audit consumer on audit.events")
		if err := auditSvc.RunConsumer(ctx, b); err != nil && !errors.Is(err, context.Canceled) {
			errCh <- fmt.Errorf("audit consumer: %w", err)
		}
	}()
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := roeSvc.ExpireDue(context.Background()); err != nil {
					fmt.Printf("gatekeeper: expiry sweep: %v\n", err)
				} else if n > 0 {
					fmt.Printf("gatekeeper: expired %d RoE(s)\n", n)
				}
			}
		}
	}()
	go func() {
		fmt.Printf("gatekeeper: gRPC on %s\n", cfg.GRPCAddr)
		if err := grpcSrv.Serve(grpcLis); err != nil {
			errCh <- fmt.Errorf("grpc: %w", err)
		}
	}()
	go func() {
		fmt.Printf("gatekeeper: HTTP on %s (JWKS at /.well-known/gatekeeper-jwks.json)\n", cfg.HTTPAddr)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("http: %w", err)
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
	}
	fmt.Println("gatekeeper: shutting down…")
	stopped := make(chan struct{})
	go func() {
		grpcSrv.GracefulStop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		grpcSrv.Stop()
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = adminSrv.Shutdown(shutdownCtx)
	fmt.Println("gatekeeper: stopped")
	return nil
}

func natsCheck(b *bus.Bus) error {
	if !b.NC.IsConnected() {
		return errors.New("nats: not connected")
	}
	return nil
}

// ---------------------------------------------------------------------------
// CLI (approver four-eyes workflow + kill switch)
// ---------------------------------------------------------------------------

func dial(addr string) (*grpc.ClientConn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return grpc.DialContext(ctx, addr, grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithBlock())
}

func approvalsCLI(args []string) error {
	if len(args) == 0 {
		printUsage()
		return errors.New("missing approvals action (list|show|approve|reject)")
	}
	action := args[0]
	fs := flag.NewFlagSet("approvals "+action, flag.ContinueOnError)
	addr := fs.String("addr", envOr("GATEKEEPER_GRPC", "localhost:50051"), "gRPC endpoint")
	id := fs.String("id", "", "approval id (appr_…)")
	approver := fs.String("approver", "", "approver identity (must hold offensive-approver)")
	note := fs.String("note", "", "decision note")
	state := fs.String("state", "", "filter by state (pending|granted|rejected|expired)")
	roeID := fs.String("roe-id", "", "filter by RoE")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	conn, err := dial(*addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	cli := gatekeeperv1.NewApprovalServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	switch action {
	case "list":
		req := &gatekeeperv1.ListApprovalsRequest{RoeId: *roeID}
		if *state != "" {
			v, ok := gatekeeperv1.ApprovalState_value["APPROVAL_STATE_"+toUpper(*state)]
			if !ok {
				return fmt.Errorf("unknown state %q", *state)
			}
			req.State = gatekeeperv1.ApprovalState(v)
		}
		resp, err := cli.ListApprovals(ctx, req)
		if err != nil {
			return err
		}
		for _, a := range resp.GetApprovals() {
			fmt.Printf("%s  %-8s  %s %s v%d  %s  targets=%d  requester=%s  expires=%s\n",
				a.GetApprovalId(), a.GetState().String()[len("APPROVAL_STATE_"):],
				a.GetCapability(), a.GetRoeId(), a.GetRoeVersion(),
				a.GetRiskClass().String()[len("RISK_CLASS_"):], len(a.GetTargets()),
				a.GetRequester(), a.GetExpiresAt().AsTime().Format(time.RFC3339))
		}
		if len(resp.GetApprovals()) == 0 {
			fmt.Println("(no approvals)")
		}
		return nil
	case "show":
		if *id == "" {
			return errors.New("--id is required")
		}
		resp, err := cli.GetApproval(ctx, &gatekeeperv1.GetApprovalRequest{ApprovalId: *id})
		if err != nil {
			return err
		}
		a := resp.GetApproval()
		fmt.Printf("approval %s\n  state:      %s\n  roe:        %s v%d\n  capability: %s (%s)\n  requester:  %s\n  targets:    %v\n  created:    %s\n  expires:    %s\n",
			a.GetApprovalId(), a.GetState(), a.GetRoeId(), a.GetRoeVersion(),
			a.GetCapability(), a.GetRiskClass(), a.GetRequester(), a.GetTargets(),
			a.GetCreatedAt().AsTime().Format(time.RFC3339), a.GetExpiresAt().AsTime().Format(time.RFC3339))
		for _, d := range a.GetDecisions() {
			fmt.Printf("  vote: %s approved=%v at %s (%s)\n", d.GetApprover(), d.GetApproved(),
				d.GetAt().AsTime().Format(time.RFC3339), d.GetNote())
		}
		return nil
	case "approve", "reject":
		if *id == "" || *approver == "" {
			return errors.New("--id and --approver are required")
		}
		resp, err := cli.RecordApprovalDecision(ctx, &gatekeeperv1.RecordApprovalDecisionRequest{
			ApprovalId: *id,
			Decision: &gatekeeperv1.ApproverDecision{
				Approver: *approver, Approved: action == "approve", Note: *note,
			},
		})
		if err != nil {
			return err
		}
		fmt.Printf("%s → %s\n", resp.GetApproval().GetApprovalId(), resp.GetApproval().GetState())
		return nil
	default:
		printUsage()
		return fmt.Errorf("unknown approvals action %q", action)
	}
}

func revokeCLI(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ContinueOnError)
	addr := fs.String("addr", envOr("GATEKEEPER_GRPC", "localhost:50051"), "gRPC endpoint")
	scope := fs.String("scope", "", "global|roe|target|capability")
	key := fs.String("key", "", "scoped key (roe id / target / capability)")
	by := fs.String("by", "", "issuing human identity (must hold revocation:issue)")
	reason := fs.String("reason", "", "reason (audit)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *scope == "" || *by == "" {
		printUsage()
		return errors.New("--scope and --by are required")
	}
	v, ok := gatekeeperv1.RevocationScope_value["REVOCATION_SCOPE_"+toUpper(*scope)]
	if !ok {
		return fmt.Errorf("unknown scope %q", *scope)
	}
	conn, err := dial(*addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	cli := gatekeeperv1.NewRevocationServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	resp, err := cli.Revoke(ctx, &gatekeeperv1.RevokeRequest{
		Scope: gatekeeperv1.RevocationScope(v), Key: *key, IssuedBy: *by, Reason: *reason,
	})
	if err != nil {
		return err
	}
	fmt.Printf("revocation %s issued (%s %s) — broadcast on tasks.revocations.v1\n",
		resp.GetRevocation().GetRevocationId(), *scope, *key)
	return nil
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func toUpper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'z' {
			b[i] = c - 32
		}
	}
	return string(b)
}
