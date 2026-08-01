// Package testutil provides the shared test helpers for the discover module:
// compose-infra handles (Postgres/NATS with graceful skips), the working-store
// schema bootstrap, and an in-process gatekeeper fake (bufconn) for intake
// tests — the fake plays the PDP so tests never mint platform decisions.
package testutil

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// PostgresDSN returns the test DSN or skips when compose Postgres is
// unreachable. Override with DISCOVER_TEST_DSN.
func PostgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("DISCOVER_TEST_DSN")
	if dsn == "" {
		dsn = "postgres://aegisbastion:aegisbastion-dev@localhost:5432/aegisbastion?sslmode=disable"
	}
	conn, err := net.DialTimeout("tcp", dsnHost(dsn), 1500*time.Millisecond)
	if err != nil {
		t.Skipf("compose Postgres unreachable (%v) — start with: docker compose --profile infra up -d", err)
	}
	_ = conn.Close()
	return dsn
}

func dsnHost(dsn string) string {
	// postgres://user:pass@host:port/db?… — extract host:port.
	rest := dsn
	for i := 0; i < len(rest)-1; i++ {
		if rest[i] == '@' {
			rest = rest[i+1:]
			break
		}
	}
	for i := 0; i < len(rest); i++ {
		if rest[i] == '/' || rest[i] == '?' {
			return rest[:i]
		}
	}
	return rest
}

// NATSURL returns the test NATS URL or skips when unreachable. Override with
// DISCOVER_TEST_NATS.
func NATSURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("DISCOVER_TEST_NATS")
	if url == "" {
		url = "nats://localhost:4222"
	}
	nc, err := nats.Connect(url, nats.Timeout(1500*time.Millisecond))
	if err != nil {
		t.Skipf("compose NATS unreachable (%v) — start with: docker compose --profile infra up -d", err)
	}
	nc.Close()
	return url
}

// MigrationPath locates db/migrations/000004_module_stores.up.sql relative to
// this source file (robust across packages).
func MigrationPath(t *testing.T) string {
	t.Helper()
	_, src, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	// src = <repo>/services/discover/internal/testutil/testutil.go — up 5
	// (testutil → internal → discover → services → repo root).
	root := filepath.Dir(src)
	for i := 0; i < 4; i++ {
		root = filepath.Dir(root)
	}
	p := filepath.Join(root, "db", "migrations", "000004_module_stores.up.sql")
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("migration file: %v", err)
	}
	return p
}

// ---------------------------------------------------------------------------
// Gatekeeper fake (bufconn) — plays the PDP for intake tests.
// ---------------------------------------------------------------------------

// FakeGatekeeper implements PolicyService + ROEService in-process.
type FakeGatekeeper struct {
	gatekeeperv1.UnimplementedPolicyServiceServer
	gatekeeperv1.UnimplementedROEServiceServer

	// AllowCaps lists capabilities the fake grants (empty ⇒ deny all).
	AllowCaps map[string]bool
	// Down simulates a PDP outage (Authorize/GetROE return Unavailable).
	Down bool
	// Scope is the fake-resolved effective scope for every RoE.
	Scope *gatekeeperv1.Scope
	// ROEVersion reported by GetROE.
	ROEVersion uint64
	// AuthorizeCalls records the requested capabilities (assertions).
	AuthorizeCalls []string
}

// Authorize implements PolicyService.
func (f *FakeGatekeeper) Authorize(_ context.Context, req *gatekeeperv1.AuthorizeRequest) (*gatekeeperv1.AuthorizeResponse, error) {
	if f.Down {
		return nil, status.Error(codes.Unavailable, "fake gatekeeper down")
	}
	r := req.GetRequest()
	f.AuthorizeCalls = append(f.AuthorizeCalls, r.GetCapability())
	evt := &gatekeeperv1.DecisionEvent{
		DecisionId: "dec_fake1",
		RequestId:  r.GetRequestId(),
		RoeId:      r.GetRoeId(),
		RoeVersion: r.GetRoeVersion(),
		RiskClass:  platformv1.RiskClass_RISK_CLASS_R0,
		DecidedAt:  timestamppb.Now(),
	}
	deny := func(code gatekeeperv1.DenyReason, detail string) *gatekeeperv1.AuthorizeResponse {
		evt.Decision = gatekeeperv1.Decision_DECISION_DENY
		evt.Reasons = []*gatekeeperv1.Reason{{Code: code, Detail: detail}}
		return &gatekeeperv1.AuthorizeResponse{Decision: evt}
	}
	for _, tgt := range r.GetTargets() {
		if tgt == "denied.example.com" {
			return deny(gatekeeperv1.DenyReason_DENY_REASON_TARGET_NOT_IN_SCOPE, tgt+" outside resolved scope v1"), nil
		}
		if tgt == "excluded.example.com" {
			return deny(gatekeeperv1.DenyReason_DENY_REASON_TARGET_EXCLUDED, tgt+" in explicit_excludes"), nil
		}
	}
	if !f.AllowCaps[r.GetCapability()] {
		return deny(gatekeeperv1.DenyReason_DENY_REASON_CAPABILITY_NOT_ALLOWED, r.GetCapability()+" not in allowed_capabilities"), nil
	}
	evt.Decision = gatekeeperv1.Decision_DECISION_ALLOW
	return &gatekeeperv1.AuthorizeResponse{Decision: evt}, nil
}

// GetROE implements ROEService.
func (f *FakeGatekeeper) GetROE(_ context.Context, req *gatekeeperv1.GetROERequest) (*gatekeeperv1.GetROEResponse, error) {
	if f.Down {
		return nil, status.Error(codes.Unavailable, "fake gatekeeper down")
	}
	v := f.ROEVersion
	if v == 0 {
		v = 1
	}
	return &gatekeeperv1.GetROEResponse{
		Roe: &gatekeeperv1.RulesOfEngagement{
			RoeId:   req.GetRoeId(),
			Name:    "fake-roe",
			Version: v,
			Scope:   f.Scope,
		},
	}, nil
}

// Dial serves the fake on a bufconn and returns a client connection.
func (f *FakeGatekeeper) Dial(t *testing.T) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	srv := grpc.NewServer()
	gatekeeperv1.RegisterPolicyServiceServer(srv, f)
	gatekeeperv1.RegisterROEServiceServer(srv, f)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
