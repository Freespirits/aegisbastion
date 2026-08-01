// Package plannerclient is the shared client side of the platform
// PlannerService contract (proto aegisbastion.platform.v1.PlannerService;
// doc 01 §7.2 "PlannerAPI"). Both commander adapters (HexStrike MCP, CAI)
// submit TaskPlans and read mission state exclusively through this client.
//
// Authorization note (doc 01 §4.2, Ruling B): the adapters are planners, not
// authorizers. This client can only *request* — every plan it forwards is
// decided by the Orchestrator and, for R1+, by the gatekeeper PDP via the
// dispatch PEP. There is deliberately no code path here that mints, verifies,
// or attaches Scope Tokens.
package plannerclient

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// Client wraps a gRPC connection to the Orchestrator's PlannerService.
type Client struct {
	conn *grpc.ClientConn
	// API is the generated PlannerService client; adapters code against it so
	// tests can substitute any platformv1.PlannerServiceClient (e.g. bufconn).
	API platformv1.PlannerServiceClient
}

// Dial connects to the PlannerService at addr (host:port).
//
// MVP-A transport is plaintext gRPC inside the Compose network. mTLS adapter
// authentication (doc 01 §7.1) arrives with the platform-CA work; the
// endpoint and credentials are env-driven so this is a deployment concern,
// not a code change.
func Dial(addr string) (*Client, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, fmt.Errorf("plannerclient: dial %s: %w", addr, err)
	}
	return &Client{conn: conn, API: platformv1.NewPlannerServiceClient(conn)}, nil
}

// Close releases the underlying connection.
func (c *Client) Close() error {
	return c.conn.Close()
}

// Ready reports whether the PlannerService answers a minimal read call. Used
// by the /readyz probe. gRPC dials lazily, so an actual RPC is the only
// honest readiness signal.
func Ready(ctx context.Context, api platformv1.PlannerServiceClient) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := api.ListCapabilities(ctx, &platformv1.ListCapabilitiesRequest{
		Query: &platformv1.CapabilityQuery{},
	})
	if err != nil {
		return fmt.Errorf("planner service not ready: %w", err)
	}
	return nil
}
