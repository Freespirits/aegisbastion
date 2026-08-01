// Package registry is the SDK's client for the Agent Registry's AgentService
// (doc 01 §8.3, proto aegisbastion.platform.v1.AgentService): Register,
// Heartbeat (10 s cadence, 30 s TTL), AckTask (≤ 10 s or redelivery),
// ReportProgress, ReportResult, and the StreamTasks server-stream — the
// long-poll alternative to bus subscription; the TaskAssignment payload is
// identical either way.
package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/platform/v1"
)

// HeartbeatInterval is the doc 01 §8.1 cadence (Registry TTL is 30 s).
const HeartbeatInterval = 10 * time.Second

// Client calls the platform AgentService. It is safe for concurrent use.
type Client struct {
	conn    *grpc.ClientConn
	api     platformv1.AgentServiceClient
	agentID string
}

// InsecureDialOption returns a plaintext transport dial option — local
// Docker-Compose development only. Production deployments pass mTLS
// credentials (doc 01 §9 item 1: platform-CA-issued cert, SPIFFE ID in SANs)
// via Dial's opts instead.
func InsecureDialOption() grpc.DialOption {
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

// Dial connects to the AgentService at addr. The caller owns transport
// security: pass mTLS credentials, or InsecureDialOption() for local dev.
func Dial(addr string, opts ...grpc.DialOption) (*Client, error) {
	if len(opts) == 0 {
		return nil, errors.New("registry: no dial options — pass mTLS credentials or registry.InsecureDialOption()")
	}
	conn, err := grpc.NewClient(addr, opts...)
	if err != nil {
		return nil, fmt.Errorf("registry: dial %s: %w", addr, err)
	}
	return &Client{conn: conn, api: platformv1.NewAgentServiceClient(conn)}, nil
}

// Close closes the underlying connection.
func (c *Client) Close() error { return c.conn.Close() }

// AgentID returns the id assigned at Register.
func (c *Client) AgentID() string { return c.agentID }

// Register (re-)registers the manifest and records the assigned agent id.
// Manifest.AgentId is empty on first registration, present on re-registration
// (doc 01 §9 item 1: re-register on version change).
func (c *Client) Register(ctx context.Context, manifest *platformv1.AgentManifest) (string, error) {
	resp, err := c.api.Register(ctx, &platformv1.RegisterRequest{Manifest: manifest})
	if err != nil {
		return "", fmt.Errorf("registry: register: %w", err)
	}
	if resp.GetAgentId() == "" {
		return "", errors.New("registry: register returned empty agent_id")
	}
	c.agentID = resp.GetAgentId()
	return c.agentID, nil
}

// Heartbeat sends one heartbeat. killActive=true means a kill switch
// (global/per-agent) is engaged — the agent must halt target contact ≤ 5 s
// (doc 01 §10.5).
func (c *Client) Heartbeat(ctx context.Context, runningTaskIDs []string) (killActive bool, err error) {
	resp, err := c.api.Heartbeat(ctx, &platformv1.HeartbeatRequest{
		AgentId:        c.agentID,
		Ts:             timestamppb.Now(),
		RunningTaskIds: runningTaskIDs,
	})
	if err != nil {
		return false, fmt.Errorf("registry: heartbeat: %w", err)
	}
	return resp.GetKillActive(), nil
}

// AckTask acknowledges an assignment (doc 01 §9 item 3: ≤ 10 s or it
// redelivers).
func (c *Client) AckTask(ctx context.Context, taskID string) error {
	resp, err := c.api.AckTask(ctx, &platformv1.AckTaskRequest{
		AgentId: c.agentID,
		TaskId:  taskID,
	})
	if err != nil {
		return fmt.Errorf("registry: ack task %s: %w", taskID, err)
	}
	if !resp.GetAcked() {
		return fmt.Errorf("registry: ack task %s not recorded", taskID)
	}
	return nil
}

// ReportProgress streams liveness/progress (doc 03 §4.3: Monitor every 60 s
// with {assets_watched, queue_depth, probes_per_min}).
func (c *Client) ReportProgress(ctx context.Context, taskID string, progress *structpb.Struct) error {
	resp, err := c.api.ReportProgress(ctx, &platformv1.ReportProgressRequest{
		AgentId:  c.agentID,
		TaskId:   taskID,
		Progress: progress,
	})
	if err != nil {
		return fmt.Errorf("registry: progress task %s: %w", taskID, err)
	}
	if !resp.GetRecorded() {
		return fmt.Errorf("registry: progress task %s not recorded", taskID)
	}
	return nil
}

// ReportResult delivers the terminal TaskResult (idempotent on task_id).
func (c *Client) ReportResult(ctx context.Context, result *platformv1.TaskResult) error {
	resp, err := c.api.ReportResult(ctx, &platformv1.ReportResultRequest{Result: result})
	if err != nil {
		return fmt.Errorf("registry: result task %s: %w", result.GetTaskId(), err)
	}
	if !resp.GetRecorded() {
		return fmt.Errorf("registry: result task %s not recorded", result.GetTaskId())
	}
	return nil
}

// StreamTasks opens the long-poll assignment stream (doc 01 §8.3) and invokes
// handle for each assignment. It reconnects with backoff on transient stream
// errors and returns only when ctx is done or handle returns an error.
// Redelivery after a reconnect is expected — handlers must be idempotent on
// task_id (doc 01 §9 item 7).
func (c *Client) StreamTasks(ctx context.Context, handle func(context.Context, *platformv1.TaskAssignment) error) error {
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := c.streamOnce(ctx, handle)
		if err == nil || errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
			return ctx.Err()
		}
		// Transient: back off and reopen (agents fail-safe on bus/registry
		// outage — doc 01 §13: stop new target contact, retry).
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff):
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (c *Client) streamOnce(ctx context.Context, handle func(context.Context, *platformv1.TaskAssignment) error) error {
	stream, err := c.api.StreamTasks(ctx, &platformv1.StreamTasksRequest{AgentId: c.agentID})
	if err != nil {
		return err
	}
	for {
		resp, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if a := resp.GetAssignment(); a != nil {
			if err := handle(ctx, a); err != nil {
				return err
			}
		}
	}
}
