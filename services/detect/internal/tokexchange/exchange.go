// Package tokexchange implements Ruling C9: the Detect Coordinator never
// mints worker tokens — it requests a narrowed, job-scoped Scope Token from
// gatekeeper's TokenService.ExchangeToken per job. The exchange is
// FAIL-CLOSED: if gatekeeper is unreachable or denies the exchange, the job
// is not dispatched (doc 04 §5.2, §12).
package tokexchange

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
)

// ErrUnavailable marks gatekeeper unreachability — callers hold the job and
// retry until the task deadline, never dispatching unscoped work (fail-closed).
var ErrUnavailable = errors.New("tokexchange: gatekeeper token-service unavailable (fail-closed)")

// ErrDenied marks a gatekeeper refusal (narrowed targets outside the parent
// manifest/scope, RoE no longer ACTIVE, …). Denials are NOT retried — the job
// is dead-lettered and audit-logged.
var ErrDenied = errors.New("tokexchange: token exchange denied (fail-closed)")

// Exchanger obtains narrowed worker tokens (the gatekeeper TokenService
// client satisfies this interface; tests use a stub).
type Exchanger interface {
	ExchangeToken(ctx context.Context, in *gatekeeperv1.ExchangeTokenRequest, opts ...grpc.CallOption) (*gatekeeperv1.ExchangeTokenResponse, error)
}

// Client wraps the gatekeeper TokenService connection.
type Client struct {
	ex      Exchanger
	timeout time.Duration
}

// New builds a Client over the given TokenService client.
func New(ex Exchanger, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Client{ex: ex, timeout: timeout}
}

// Narrowed is one exchanged job token.
type Narrowed struct {
	Token  string
	JTI    string
	Expiry time.Time
}

// Exchange requests one narrowed token for (parentToken × targets → jobID).
// Fail-closed: any error means the job MUST NOT be dispatched.
func (c *Client) Exchange(ctx context.Context, parentToken string, targets []string, jobID, workerSubject string) (*Narrowed, error) {
	if parentToken == "" {
		return nil, fmt.Errorf("%w: empty parent token", ErrDenied)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("%w: empty narrowed target set", ErrDenied)
	}
	rctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, err := c.ex.ExchangeToken(rctx, &gatekeeperv1.ExchangeTokenRequest{
		ParentToken:     parentToken,
		NarrowedTargets: targets,
		WorkerTaskId:    jobID,
		WorkerSubject:   workerSubject,
	})
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		// Transport-level failures (Unavailable/Unknown) are retryable
		// unavailability; gRPC status errors carrying gatekeeper's fail-closed
		// messages are denials. The gatekeeper service wraps refusals in
		// "token: …(fail-closed)…" — treat everything else as unavailable.
		if isTransport(err) {
			return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
		return nil, fmt.Errorf("%w: %v", ErrDenied, err)
	}
	if resp.GetToken() == "" || resp.GetClaims() == nil {
		return nil, fmt.Errorf("%w: empty token in response", ErrUnavailable)
	}
	return &Narrowed{
		Token:  resp.GetToken(),
		JTI:    resp.GetClaims().GetJti(),
		Expiry: time.Unix(resp.GetClaims().GetExp(), 0).UTC(),
	}, nil
}

// isTransport classifies retryable transport failures vs gatekeeper denials.
// gatekeeper's ExchangeToken returns plain errors (mapped to codes.Unknown by
// gRPC) for fail-closed refusals; genuine reachability problems surface as
// Unavailable / DeadlineExceeded / ResourceExhausted / connection errors.
func isTransport(err error) bool {
	code := status.Code(err)
	switch code {
	case codes.Unavailable, codes.DeadlineExceeded, codes.ResourceExhausted,
		codes.Canceled:
		return true
	case codes.Unknown:
		// Plain server errors arrive as Unknown; only treat clearly
		// transport-flavored messages as retryable.
		s := err.Error()
		for _, pat := range []string{
			"connection refused", "connection reset", "no such host",
			"i/o timeout", "transport:", "EOF",
		} {
			if containsFold(s, pat) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func containsFold(s, sub string) bool {
	ls, lsub := len(s), len(sub)
	if lsub > ls {
		return false
	}
	for i := 0; i+lsub <= ls; i++ {
		match := true
		for j := 0; j < lsub; j++ {
			a, b := s[i+j], sub[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// ExchangeForJobs exchanges one narrowed token per job, retrying
// unavailability until ctx ends (fail-closed hold, doc 04 §12). Denials abort
// immediately. It exists for the coordinator's dispatch loop; callers pass a
// ctx bounded by the task deadline.
func (c *Client) ExchangeForJobs(ctx context.Context, retryInterval time.Duration, parentToken, workerSubject string, jobs []JobRequest) ([]Narrowed, error) {
	if retryInterval <= 0 {
		retryInterval = 5 * time.Second
	}
	out := make([]Narrowed, len(jobs))
	for i, j := range jobs {
		for {
			n, err := c.Exchange(ctx, parentToken, j.Targets, j.JobID, workerSubject)
			if err == nil {
				out[i] = *n
				break
			}
			if errors.Is(err, ErrDenied) {
				return nil, err
			}
			// Unavailable: hold and retry until the task deadline (fail-closed).
			select {
			case <-ctx.Done():
				return nil, fmt.Errorf("%w: gatekeeper unreachable before task deadline: %v", ErrUnavailable, ctx.Err())
			case <-time.After(retryInterval):
			}
		}
	}
	return out, nil
}

// JobRequest is one (job id, narrowed targets) exchange unit.
type JobRequest struct {
	JobID   string
	Targets []string
}
