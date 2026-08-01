package tokexchange

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
)

type stubExchanger struct {
	resp *gatekeeperv1.ExchangeTokenResponse
	err  error
	seen []*gatekeeperv1.ExchangeTokenRequest
}

func (s *stubExchanger) ExchangeToken(ctx context.Context, in *gatekeeperv1.ExchangeTokenRequest, opts ...grpc.CallOption) (*gatekeeperv1.ExchangeTokenResponse, error) {
	s.seen = append(s.seen, in)
	return s.resp, s.err
}

func TestExchangeSuccess(t *testing.T) {
	stub := &stubExchanger{resp: &gatekeeperv1.ExchangeTokenResponse{
		Token:  "header.payload.sig",
		Claims: &gatekeeperv1.ScopeTokenClaims{Jti: "tok_abc", Exp: 1900000000},
	}}
	c := New(stub, time.Second)
	n, err := c.Exchange(context.Background(), "parent.jwt", []string{"https://a.example"}, "job_1", "agent_x")
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if n.Token != "header.payload.sig" || n.JTI != "tok_abc" {
		t.Fatalf("bad narrowed token: %+v", n)
	}
	if got := stub.seen[0].GetNarrowedTargets(); len(got) != 1 || got[0] != "https://a.example" {
		t.Fatalf("request targets wrong: %v", got)
	}
	if stub.seen[0].GetWorkerTaskId() != "job_1" || stub.seen[0].GetWorkerSubject() != "agent_x" {
		t.Fatalf("request binding wrong: %+v", stub.seen[0])
	}
}

func TestExchangeFailClosedOnUnavailable(t *testing.T) {
	stub := &stubExchanger{err: status.Error(codes.Unavailable, "dial tcp: connection refused")}
	c := New(stub, time.Second)
	_, err := c.Exchange(context.Background(), "parent.jwt", []string{"t"}, "job_1", "agent_x")
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable, got %v", err)
	}
}

func TestExchangeFailClosedOnDenial(t *testing.T) {
	// gatekeeper returns plain errors for refusals (→ codes.Unknown on gRPC).
	stub := &stubExchanger{err: errors.New("token: narrowed target \"evil.example\" not in parent manifest (fail-closed)")}
	c := New(stub, time.Second)
	_, err := c.Exchange(context.Background(), "parent.jwt", []string{"evil.example"}, "job_1", "agent_x")
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
	if errors.Is(err, ErrUnavailable) {
		t.Fatal("denial must not be classified retryable")
	}
}

func TestExchangeForJobsHoldsThenSucceeds(t *testing.T) {
	// First call unavailable, second succeeds — the retry loop must hold
	// (fail-closed) rather than dispatch or abort.
	flaky := &flakyExchanger{failures: 1}
	c := New(flaky, time.Second)
	jobs := []JobRequest{{JobID: "job_1", Targets: []string{"t1"}}, {JobID: "job_2", Targets: []string{"t2"}}}
	out, err := c.ExchangeForJobs(context.Background(), 10*time.Millisecond, "parent.jwt", "agent_x", jobs)
	if err != nil {
		t.Fatalf("ExchangeForJobs: %v", err)
	}
	if len(out) != 2 || out[0].Token == "" || out[1].Token == "" {
		t.Fatalf("bad output: %+v", out)
	}
}

func TestExchangeForJobsAbortsOnDenial(t *testing.T) {
	deny := &stubExchanger{err: errors.New("token: RoE roe_x is ROE_STATUS_REVOKED — exchange denied")}
	c := New(deny, time.Second)
	jobs := []JobRequest{{JobID: "job_1", Targets: []string{"t1"}}}
	_, err := c.ExchangeForJobs(context.Background(), 10*time.Millisecond, "parent.jwt", "agent_x", jobs)
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("want ErrDenied, got %v", err)
	}
}

func TestExchangeForJobsTimesOutWhenGatekeeperDown(t *testing.T) {
	down := &stubExchanger{err: status.Error(codes.Unavailable, "gatekeeper down")}
	c := New(down, time.Second)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	jobs := []JobRequest{{JobID: "job_1", Targets: []string{"t1"}}}
	_, err := c.ExchangeForJobs(ctx, 10*time.Millisecond, "parent.jwt", "agent_x", jobs)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want ErrUnavailable on deadline, got %v", err)
	}
}

type flakyExchanger struct {
	failures int
	calls    int
}

func (f *flakyExchanger) ExchangeToken(ctx context.Context, in *gatekeeperv1.ExchangeTokenRequest, opts ...grpc.CallOption) (*gatekeeperv1.ExchangeTokenResponse, error) {
	f.calls++
	if f.calls <= f.failures {
		return nil, status.Error(codes.Unavailable, "transient")
	}
	return &gatekeeperv1.ExchangeTokenResponse{
		Token:  "tok-for-" + in.GetWorkerTaskId(),
		Claims: &gatekeeperv1.ScopeTokenClaims{Jti: "tok_" + in.GetWorkerTaskId(), Exp: 1900000000},
	}, nil
}
