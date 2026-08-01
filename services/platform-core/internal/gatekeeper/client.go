// Package gatekeeper is the thin client of the gatekeeper PDP (doc 11) used
// by the dispatch PEP and the Mission API (Ruling B: gatekeeper is the single
// PDP; platform-core holds no RoE/token/audit stores of its own).
package gatekeeper

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	gatekeeperv1 "github.com/aegisbastion/aegisbastion/gen/go/aegisbastion/gatekeeper/v1"
)

// PDP authorizes dispatches (policy-service.Authorize, doc 11 §3.3).
type PDP interface {
	Authorize(ctx context.Context, req *gatekeeperv1.AuthorizationRequest) (*gatekeeperv1.DecisionEvent, error)
}

// TokenMinter mints Scope Tokens against ALLOW decisions (token-service).
type TokenMinter interface {
	MintToken(ctx context.Context, req *gatekeeperv1.MintTokenRequest) (*gatekeeperv1.MintTokenResponse, error)
}

// ROEStore reads RoE records (roe-service) for mission admission and plan
// validation.
type ROEStore interface {
	GetROE(ctx context.Context, roeID string, version uint64) (*gatekeeperv1.RulesOfEngagement, error)
	RevokeROE(ctx context.Context, roeID, reason string) (*gatekeeperv1.RulesOfEngagement, error)
}

// ApprovalQueue drives four-eyes approvals (approval-service).
type ApprovalQueue interface {
	ListPendingApprovals(ctx context.Context, roeID string) ([]*gatekeeperv1.Approval, error)
	RecordApprovalDecision(ctx context.Context, approvalID, approver string, approved bool) (*gatekeeperv1.Approval, error)
}

// Client implements PDP + TokenMinter + ROEStore + ApprovalQueue over one
// gRPC connection to gatekeeper.
type Client struct {
	conn     *grpc.ClientConn
	policy   gatekeeperv1.PolicyServiceClient
	token    gatekeeperv1.TokenServiceClient
	roe      gatekeeperv1.ROEServiceClient
	approval gatekeeperv1.ApprovalServiceClient
	timeout  time.Duration
}

// Dial connects to gatekeeper. MVP-A runs on one Compose host without mTLS
// between services (mTLS/SPIFFE workload identity lands with the identity
// wave; the PEP contract is unchanged).
func Dial(ctx context.Context, addr string, callTimeout time.Duration) (*Client, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("gatekeeper dial %s: %w", addr, err)
	}
	return &Client{
		conn:     conn,
		policy:   gatekeeperv1.NewPolicyServiceClient(conn),
		token:    gatekeeperv1.NewTokenServiceClient(conn),
		roe:      gatekeeperv1.NewROEServiceClient(conn),
		approval: gatekeeperv1.NewApprovalServiceClient(conn),
		timeout:  callTimeout,
	}, nil
}

// Close tears down the connection.
func (c *Client) Close() error { return c.conn.Close() }

func (c *Client) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if c.timeout > 0 {
		return context.WithTimeout(ctx, c.timeout)
	}
	return ctx, func() {}
}

// Authorize calls policy-service.Authorize (fail-closed at the caller).
func (c *Client) Authorize(ctx context.Context, req *gatekeeperv1.AuthorizationRequest) (*gatekeeperv1.DecisionEvent, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.policy.Authorize(ctx, &gatekeeperv1.AuthorizeRequest{Request: req})
	if err != nil {
		return nil, err
	}
	return resp.GetDecision(), nil
}

// MintToken calls token-service.MintToken.
func (c *Client) MintToken(ctx context.Context, req *gatekeeperv1.MintTokenRequest) (*gatekeeperv1.MintTokenResponse, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	return c.token.MintToken(ctx, req)
}

// GetROE fetches an RoE record (version 0 = latest).
func (c *Client) GetROE(ctx context.Context, roeID string, version uint64) (*gatekeeperv1.RulesOfEngagement, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.roe.GetROE(ctx, &gatekeeperv1.GetROERequest{RoeId: roeID, Version: version})
	if err != nil {
		return nil, err
	}
	return resp.GetRoe(), nil
}

// RevokeROE permanently revokes an RoE (kills in-flight tasks under it).
func (c *Client) RevokeROE(ctx context.Context, roeID, reason string) (*gatekeeperv1.RulesOfEngagement, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.roe.RevokeROE(ctx, &gatekeeperv1.RevokeROERequest{RoeId: roeID, Reason: reason})
	if err != nil {
		return nil, err
	}
	return resp.GetRoe(), nil
}

// ListPendingApprovals returns PENDING approvals for an RoE.
func (c *Client) ListPendingApprovals(ctx context.Context, roeID string) ([]*gatekeeperv1.Approval, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.approval.ListApprovals(ctx, &gatekeeperv1.ListApprovalsRequest{
		RoeId: roeID, State: gatekeeperv1.ApprovalState_APPROVAL_STATE_PENDING,
	})
	if err != nil {
		return nil, err
	}
	return resp.GetApprovals(), nil
}

// RecordApprovalDecision adds one approver vote.
func (c *Client) RecordApprovalDecision(ctx context.Context, approvalID, approver string, approved bool) (*gatekeeperv1.Approval, error) {
	ctx, cancel := c.withTimeout(ctx)
	defer cancel()
	resp, err := c.approval.RecordApprovalDecision(ctx, &gatekeeperv1.RecordApprovalDecisionRequest{
		ApprovalId: approvalID,
		Decision: &gatekeeperv1.ApproverDecision{
			Approver: approver,
			Approved: approved,
		},
	})
	if err != nil {
		return nil, err
	}
	return resp.GetApproval(), nil
}
