package missionapi

import (
	"context"

	"google.golang.org/grpc/metadata"
)

// OperatorHeader carries the operator identity at both transports
// (X-Operator-Id). MVP RBAC shim: real RBAC is gatekeeper rbac-service.
const OperatorHeader = "x-operator-id"

// operatorFromContext extracts the operator identity from gRPC metadata.
func operatorFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	for _, v := range md.Get(OperatorHeader) {
		if v != "" {
			return v
		}
	}
	return ""
}
