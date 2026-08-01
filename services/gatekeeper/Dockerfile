# syntax=docker/dockerfile:1
# Gatekeeper — one binary, all services (doc 11 §9): roe / token / policy /
# rbac / approval / revocation / audit + admin REST + JWKS.
#
# Build context is services/gatekeeper (deploy/docker-compose.yml). The Go
# module replaces github.com/aegisbastion/aegisbastion/gen/go with ../../gen/go, which
# is OUTSIDE this context — so the image builds from the vendored module tree.
# Refresh it before building (after proto regeneration or dep changes):
#
#   (cd services/gatekeeper && GOWORK=off go mod tidy && GOWORK=off go mod vendor)

FROM golang:1.24-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOWORK=off GOFLAGS=-mod=vendor
COPY go.mod go.sum ./
COPY vendor ./vendor
COPY cmd ./cmd
COPY internal ./internal
RUN go build -trimpath -ldflags="-s -w" -o /out/gatekeeper ./cmd/gatekeeper

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata \
 && adduser -D -u 10001 gatekeeper \
 && mkdir -p /run/secrets && chown gatekeeper:gatekeeper /run/secrets
COPY --from=build /out/gatekeeper /usr/local/bin/gatekeeper
USER gatekeeper
# 50051 gRPC gatekeeper.v1 · 8080 admin REST + JWKS + health
EXPOSE 50051 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=15s \
  CMD ["wget", "-q", "-O", "/dev/null", "http://localhost:8080/healthz"]
ENTRYPOINT ["gatekeeper"]
CMD ["serve"]
