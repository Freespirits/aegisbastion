# syntax=docker/dockerfile:1
# discover (doc 02): orchestrator + worker pools (passive/ct/cloud) +
# discover-mcp — static binaries, multi-stage build.
#
# Compose builds this with context ../services/discover plus
# additional_contexts { gen-go: ../gen/go, sdks-go: ../sdks/go } — go.mod
# references both via `replace` at ../../gen/go and ../../sdks/go, so the
# Dockerfile mirrors the repo layout and builds with GOWORK=off.

FROM golang:1.26-bookworm AS build

# Stage the generated stubs module and the platform Go agent SDK at the exact
# relative paths the replace directives expect.
COPY --from=gen-go . /src/gen/go
COPY --from=sdks-go . /src/sdks/go

WORKDIR /src/services/discover
COPY go.mod go.sum ./
RUN GOWORK=off go mod download

COPY . ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/orchestrator ./cmd/orchestrator \
    && GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/worker-passive ./cmd/worker-passive \
    && GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/worker-ct ./cmd/worker-ct \
    && GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/worker-cloud ./cmd/worker-cloud \
    && GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/discover-mcp ./cmd/discover-mcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/orchestrator /bin/orchestrator
COPY --from=build /out/worker-passive /bin/worker-passive
COPY --from=build /out/worker-ct /bin/worker-ct
COPY --from=build /out/worker-cloud /bin/worker-cloud
COPY --from=build /out/discover-mcp /bin/discover-mcp
COPY connectors.yaml /etc/discover/connectors.yaml
USER nonroot:nonroot
# 8083 = order REST API + health (orchestrator); 8087 = MCP (discover-mcp);
# 8090 = worker pool health endpoints.
EXPOSE 8083 8087 8090
# Default role: the orchestrator. Worker pools and the MCP server run the
# same image with a command override (see deploy/docker-compose.yml).
ENTRYPOINT ["/bin/orchestrator"]
