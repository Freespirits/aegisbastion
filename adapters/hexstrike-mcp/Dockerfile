# HexStrike MCP commander adapter (doc 01 §4.1, §7.1).
#
# Build context is the REPOSITORY ROOT (the module replaces
# github.com/aegisbastion/aegisbastion/gen/go with ../gen/go):
#
#   docker build -f adapters/hexstrike-mcp/Dockerfile -t aegisbastion/hexstrike-mcp .
#
# Generated stubs are gitignored; regenerate before building an image:
#   bin/buf.exe generate proto --template proto/buf.gen.yaml
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY gen/go ./gen/go
COPY adapters ./adapters
WORKDIR /src/adapters
RUN GOWORK=off CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /out/hexstrike-mcp ./hexstrike-mcp/cmd/hexstrike-mcp

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/hexstrike-mcp /hexstrike-mcp
# Defaults match main.go; override per deployment.
ENV PLANNER_ADDR=127.0.0.1:50052 \
    HEXSTRIKE_MODE=mock \
    HEXSTRIKE_SERVER_URL=http://127.0.0.1:8888 \
    HEALTH_ADDR=:8081
EXPOSE 8081
USER nonroot
ENTRYPOINT ["/hexstrike-mcp"]
