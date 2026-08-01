# syntax=docker/dockerfile:1
# platform-core (doc 01): Mission API + Orchestrator + dispatch PEP + Agent
# Registry + Scheduler + kill switch — one static binary, multi-stage build.
#
# Compose builds this with context ../services/platform-core plus
# additional_contexts { gen-go: ../gen/go } — the generated stubs module is
# referenced from go.mod via a `replace` directive at ../../gen/go, so the
# Dockerfile mirrors the repo layout (/src/gen/go +
# /src/services/platform-core) and builds with GOWORK=off.

FROM golang:1.26-bookworm AS build

# Stage the generated stubs module at the exact relative path the replace
# directive expects.
COPY --from=gen-go . /src/gen/go

WORKDIR /src/services/platform-core
COPY go.mod go.sum ./
RUN GOWORK=off go mod download

COPY . ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/platform-core ./cmd/platform-core

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/platform-core /bin/platform-core
USER nonroot:nonroot
# 8081 = Mission API REST + health; 50052 = gRPC (Mission/Planner/Agent services)
EXPOSE 8081 50052
ENTRYPOINT ["/bin/platform-core", "serve"]
