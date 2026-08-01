# syntax=docker/dockerfile:1
# monitor (doc 03): 24/7 continuous monitoring — Coordinator + scheduler +
# probe workers (dns/tls/http) + diff/rules engines + event streamer +
# CT poller — one static binary, multi-stage build.
#
# Compose builds this with context ../services/monitor plus
# additional_contexts { gen-go: ../gen/go, sdks-go: ../sdks/go } — both are
# referenced from go.mod via `replace` directives at ../../gen/go and
# ../../sdks/go, so the Dockerfile mirrors the repo layout (/src/gen/go,
# /src/sdks/go, /src/services/monitor) and builds with GOWORK=off.

FROM golang:1.26-bookworm AS build

# Stage the sibling modules at the exact relative paths the replace
# directives expect.
COPY --from=gen-go . /src/gen/go
COPY --from=sdks-go . /src/sdks/go

WORKDIR /src/services/monitor
COPY go.mod go.sum ./
RUN GOWORK=off go mod download

COPY . ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/monitor ./cmd/monitor

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/monitor /bin/monitor
USER nonroot:nonroot
# 8084 = Module Management API (doc 03 §13) + /healthz /readyz /metrics
EXPOSE 8084
ENTRYPOINT ["/bin/monitor", "serve"]
