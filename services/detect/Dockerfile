# syntax=docker/dockerfile:1
# detect (doc 04): Coordinator + scanner workers + AVE + EVS + OOB service +
# risk scorer + findings/alert publishers — one static binary, multi-stage
# build.
#
# Compose builds this with context ../services/detect plus
# additional_contexts { gen-go: ../gen/go, sdks-go: ../sdks/go } — the
# generated stubs module and the platform Go agent SDK are referenced from
# go.mod via `replace` directives at ../../gen/go and ../../sdks/go, so the
# Dockerfile mirrors the repo layout (/src/gen/go, /src/sdks/go,
# /src/services/detect) and builds with GOWORK=off.

FROM golang:1.26-bookworm AS build

# Stage the generated stubs module + the Go agent SDK at the exact relative
# paths the replace directives expect.
COPY --from=gen-go . /src/gen/go
COPY --from=sdks-go . /src/sdks/go

WORKDIR /src/services/detect
COPY go.mod go.sum ./
RUN GOWORK=off go mod download

COPY . ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/detect ./cmd/detect

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/detect /bin/detect
# Fixture-mode canned scanner outputs (default DETECT_SCANNER_MODE=fixture;
# exec mode mounts real scanner binaries and sets DETECT_*_BIN instead).
COPY --from=build /src/services/detect/internal/scanner/testdata /fixtures
ENV DETECT_FIXTURE_DIR=/fixtures
USER nonroot:nonroot
# 8085 = /healthz /readyz; 8090 = OOB interaction service (canary callbacks)
EXPOSE 8085 8090
ENTRYPOINT ["/bin/detect", "serve"]
