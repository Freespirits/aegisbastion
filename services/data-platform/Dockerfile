# syntax=docker/dockerfile:1
# data-platform (doc 09): Ingest API + GraphQL Query API + TPEL + retention +
# audit forwarder — one static binary, multi-stage build.
#
# Compose builds this with context ../services/data-platform plus
# additional_contexts { gen-go: ../gen/go, sdks-go: ../sdks/go } — both are
# referenced from go.mod via `replace` directives at ../../gen/go and
# ../../sdks/go, so the Dockerfile mirrors the repo layout (/src/gen/go,
# /src/sdks/go, /src/services/data-platform) and builds with GOWORK=off.

FROM golang:1.26-bookworm AS build

# Stage the sibling modules at the exact relative paths the replace
# directives expect.
COPY --from=gen-go . /src/gen/go
COPY --from=sdks-go . /src/sdks/go

WORKDIR /src/services/data-platform
COPY go.mod go.sum ./
RUN GOWORK=off go mod download

COPY . ./
RUN GOWORK=off CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
    -o /out/data-platform ./cmd/data-platform

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/data-platform /bin/data-platform
USER nonroot:nonroot
# 8082 = Ingest REST + GraphQL /v1/query + admin + /healthz /readyz
EXPOSE 8082
ENTRYPOINT ["/bin/data-platform", "serve"]
