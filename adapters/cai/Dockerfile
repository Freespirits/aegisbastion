# CAI commander adapter (doc 01 §4.1, §7.1) — bring-your-own-license (BYO).
# The default planner is the built-in deterministic STUB (CAI_MODE=stub);
# a real CAI backend plugs in behind the app.Planner interface without
# touching the REST surface.
#
# LICENSING: CAI (Alias Robotics S.L.) is research-use only — commercial use
# of a real CAI backend requires the operator's own Alias Robotics commercial
# license. This image contains NO CAI code.
#
# Build context is the REPOSITORY ROOT (the module replaces
# github.com/aegisbastion/aegisbastion/gen/go with ../gen/go):
#
#   docker build -f adapters/cai/Dockerfile -t aegisbastion/cai .
#
# Generated stubs are gitignored; regenerate before building an image:
#   bin/buf.exe generate proto --template proto/buf.gen.yaml
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY gen/go ./gen/go
COPY adapters ./adapters
WORKDIR /src/adapters
RUN GOWORK=off CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /out/cai ./cai/cmd/cai

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/cai /cai
# Defaults match main.go; override per deployment.
ENV PLANNER_ADDR=127.0.0.1:50052 \
    CAI_MODE=stub \
    CAI_LISTEN_ADDR=:8082
EXPOSE 8082
USER nonroot
ENTRYPOINT ["/cai"]
