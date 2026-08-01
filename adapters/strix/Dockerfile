# Strix commander adapter (doc 01 §4.1, §7.1).
#
# Build context is the REPOSITORY ROOT (the module replaces
# github.com/aegisbastion/aegisbastion/gen/go with ../gen/go):
#
#   docker build -f adapters/strix/Dockerfile -t aegisbastion/strix .
#
# Generated stubs are gitignored; regenerate before building an image:
#   bin/buf.exe generate proto --template proto/buf.gen.yaml
FROM golang:1.25-alpine AS build
WORKDIR /src
COPY gen/go ./gen/go
COPY adapters ./adapters
WORKDIR /src/adapters
RUN GOWORK=off CGO_ENABLED=0 GOOS=linux \
    go build -trimpath -ldflags="-s -w" -o /out/strix ./strix/cmd/strix

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/strix /strix
# Defaults match main.go; override per deployment. live mode additionally
# needs the strix CLI (Python) in the image — mount or extend the image.
ENV PLANNER_ADDR=127.0.0.1:50052 \
    STRIX_MODE=mock \
    STRIX_BIN=strix \
    STRIX_WORK_DIR=/tmp/strix_work \
    HEALTH_ADDR=:8087
EXPOSE 8087
USER nonroot
ENTRYPOINT ["/strix"]
