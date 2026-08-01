# jetstream-bootstrap — one-shot topology provisioner for MVP-A.
# Builds the Go bootstrap binary; runs against the `nats` service and exits.
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/jetstream-bootstrap .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates
COPY --from=build /out/jetstream-bootstrap /usr/local/bin/jetstream-bootstrap
ENV NATS_URL=nats://nats:4222
ENTRYPOINT ["jetstream-bootstrap"]
