// Package probes implements the M3 probe executors of doc 03 §6.1 (dns, tls,
// http; tcp_port is Later). Every probe is interface-driven: production
// executors talk to the network only AFTER the caller authorized the target
// through the PEP (Task.AuthorizeTarget / Guard.AuthorizeTarget — doc 03
// §9.2); fixture and loopback executors serve tests without network access.
package probes

import (
	"context"
	"time"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

// Timeouts (doc 03 §6.1).
const (
	DNSTimeout  = 10 * time.Second
	TLSTimeout  = 10 * time.Second
	HTTPTimeout = 15 * time.Second
	TCPTimeout  = 20 * time.Second
)

// MaxBodyBytes caps HTTP bodies (doc 03 §6.1/§9.5: 256 KiB).
const MaxBodyBytes = 256 << 10

// UserAgent is the fixed, deliberately identifiable UA (doc 03 §6.1/§9.6).
func UserAgent(roeID string) string {
	return "AegisBastion-Monitor/0.1 (+roe:" + roeID + ")"
}

// Request is one authorized probe invocation.
type Request struct {
	// Target is the canonical probe target (fqdn or IP) — ALREADY authorized
	// by the caller through the PEP.
	Target string
	// AssetID / MissionID / ROEID bind the observation to its context.
	AssetID   string
	MissionID string
	ROEID     string
	// ROEVersion / TokenJTI stamp the snapshot authorization block.
	ROEVersion uint64
	TokenJTI   string
	// WorkerID is the observer identity.
	WorkerID string
	// Now is the probe timestamp clock (injectable for tests).
	Now time.Time
}

// Result carries the snapshot plus side artifacts the executor persists
// (raw bodies go to MinIO after PII redaction, doc 03 §9.5).
type Result struct {
	Doc *snapshot.Document
	// RawBody is the truncated raw HTTP body (nil for non-HTTP probes).
	RawBody []byte
}

// Probe is one executor. Implementations must honor ctx cancellation
// (kill-switch halts at the next network boundary, doc 03 §4.4).
type Probe interface {
	// Type is the probe_type string ("dns" | "tls" | "http").
	Type() string
	// Probe executes the observation. Errors are transport-level failures
	// that produced NO usable observation; observation failures are reported
	// in Doc.Status instead (timeout/refused/nxdomain/…).
	Probe(ctx context.Context, req Request) (*Result, error)
}

// ByType indexes executors by probe type.
func ByType(ps []Probe) map[string]Probe {
	out := make(map[string]Probe, len(ps))
	for _, p := range ps {
		out[p.Type()] = p
	}
	return out
}
