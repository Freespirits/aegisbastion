// Package snapshot defines SnapshotDocument v1 (doc 03 §6.2) — the normalized
// per-asset × probe_type observation the diff engine, rules engine, and store
// all speak. The JSON form is what monitor.snapshots_history.data persists.
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aegisbastion/aegisbastion/sdks/go/audit"
)

// Probe statuses (doc 03 §6.2). "unauthorized" is monitor-internal: the PEP
// refused target contact — the probe never happened (zero target contact).
const (
	StatusOK            = "ok"
	StatusTimeout       = "timeout"
	StatusRefused       = "refused"
	StatusDNSNXDomain   = "dns_nxdomain"
	StatusTLSError      = "tls_error"
	StatusFiltered      = "filtered"
	StatusInconclusive  = "inconclusive"
	StatusUnauthorized  = "unauthorized"
	StatusPassiveCached = "passive_cached" // R0 passive-mode observation, zero target contact
)

// Probe types (doc 03 §6.1; tcp_port is Later, not MVP-A).
const (
	ProbeDNS     = "dns"
	ProbeTLS     = "tls"
	ProbeHTTP    = "http"
	ProbeTCPPort = "tcp_port"
)

// Document is SnapshotDocument v1 (doc 03 §6.2).
type Document struct {
	SnapshotID    string        `json:"snapshot_id"`
	AssetID       string        `json:"asset_id"`
	MissionID     string        `json:"mission_id"`
	ProbeType     string        `json:"probe_type"`
	ProbeTS       time.Time     `json:"probe_ts"`
	Status        string        `json:"status"`
	Observer      Observer      `json:"observer"`
	Data          Data          `json:"data"`
	ContentHash   string        `json:"content_hash"`
	Authorization Authorization `json:"authorization"`
}

// Observer identifies where the observation was made from.
type Observer struct {
	WorkerID    string `json:"worker_id"`
	Region      string `json:"region,omitempty"`
	ResolverSet string `json:"resolver_set,omitempty"`
}

// Authorization binds the snapshot to the Scope Token that authorized the
// probe (empty token_jti for passive/R0 observations).
type Authorization struct {
	TokenJTI   string `json:"token_jti,omitempty"`
	ROEVersion uint64 `json:"roe_version,omitempty"`
}

// Data carries the normalized per-probe payload; exactly one field is set for
// active probes (doc 03 §6.2 "normalized, per-probe typed").
type Data struct {
	DNS  *DNSData  `json:"dns,omitempty"`
	TLS  *TLSData  `json:"tls,omitempty"`
	HTTP *HTTPData `json:"http,omitempty"`
	TCP  *TCPData  `json:"tcp,omitempty"`
}

// DNSData is the normalized DNS observation (doc 03 §6.1/§6.3): record sets
// sorted, TTLs stored separately (changes below 60 s delta ignored), resolver
// quorum recorded — a record visible to only 1 of 3 resolvers yields
// confidence "possible" (handled by the diff engine).
type DNSData struct {
	// Records maps record type ("A","AAAA","CNAME","MX","TXT","NS") to the
	// sorted, deduplicated quorum-agreed record set.
	Records map[string][]string `json:"records"`
	// TTLs maps record type → lowest observed TTL (TTL-insensitive diffing).
	TTLs map[string]uint32 `json:"ttls,omitempty"`
	// CNAMEChain is the followed CNAME chain (target order).
	CNAMEChain []string `json:"cname_chain,omitempty"`
	// Dangling is set when a CNAME target is NXDOMAIN/unregistered.
	Dangling *DanglingCNAME `json:"dangling,omitempty"`
	// Quorum records resolver agreement (doc 03 §6.1: 3 resolvers, quorum 2-of-3).
	Quorum Quorum `json:"quorum"`
}

// DanglingCNAME marks a CNAME target that no longer resolves; takeable when
// the target matches the module-owned known-takeable-service list (doc 03 §7.2).
type DanglingCNAME struct {
	Target          string `json:"target"`
	TakeableService string `json:"takeable_service,omitempty"`
	Reason          string `json:"reason"`
}

// Quorum is the resolver-agreement record for a DNS probe.
type Quorum struct {
	ResolverSet string   `json:"resolver_set"`
	Resolvers   int      `json:"resolvers"`
	Agreeing    int      `json:"agreeing"`
	Disagreed   []string `json:"disagreed,omitempty"`
}

// Confirmed reports whether the quorum confirms the observation (≥2-of-3).
func (q Quorum) Confirmed() bool { return q.Resolvers == 0 || q.Agreeing*2 > q.Resolvers }

// TLSData is the normalized TLS observation (doc 03 §6.1/§6.3): leaf
// fingerprint, issuer, SAN set, validity window, negotiated protocol/cipher,
// chain intermediates by hash-set. No vulnerability probing (Detect's job).
type TLSData struct {
	Leaf            TLSCert  `json:"leaf"`
	ChainHashes     []string `json:"chain_hashes,omitempty"`
	Negotiated      TLSNeg   `json:"negotiated"`
	HostnameMatch   bool     `json:"hostname_match"`
	DaysToExpiry    int      `json:"days_to_expiry"`
	ExpiryLeewaySec int      `json:"expiry_leeway_sec,omitempty"` // doc 03 §12 clock-skew leeway
}

// TLSCert is the normalized leaf certificate.
type TLSCert struct {
	FingerprintSHA256 string   `json:"fingerprint_sha256"`
	SubjectCN         string   `json:"subject_cn,omitempty"`
	Issuer            string   `json:"issuer"`
	SANs              []string `json:"sans,omitempty"`
	NotBefore         string   `json:"not_before"`
	NotAfter          string   `json:"not_after"`
	SelfSigned        bool     `json:"self_signed"`
}

// TLSNeg is the negotiated handshake result.
type TLSNeg struct {
	Version string `json:"version"` // "1.0"|"1.1"|"1.2"|"1.3"
	Cipher  string `json:"cipher"`
	ALPN    string `json:"alpn,omitempty"`
}

// HTTPData is the normalized HTTP observation (doc 03 §6.1/§6.3): canonical
// headers (volatile dropped), title, body SimHash + size (never the body
// itself), technology fingerprint, raw body reference in MinIO.
type HTTPData struct {
	FinalURL         string            `json:"final_url"`
	Status           int               `json:"status"`
	RedirectChain    []string          `json:"redirect_chain,omitempty"`
	HeadersCanonical map[string]string `json:"headers_canonical,omitempty"`
	Title            string            `json:"title,omitempty"`
	BodySimHash      string            `json:"body_simhash,omitempty"` // 16 hex chars (64-bit)
	BodySize         int               `json:"body_size"`
	Tech             []Tech            `json:"tech,omitempty"`
	RobotsStatus     int               `json:"robots_status,omitempty"`
	RawRef           string            `json:"raw_ref,omitempty"`
	RawPending       bool              `json:"raw_pending,omitempty"` // MinIO outage path (doc 03 §12)
	PIIHits          []string          `json:"pii_hits,omitempty"`    // redaction classes hit pre-upload (doc 03 §9.5)
}

// Tech is one technology fingerprint entry (Wappalyzer-style, module-owned
// ruleset v1).
type Tech struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Confidence string `json:"confidence"` // sure|likely
}

// TCPData is the normalized TCP port-state observation (Later — modelled so
// the diff library covers the change_type enum; no MVP producer).
type TCPData struct {
	Ports []PortState `json:"ports"`
}

// PortState is the tri-state of one previously-open port (doc 03 §6.3).
type PortState struct {
	Port  int    `json:"port"`
	State string `json:"state"` // open|closed|filtered
}

// ComputeContentHash sets ContentHash to "sha256:<hex>" over the JCS
// (RFC 8785, doc 01 §10.2) canonical form of Data — the cheap "anything
// changed?" check of doc 03 §6.2/§7.1.
func (d *Document) ComputeContentHash() error {
	raw, err := json.Marshal(d.Data)
	if err != nil {
		return fmt.Errorf("snapshot: marshal data: %w", err)
	}
	canon, err := audit.CanonicalizeJSON(raw)
	if err != nil {
		return fmt.Errorf("snapshot: JCS canonicalize: %w", err)
	}
	sum := sha256.Sum256(canon)
	d.ContentHash = "sha256:" + hex.EncodeToString(sum[:])
	return nil
}
