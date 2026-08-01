package probes

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

// expiryLeeway is the clock-skew leeway for cert-expiry computations
// (doc 03 §12: now ± 5 min).
const expiryLeeway = 5 * time.Minute

// TLSDialer performs one TLS handshake and returns the connection state —
// injectable for fixture/loopback tests.
type TLSDialer interface {
	Handshake(ctx context.Context, target string, port int) (*tls.ConnectionState, error)
}

// NetTLSDialer is the production dialer (TLS on 443, doc 03 §6.1).
type NetTLSDialer struct {
	// ServerName overrides the SNI/verification name (loopback tests).
	ServerName string
	// Addr overrides the dial address (loopback tests); empty dials
	// target:port.
	Addr string
}

// Handshake implements TLSDialer. Verification is deliberately NOT delegated
// to the handshake: expired/mismatched certificates are exactly what Monitor
// reports, so the handshake captures the chain (InsecureSkipVerify) and the
// probe classifies trust facts itself.
func (d NetTLSDialer) Handshake(ctx context.Context, target string, port int) (*tls.ConnectionState, error) {
	serverName := d.ServerName
	if serverName == "" {
		serverName = target
	}
	addr := d.Addr
	if addr == "" {
		addr = net.JoinHostPort(target, fmt.Sprint(port))
	}
	dialer := &net.Dialer{Timeout: TLSTimeout}
	td := &tls.Dialer{
		NetDialer: dialer,
		Config: &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // capture, then classify — see doc comment
			MinVersion:         tls.VersionTLS10,
		},
	}
	conn, err := td.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		_ = conn.Close()
		return nil, fmt.Errorf("tls: unexpected connection type %T", conn)
	}
	defer tlsConn.Close()
	state := tlsConn.ConnectionState()
	return &state, nil
}

// TLSProbe captures the certificate chain and negotiated parameters of a TLS
// handshake (doc 03 §6.1: no vulnerability probing — that is Detect's job).
type TLSProbe struct {
	Dialer TLSDialer
	// Port defaults to 443 (previously observed TLS ports are a Later
	// inventory input).
	Port int
}

// Type implements Probe.
func (p *TLSProbe) Type() string { return snapshot.ProbeTLS }

// Probe implements Probe.
func (p *TLSProbe) Probe(ctx context.Context, req Request) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, TLSTimeout)
	defer cancel()
	dialer := p.Dialer
	if dialer == nil {
		dialer = NetTLSDialer{}
	}
	port := p.Port
	if port == 0 {
		port = 443
	}
	doc := &snapshot.Document{
		AssetID:   req.AssetID,
		MissionID: req.MissionID,
		ProbeType: snapshot.ProbeTLS,
		ProbeTS:   req.Now.UTC(),
		Observer:  snapshot.Observer{WorkerID: req.WorkerID},
		Authorization: snapshot.Authorization{
			TokenJTI: req.TokenJTI, ROEVersion: req.ROEVersion,
		},
	}

	state, err := dialer.Handshake(ctx, req.Target, port)
	if err != nil {
		doc.Status = classifyTLSError(err)
		doc.Data.TLS = &snapshot.TLSData{}
		return &Result{Doc: doc}, nil
	}
	if state == nil || len(state.PeerCertificates) == 0 {
		doc.Status = snapshot.StatusTLSError
		doc.Data.TLS = &snapshot.TLSData{}
		return &Result{Doc: doc}, nil
	}

	leaf := state.PeerCertificates[0]
	now := req.Now.UTC()
	fp := sha256.Sum256(leaf.Raw)
	sans := append([]string{}, leaf.DNSNames...)
	sort.Strings(sans)
	chainHashes := make([]string, 0, len(state.PeerCertificates)-1)
	for _, c := range state.PeerCertificates[1:] {
		h := sha256.Sum256(c.Raw)
		chainHashes = append(chainHashes, hex.EncodeToString(h[:]))
	}
	sort.Strings(chainHashes)

	hostnameMatch := leaf.VerifyHostname(req.Target) == nil
	selfSigned := isSelfSigned(leaf)

	days := int(time.Until(leaf.NotAfter.Add(-expiryLeeway)).Hours() / 24)
	if now.After(leaf.NotAfter) {
		days = -int(time.Since(leaf.NotAfter.Add(expiryLeeway)).Hours() / 24)
		if days == 0 {
			days = -1
		}
	}

	doc.Status = snapshot.StatusOK
	doc.Data.TLS = &snapshot.TLSData{
		Leaf: snapshot.TLSCert{
			FingerprintSHA256: hex.EncodeToString(fp[:]),
			SubjectCN:         leaf.Subject.CommonName,
			Issuer:            leaf.Issuer.String(),
			SANs:              sans,
			NotBefore:         leaf.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:          leaf.NotAfter.UTC().Format(time.RFC3339),
			SelfSigned:        selfSigned,
		},
		ChainHashes:     chainHashes,
		Negotiated:      snapshot.TLSNeg{Version: tlsVersionName(state.Version), Cipher: tls.CipherSuiteName(state.CipherSuite), ALPN: state.NegotiatedProtocol},
		HostnameMatch:   hostnameMatch,
		DaysToExpiry:    days,
		ExpiryLeewaySec: int(expiryLeeway.Seconds()),
	}
	return &Result{Doc: doc}, nil
}

// classifyTLSError maps handshake failures to snapshot statuses.
func classifyTLSError(err error) string {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return snapshot.StatusTimeout
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && strings.Contains(strings.ToLower(opErr.Err.Error()), "refused") {
		return snapshot.StatusRefused
	}
	return snapshot.StatusTLSError
}

// isSelfSigned reports whether the cert is its own issuer and verifies with
// its own public key.
func isSelfSigned(cert *x509.Certificate) bool {
	if cert.Issuer.String() != cert.Subject.String() {
		return false
	}
	return cert.CheckSignatureFrom(cert) == nil
}

// tlsVersionName renders the negotiated version per SnapshotDocument v1.
func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "1.3"
	case tls.VersionTLS12:
		return "1.2"
	case tls.VersionTLS11:
		return "1.1"
	case tls.VersionTLS10:
		return "1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
