package ave

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"
)

// TLSValidator implements doc 04 §6 "TLS misconfig": re-handshake
// INDEPENDENTLY of the scanner and confirm the weak protocol/cipher
// negotiates. Handshake-only — non-destructive.
type TLSValidator struct{}

// Name implements Validator.
func (TLSValidator) Name() string { return "ave.tls" }

// Classes implements Validator.
func (TLSValidator) Classes() []string { return []string{"tls_misconfig"} }

// weakVersions are protocol versions whose negotiated acceptance is a
// confirmed misconfig (doc 04 §6: confirm weak protocol negotiated).
var weakVersions = map[uint16]string{
	tls.VersionSSL30: "SSLv3",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
}

// weakCiphers are suites whose acceptance confirms a weak-cipher finding.
var weakCiphers = map[uint16]string{
	tls.TLS_RSA_WITH_RC4_128_SHA:            "RC4-SHA",
	tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:       "3DES-EDE-CBC-SHA",
	tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: "ECDHE-RSA-3DES-EDE-CBC-SHA",
	tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:      "ECDHE-RSA-RC4-SHA",
	tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:    "ECDHE-ECDSA-RC4-SHA",
}

// Validate implements Validator.
func (TLSValidator) Validate(ctx context.Context, cand Candidate, tools *Tools) (*Result, error) {
	tr := &Transcript{}
	res := &Result{Method: "ave.tls", Transcript: tr}

	prober := tools.TLS
	if prober == nil {
		prober = DefaultTLSProber{Timeout: 8 * time.Second}
	}
	profile, err := prober.ProbeVersions(ctx, hostPort(cand.MatchedAtIfTarget()))
	if err != nil {
		res.Verdict = VerdictInconclusive
		res.Confidence = 0.2
		res.Detail = "independent handshake failed: " + err.Error()
		return res, nil
	}
	tr.Notes = append(tr.Notes,
		fmt.Sprintf("independent handshake: min_version=0x%04x ciphers=%d", profile.MinVersionOffered, len(profile.CipherSuites)))
	tr.Exchanges = append(tr.Exchanges, Exchange{
		Label:  "tls_handshake",
		Method: "TLS",
		URL:    profile.ServerName,
		Response: fmt.Sprintf("min_version=0x%04x cipher_suites=%v",
			profile.MinVersionOffered, profile.CipherSuites),
	})

	if name, weak := weakVersions[profile.MinVersionOffered]; weak {
		res.Verdict = VerdictConfirmed
		res.Confidence = 0.95
		res.Detail = "weak protocol negotiated independently: " + name
		return res, nil
	}
	for _, cs := range profile.CipherSuites {
		if name, weak := weakCiphers[cs]; weak {
			res.Verdict = VerdictConfirmed
			res.Confidence = 0.9
			res.Detail = "weak cipher suite negotiated independently: " + name
			return res, nil
		}
	}

	res.Verdict = VerdictNotReproducible
	res.Confidence = 0.9
	res.Detail = "no weak protocol or cipher negotiated on independent handshake"
	return res, nil
}

// MatchedAtIfTarget prefers MatchedAt (host:port) else Target.
func (c Candidate) MatchedAtIfTarget() string {
	if c.MatchedAt != "" {
		return c.MatchedAt
	}
	return c.Target
}

// DefaultTLSProber performs real independent handshakes (handshake-only;
// InsecureSkipVerify is intentional — we are testing NEGOTIATION, not trust).
type DefaultTLSProber struct {
	Timeout time.Duration
}

// ProbeVersions implements TLSProber: it attempts handshakes pinned at
// decreasing protocol versions and records the weakest the server accepts,
// plus weak-cipher acceptance at the server's preferred version.
func (DefaultTLSProber) ProbeVersions(ctx context.Context, hp string) (*TLSProfile, error) {
	timeout := 8 * time.Second
	host := hp
	serverName := strings.Split(hp, ":")[0]
	profile := &TLSProfile{ServerName: hp, MinVersionOffered: tls.VersionTLS13}

	dial := func(cfg *tls.Config) (*tls.Conn, error) {
		d := &net.Dialer{Timeout: timeout}
		raw, err := d.DialContext(ctx, "tcp", host)
		if err != nil {
			return nil, err
		}
		conn := tls.Client(raw, cfg)
		_ = conn.SetDeadline(time.Now().Add(timeout))
		if err := conn.HandshakeContext(ctx); err != nil {
			_ = raw.Close()
			return nil, err
		}
		return conn, nil
	}

	// Weakest-version acceptance (probe weakest first; the first acceptance
	// IS the weakest the server offers).
	for _, v := range []uint16{tls.VersionTLS10, tls.VersionTLS11, tls.VersionTLS12} {
		cfg := &tls.Config{
			MinVersion:         v,
			MaxVersion:         v,
			InsecureSkipVerify: true, // negotiation test only
			ServerName:         serverName,
		}
		conn, err := dial(cfg)
		if err != nil {
			continue // version refused — good
		}
		_ = conn.Close()
		profile.MinVersionOffered = v
		break
	}

	// Weak-cipher acceptance at the server's preferred version.
	weakList := make([]uint16, 0, len(weakCiphers))
	for cs := range weakCiphers {
		weakList = append(weakList, cs)
	}
	cfg := &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         serverName,
		CipherSuites:       weakList,
	}
	if conn, err := dial(cfg); err == nil {
		state := conn.ConnectionState()
		profile.CipherSuites = append(profile.CipherSuites, state.CipherSuite)
		_ = conn.Close()
	}

	if profile.MinVersionOffered == tls.VersionTLS13 {
		// Confirm the server speaks modern TLS at all (else it's just down).
		cfg := &tls.Config{InsecureSkipVerify: true, ServerName: serverName}
		conn, err := dial(cfg)
		if err != nil {
			return nil, fmt.Errorf("no TLS handshake possible: %w", err)
		}
		profile.MinVersionOffered = conn.ConnectionState().Version
		_ = conn.Close()
	}
	return profile, nil
}
