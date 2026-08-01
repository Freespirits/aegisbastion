package probes

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/normalize"
	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

// maxRedirects caps the redirect chain capture (doc 03 §6.1: GET / over
// HTTPS→HTTP fallback; the chain is data, not extra probing).
const maxRedirects = 5

// HTTPClient executes requests — injectable for fixture/loopback tests.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// HTTPProbe fetches GET / (plus /robots.txt header-only) over HTTPS with an
// HTTP fallback, capturing status, redirect chain, canonical headers, title,
// body hash, and the technology fingerprint (doc 03 §6.1).
type HTTPProbe struct {
	// Client is the HTTP client (default: production client with 15 s
	// timeout). Loopback tests inject a client bound to httptest servers.
	Client HTTPClient
	// ResolveURL maps (target, scheme) to the request URL — loopback tests
	// redirect to local servers; nil uses scheme://target/.
	ResolveURL func(target, scheme string) string
	// FetchRobots toggles the /robots.txt header-only fetch (default true).
	FetchRobots *bool
}

// Type implements Probe.
func (p *HTTPProbe) Type() string { return snapshot.ProbeHTTP }

// Probe implements Probe.
func (p *HTTPProbe) Probe(ctx context.Context, req Request) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, HTTPTimeout)
	defer cancel()

	doc := &snapshot.Document{
		AssetID:   req.AssetID,
		MissionID: req.MissionID,
		ProbeType: snapshot.ProbeHTTP,
		ProbeTS:   req.Now.UTC(),
		Observer:  snapshot.Observer{WorkerID: req.WorkerID},
		Authorization: snapshot.Authorization{
			TokenJTI: req.TokenJTI, ROEVersion: req.ROEVersion,
		},
	}

	// HTTPS first, HTTP fallback (doc 03 §6.1).
	data, raw, status, err := p.fetch(ctx, req, "https")
	if err != nil {
		data, raw, status, err = p.fetch(ctx, req, "http")
	}
	if err != nil {
		doc.Status = status
		doc.Data.HTTP = &snapshot.HTTPData{}
		return &Result{Doc: doc}, nil
	}
	doc.Status = snapshot.StatusOK
	doc.Data.HTTP = data
	return &Result{Doc: doc, RawBody: raw}, nil
}

// fetch performs one GET / over scheme with redirect-chain capture and the
// robots header-only check. The returned status is only meaningful when err
// is non-nil.
func (p *HTTPProbe) fetch(ctx context.Context, req Request, scheme string) (*snapshot.HTTPData, []byte, string, error) {
	client := p.Client
	if client == nil {
		client = productionHTTPClient()
	}
	resolve := p.ResolveURL
	if resolve == nil {
		resolve = func(target, scheme string) string {
			return scheme + "://" + target + "/"
		}
	}

	var chain []string
	hc, ok := client.(*http.Client)
	if !ok {
		// Custom client: wrap in an http.Client delegating to Do so redirect
		// handling stays stdlib.
		hc = &http.Client{
			Timeout: HTTPTimeout,
			Transport: roundTripperFunc(func(r *http.Request) (*http.Response, error) {
				return client.Do(r)
			}),
		}
	}
	hc2 := *hc
	hc2.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return http.ErrUseLastResponse
		}
		// Record the URL that just redirected us (doc 03 §6.2: the chain
		// holds the hops before final_url).
		chain = append(chain, via[len(via)-1].URL.String())
		return nil
	}

	url := resolve(req.Target, scheme)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, snapshot.StatusInconclusive, err
	}
	httpReq.Header.Set("User-Agent", UserAgent(req.ROEID))
	httpReq.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.5")

	resp, err := hc2.Do(httpReq)
	if err != nil {
		return nil, nil, classifyHTTPError(err), err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil && len(raw) == 0 {
		return nil, nil, classifyHTTPError(err), err
	}
	if len(raw) > MaxBodyBytes {
		raw = raw[:MaxBodyBytes]
	}

	headers := normalize.CanonicalHeaders(resp.Header)
	title := extractTitle(raw)
	data := &snapshot.HTTPData{
		FinalURL:         resp.Request.URL.String(),
		Status:           resp.StatusCode,
		RedirectChain:    chain,
		HeadersCanonical: headers,
		Title:            title,
		BodySimHash:      normalize.SimHashHex(normalize.SimHash64(normalize.TokenizeBody(raw))),
		BodySize:         len(raw),
	}

	// Technology fingerprint (module-owned ruleset v1).
	tech := normalize.FingerprintTech(headers, raw)
	for _, t := range tech {
		data.Tech = append(data.Tech, snapshot.Tech{
			Name: t.Name, Version: t.Version, Confidence: t.Confidence,
		})
	}

	// /robots.txt header-only (doc 03 §6.1).
	if p.robotsEnabled() {
		data.RobotsStatus = p.fetchRobots(ctx, client, req, scheme)
	}
	return data, raw, "", nil
}

// fetchRobots issues a HEAD against /robots.txt and records the status
// (best-effort; 0 when unreachable).
func (p *HTTPProbe) fetchRobots(ctx context.Context, client HTTPClient, req Request, scheme string) int {
	resolve := p.ResolveURL
	base := ""
	if resolve != nil {
		base = resolve(req.Target, scheme)
	} else {
		base = scheme + "://" + req.Target + "/"
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(rctx, http.MethodHead, strings.TrimSuffix(base, "/")+"/robots.txt", nil)
	if err != nil {
		return 0
	}
	r.Header.Set("User-Agent", UserAgent(req.ROEID))
	resp, err := client.Do(r)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func (p *HTTPProbe) robotsEnabled() bool {
	return p.FetchRobots == nil || *p.FetchRobots
}

// productionHTTPClient builds the default client: 15 s timeout, no proxy
// from environment (probe determinism), TLS that captures rather than refuses
// (cert problems are findings, not fetch failures).
func productionHTTPClient() *http.Client {
	return &http.Client{
		Timeout: HTTPTimeout,
		Transport: &http.Transport{
			Proxy:               nil,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConns:        8,
			IdleConnTimeout:     30 * time.Second,
			DisableCompression:  false,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
}

// classifyHTTPError maps fetch failures to snapshot statuses.
func classifyHTTPError(err error) string {
	var nerr net.Error
	if errors.As(err, &nerr) && nerr.Timeout() {
		return snapshot.StatusTimeout
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		if dnsErr.IsNotFound {
			return snapshot.StatusDNSNXDomain
		}
		return snapshot.StatusInconclusive
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		msg := strings.ToLower(opErr.Err.Error())
		if strings.Contains(msg, "refused") {
			return snapshot.StatusRefused
		}
	}
	if strings.Contains(strings.ToLower(err.Error()), "tls") ||
		strings.Contains(strings.ToLower(err.Error()), "certificate") {
		return snapshot.StatusTLSError
	}
	return snapshot.StatusInconclusive
}

// titleRe extracts <title> content (first match, case-insensitive).
var titleRe = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

func extractTitle(body []byte) string {
	m := titleRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.Join(strings.Fields(string(m[1])), " ")
}

// roundTripperFunc adapts a function to http.RoundTripper.
type roundTripperFunc func(*http.Request) (*http.Response, error)

// RoundTrip implements http.RoundTripper.
func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
