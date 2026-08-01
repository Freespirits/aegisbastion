// Package evs is the Exploit-Verification Sandbox (doc 04 §7.1, D5) plus the
// scope-enforcing egress proxy (doc 04 §10.2) it shares with the scanner
// workers and the AVE.
//
// The egress proxy is the network-level scope control: all target-bound
// traffic egresses through a per-task forward proxy whose allowlist is
// exactly the task token's targets (plus the OOB collector endpoint for
// canary callbacks). Everything else is refused — "we cannot scan out of
// scope" is a network fact, not a code promise (module-level control retained
// per Ruling B.2). Every refusal is a SCOPE_VIOLATION candidate event
// (doc 04 §10.2/§12 "sandbox compromise" signal).
package evs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Allowlist is the parsed set of egress-permitted endpoints derived from the
// task token's targets (+ the OOB collector, added by the coordinator).
// Deny-all is the default: an empty allowlist permits nothing.
type Allowlist struct {
	hosts     map[string]bool // exact hosts (lower-case, no port)
	suffix    []string        // domain suffixes ("acme.com" covers api.acme.com)
	cidrs     []netip.Prefix  // CIDR targets
	hostPorts map[string]bool // explicit host:port pins ("host:8443")
}

// NewAllowlist parses task targets (URLs, hosts, host:port, CIDRs) into an
// Allowlist. Unparseable entries are skipped (fail-closed — they permit
// nothing rather than everything).
func NewAllowlist(targets []string) *Allowlist {
	a := &Allowlist{hosts: map[string]bool{}, hostPorts: map[string]bool{}}
	for _, raw := range targets {
		a.add(raw)
	}
	return a
}

func (a *Allowlist) add(raw string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return
	}
	if p, err := netip.ParsePrefix(raw); err == nil {
		a.cidrs = append(a.cidrs, p.Masked())
		return
	}
	if strings.HasPrefix(raw, "http://") || strings.HasPrefix(raw, "https://") {
		if u, err := url.Parse(raw); err == nil && u.Hostname() != "" {
			a.addHostPort(u.Hostname(), u.Port())
		}
		return
	}
	// host[:port] form (also tolerate a trailing path).
	s := raw
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, p, err := net.SplitHostPort(s); err == nil {
		a.addHostPort(strings.Trim(h, "[]"), p)
		return
	}
	a.addHostPort(strings.Trim(s, "[]"), "")
}

func (a *Allowlist) addHostPort(host, port string) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return
	}
	if port != "" {
		a.hostPorts[host+":"+port] = true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		a.cidrs = append(a.cidrs, netip.PrefixFrom(ip, ip.BitLen()))
		return
	}
	a.hosts[host] = true
	// Domain targets cover their subdomains (the RoE scope semantics, doc 01
	// §10.1 longest-prefix/exact-host matching).
	labels := strings.Split(host, ".")
	if len(labels) >= 2 {
		a.suffix = append(a.suffix, host)
	}
}

// Allows reports whether host[:port] is inside the allowlist. Port pins, when
// present for a host, narrow it: a host pinned to specific ports is permitted
// only on those ports.
func (a *Allowlist) Allows(hostPort string) bool {
	host := hostPort
	port := ""
	if h, p, err := net.SplitHostPort(hostPort); err == nil {
		host, port = h, p
	}
	host = strings.ToLower(strings.Trim(strings.TrimSuffix(host, "."), "[]"))
	if host == "" {
		return false
	}
	if port != "" && a.hostPorts[host+":"+port] {
		return true
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		for _, p := range a.cidrs {
			if p.Contains(ip) {
				return true
			}
		}
		return false
	}
	if a.hosts[host] {
		return true
	}
	for _, s := range a.suffix {
		if strings.HasSuffix(host, "."+s) {
			return true
		}
	}
	return false
}

// DenyEvent describes one refused egress attempt (SCOPE_VIOLATION candidate,
// doc 04 §10.2).
type DenyEvent struct {
	At       time.Time
	HostPort string
	Reason   string
	Via      string // "connect" | "http"
}

// Proxy is the per-task scope-enforcing forward proxy (doc 04 §10.2): an
// HTTP/CONNECT proxy on a loopback address. Scanner children, AVE HTTP
// clients and EVS sandboxes point their proxy env at it.
type Proxy struct {
	allow *Allowlist
	log   *slog.Logger

	// OnDeny receives every refusal (the coordinator wires it to the audit
	// emitter as a SCOPE_VIOLATION candidate event).
	OnDeny func(DenyEvent)

	srv    *http.Server
	ln     net.Listener
	denies atomic.Uint64
	allowN atomic.Uint64
	once   sync.Once
}

// NewProxy builds a Proxy for the allowlist (nil allowlist → deny-all).
func NewProxy(allow *Allowlist, log *slog.Logger) *Proxy {
	if allow == nil {
		allow = NewAllowlist(nil)
	}
	if log == nil {
		log = slog.Default()
	}
	p := &Proxy{allow: allow, log: log}
	p.srv = &http.Server{
		Handler:           http.HandlerFunc(p.serve),
		ReadHeaderTimeout: 10 * time.Second,
	}
	return p
}

// Start binds the proxy on 127.0.0.1:0 and serves in the background. Returns
// the proxy URL ("http://127.0.0.1:PORT") for proxy env vars.
func (p *Proxy) Start() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("evs: proxy listen: %w", err)
	}
	p.ln = ln
	go func() {
		if err := p.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			p.log.Error("evs: egress proxy serve failed", "err", err)
		}
	}()
	return "http://" + ln.Addr().String(), nil
}

// Close stops the proxy (task end / kill path).
func (p *Proxy) Close(ctx context.Context) error {
	var err error
	p.once.Do(func() {
		if p.srv != nil {
			err = p.srv.Shutdown(ctx)
		}
	})
	return err
}

// Stats reports (allowed, denied) request counts — self-reported per-job
// rate/scope audit figures (doc 04 §10.1 layer 5).
func (p *Proxy) Stats() (allowed, denied uint64) {
	return p.allowN.Load(), p.denies.Load()
}

func (p *Proxy) deny(w http.ResponseWriter, hostPort, reason, via string) {
	p.denies.Add(1)
	evt := DenyEvent{At: time.Now().UTC(), HostPort: hostPort, Reason: reason, Via: via}
	p.log.Warn("evs: egress DENIED (scope)", "host", hostPort, "reason", reason, "via", via)
	if p.OnDeny != nil {
		p.OnDeny(evt)
	}
	http.Error(w, "aegisbastion egress proxy: target out of scope", http.StatusForbidden)
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.serveConnect(w, r)
		return
	}
	p.serveHTTP(w, r)
}

// serveConnect handles CONNECT host:port (HTTPS tunneling).
func (p *Proxy) serveConnect(w http.ResponseWriter, r *http.Request) {
	hostPort := r.Host
	if !strings.Contains(hostPort, ":") {
		hostPort += ":443"
	}
	if !p.allow.Allows(hostPort) {
		p.deny(w, hostPort, "host not in task allowlist", "connect")
		return
	}
	upstream, err := net.DialTimeout("tcp", hostPort, 15*time.Second)
	if err != nil {
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	p.allowN.Add(1)
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = buf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = buf.Flush()
	go tunnel(upstream, client)
	go tunnel(client, upstream)
}

func tunnel(dst, src net.Conn) {
	_, _ = io.Copy(dst, src)
	_ = dst.Close()
	_ = src.Close()
}

// serveHTTP forwards plain-HTTP proxy requests.
func (p *Proxy) serveHTTP(w http.ResponseWriter, r *http.Request) {
	hostPort := r.URL.Host
	if !strings.Contains(hostPort, ":") {
		if r.URL.Scheme == "https" {
			hostPort += ":443"
		} else {
			hostPort += ":80"
		}
	}
	if !p.allow.Allows(hostPort) {
		p.deny(w, hostPort, "host not in task allowlist", "http")
		return
	}
	p.allowN.Add(1)

	outReq := r.Clone(r.Context())
	outReq.RequestURI = ""
	outReq.URL.Scheme = "http"
	outReq.URL.Host = r.URL.Host
	outReq.Host = r.URL.Host
	resp, err := (&http.Transport{
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		ResponseHeaderTimeout: 30 * time.Second,
	}).RoundTrip(outReq)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(resp.Body, 32<<20))
}

// HTTPClient returns an *http.Client whose entire egress goes through the
// proxy at proxyURL (empty proxyURL → the default transport).
func HTTPClient(proxyURL string, timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	tr := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
		ResponseHeaderTimeout: timeout,
	}
	if proxyURL != "" {
		tr.Proxy = http.ProxyURL(mustParse(proxyURL))
	}
	return &http.Client{Transport: tr, Timeout: timeout}
}

func mustParse(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic("evs: bad proxy url " + raw)
	}
	return u
}
