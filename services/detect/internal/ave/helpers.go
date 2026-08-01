package ave

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// maxBodyRead bounds how much of a response body validators consume
// (non-destructive, memory-safe re-verification).
const maxBodyRead = 256 << 10

// doExchange performs one HTTP request through the scoped client and records
// a transcript exchange. The scoped client's transport enforces the per-request
// scope guard + egress proxy + rate caps (doc 04 §10.1).
func doExchange(ctx context.Context, tools *Tools, tr *Transcript, label, method, url, body string, headers map[string]string) (*http.Response, []byte, error) {
	if tools == nil || tools.HTTP == nil {
		return nil, nil, fmt.Errorf("ave: no scoped HTTP client")
	}
	var rdr io.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return nil, nil, fmt.Errorf("ave: build request: %w", err)
	}
	req.Header.Set("User-Agent", "aegisbastion-ave/"+Version)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	start := time.Now()
	resp, err := tools.HTTP.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyRead))
	if err != nil {
		return nil, nil, fmt.Errorf("ave: read response: %w", err)
	}
	if tr != nil {
		tr.Exchanges = append(tr.Exchanges, Exchange{
			Label:    label,
			Method:   method,
			URL:      url,
			Status:   resp.StatusCode,
			Request:  truncate(requestSummary(req), 2048),
			Response: truncate(responseSummary(resp, data), 4096),
			Duration: time.Since(start).Round(time.Millisecond).String(),
		})
	}
	return resp, data, nil
}

// requestSummary renders a sanitized request head for the transcript.
func requestSummary(req *http.Request) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\nHost: %s\r\n", req.Method, req.URL.RequestURI(), req.URL.Host)
	for k, v := range req.Header {
		fmt.Fprintf(&b, "%s: %s\r\n", k, strings.Join(v, ","))
	}
	return b.String()
}

// responseSummary renders a sanitized response head + body prefix.
func responseSummary(resp *http.Response, body []byte) string {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", resp.StatusCode, http.StatusText(resp.StatusCode))
	for k, v := range resp.Header {
		fmt.Fprintf(&b, "%s: %s\r\n", k, strings.Join(v, ","))
	}
	b.WriteString("\r\n")
	b.Write(body)
	return b.String()
}

// baseTarget picks the URL a validator probes: the scanner's concrete match
// when present, else the job target.
func baseTarget(cand Candidate) string {
	if cand.MatchedAt != "" {
		return cand.MatchedAt
	}
	return cand.Target
}

// hostPort extracts host:port from a URL-ish target for TLS probing.
func hostPort(target string) string {
	t := target
	t = strings.TrimPrefix(t, "https://")
	t = strings.TrimPrefix(t, "http://")
	if i := strings.IndexByte(t, '/'); i >= 0 {
		t = t[:i]
	}
	if !strings.Contains(t, ":") {
		t += ":443"
	}
	return t
}
