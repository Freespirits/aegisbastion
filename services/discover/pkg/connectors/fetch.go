package connectors

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/netguard"
)

// HTTPFetcher is the live Fetcher: a netguard-guarded HTTP client (doc 02
// §6.3). It fails closed on non-2xx responses.
type HTTPFetcher struct {
	Client    *http.Client
	UserAgent string
}

// NewHTTPFetcher builds the live fetcher over a netguard Guard.
func NewHTTPFetcher(g *netguard.Guard) *HTTPFetcher {
	return &HTTPFetcher{
		Client:    g.HTTPClient(30 * time.Second),
		UserAgent: "aegisbastion-discover/0.1 (EASM passive collector; +https://aegisbastion.local/discover)",
	}
}

// Fetch implements Fetcher.
func (f *HTTPFetcher) Fetch(ctx context.Context, req *Request) ([]byte, error) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	var body io.Reader
	if req.Body != "" {
		body = strings.NewReader(req.Body)
	}
	hreq, err := http.NewRequestWithContext(ctx, method, req.URL, body)
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	for k, v := range req.Headers {
		hreq.Header.Set(k, v)
	}
	if hreq.Header.Get("User-Agent") == "" {
		hreq.Header.Set("User-Agent", f.UserAgent)
	}
	resp, err := f.Client.Do(hreq)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", req.URL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", req.URL, err)
	}
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, ErrNotFound
	case resp.StatusCode == http.StatusTooManyRequests:
		return nil, fmt.Errorf("%w: %s returned 429", ErrSourceUnavailable, req.URL)
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return nil, fmt.Errorf("source %s: status %d: %s", req.URL, resp.StatusCode, truncate(string(data), 200))
	}
	return data, nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// FixtureFetcher replays recorded source responses (offline mode + tests).
// Keys are connector source names; each entry is the recorded body for that
// source's seed query. Missing keys fail like an unreachable source.
type FixtureFetcher struct {
	Bodies map[string][]byte
}

// NewFixtureFetcher replays from a map.
func NewFixtureFetcher(bodies map[string][]byte) *FixtureFetcher {
	return &FixtureFetcher{Bodies: bodies}
}

// FixtureFetcherFromDir loads one recorded body per *.json / *.html / *.txt
// file in dir, keyed by filename without extension (the connector source
// name). Missing files simply produce no data for that source.
func FixtureFetcherFromDir(dir string) (*FixtureFetcher, error) {
	f := &FixtureFetcher{Bodies: map[string][]byte{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("fixtures dir %s: %w", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := filepath.Ext(name)
		if ext != ".json" && ext != ".html" && ext != ".txt" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		f.Bodies[strings.TrimSuffix(name, ext)] = data
	}
	return f, nil
}

// ForSource returns a Fetcher bound to one source (what a connector sees).
func (f *FixtureFetcher) ForSource(source string) Fetcher {
	return FetcherFunc(func(_ context.Context, req *Request) ([]byte, error) {
		body, ok := f.Bodies[source]
		if !ok {
			return nil, fmt.Errorf("%w: no fixture recorded for source %q", ErrSourceUnavailable, source)
		}
		if len(body) == 0 {
			return nil, ErrNotFound
		}
		_ = req
		return body, nil
	})
}
