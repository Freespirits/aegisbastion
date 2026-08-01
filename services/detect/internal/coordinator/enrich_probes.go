package coordinator

import (
	"context"
	"net/http"
	"strings"

	"github.com/aegisbastion/aegisbastion/services/detect/internal/ave"
)

// probeTLS re-handshakes independently of any scanner (doc 04 §6 TLS
// validator strategy) and returns the offered profile, or nil when the
// target is not TLS.
func probeTLS(ctx context.Context, tools *ave.Tools, target string) (*ave.TLSProfile, error) {
	prober := ave.TLSProber(ave.DefaultTLSProber{})
	if tools != nil && tools.TLS != nil {
		prober = tools.TLS
	}
	hostPort := hostOf(target)
	if hostPort == "" {
		return nil, nil
	}
	if !strings.Contains(hostPort, ":") {
		if strings.HasPrefix(target, "https://") || !strings.Contains(target, "://") {
			hostPort += ":443"
		} else {
			return nil, nil // plain http — no TLS surface
		}
	}
	return prober.ProbeVersions(ctx, hostPort)
}

// probeBanner fetches the target once and reports the Server / X-Powered-By
// banners (light-touch fingerprint, R1).
func probeBanner(ctx context.Context, tools *ave.Tools, target string) (server, xPoweredBy string) {
	if tools == nil || tools.HTTP == nil {
		return "", ""
	}
	url := target
	if !strings.Contains(url, "://") {
		url = "https://" + url
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", ""
	}
	resp, err := tools.HTTP.Do(req)
	if err != nil {
		return "", ""
	}
	defer resp.Body.Close()
	return resp.Header.Get("Server"), resp.Header.Get("X-Powered-By")
}
