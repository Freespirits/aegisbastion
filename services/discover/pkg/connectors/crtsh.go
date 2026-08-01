package connectors

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// --- crt.sh (CT log search; doc 02 §8 MVP connector) -----------------------
//
// GET https://crt.sh/?q=%25.example.com&output=json
// Response: array of cert entries; name_value holds the SANs (newline
// separated). We yield hostname findings; cert assets come from sources that
// expose a real sha256 fingerprint (censys_ct), keeping doc 02 §4.2's
// "certs keyed by SHA-256 of DER" honest.

const CrtSHName = "crt.sh"

type crtshEntry struct {
	ID         int64  `json:"id"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
	Serial     string `json:"serial_number"`
}

// NewCrtSH builds the crt.sh connector.
func NewCrtSH(fetch Fetcher) Connector {
	return &httpSource{
		name:       CrtSHName,
		techniques: []model.Technique{model.TechniqueCT},
		rate:       RateSpec{RPS: 0.5, Burst: 2, DailyQuota: 0},
		fetch:      fetch,
		buildReq: func(in RunInput, _ string) (*Request, error) {
			q := url.QueryEscape("%." + in.Task.Seed.Value)
			return &Request{
				Method: "GET",
				URL:    "https://crt.sh/?q=" + q + "&output=json",
			}, nil
		},
		parse: parseCrtSH,
	}
}

func parseCrtSH(body []byte, in RunInput) ([]Finding, error) {
	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("crt.sh: decode: %w", err)
	}
	apex := in.Task.Seed.Value
	seen := map[string]int{}
	var out []Finding
	wildcardBases := map[string][]int64{}
	for _, e := range entries {
		names := strings.Split(e.NameValue, "\n")
		for _, raw := range names {
			host, wildcard, err := model.CanonicalizeDomain(raw)
			if err != nil {
				continue // unparsable SAN — skip, not an error
			}
			if _, dup := seen[host]; dup {
				continue
			}
			typ, ok := model.ClassifyDomainAsset(host, apex)
			if !ok {
				// Out-of-scope SANs (e.g. shared cert names) are still
				// emitted — the REDUCER owns the scope decision and
				// quarantine (doc 02 §2.3 step 3); connectors report what
				// the source said.
				typ = model.AssetSubdomain
			}
			seen[host] = 1
			attrs := map[string]any{
				"crtsh_cert_ids": []int64{e.ID},
			}
			if e.NotAfter != "" {
				attrs["cert"] = map[string]any{"not_after": e.NotAfter}
			}
			if wildcard {
				wildcardBases[host] = append(wildcardBases[host], e.ID)
				continue // the wildcard marker is an attribute, not an asset
			}
			out = append(out, Finding{Asset: model.Asset{Type: typ, Value: host, Attributes: attrs}})
		}
	}
	// Wildcards: recorded as wildcard:true on the base domain (doc 02 §4.2);
	// the planner stops recursion under these (doc 02 §2.4).
	for base, ids := range wildcardBases {
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		out = append(out, Finding{Asset: model.Asset{
			Type:  model.AssetDomain,
			Value: base,
			Attributes: map[string]any{
				"wildcard":       true,
				"crtsh_cert_ids": ids,
			},
		}})
	}
	return out, nil
}
