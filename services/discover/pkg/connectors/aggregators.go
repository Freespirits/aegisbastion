package connectors

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// --- RapidDNS (HTML table; doc 02 §8 MVP connector) -------------------------
//
// GET https://rapiddns.io/subdomain/{domain}?full=1 → HTML table rows
// <td>host</td><td>A</td><td>1.2.3.4</td>. No credentials.

const RapidDNSName = "rapiddns"

// NewRapidDNS builds the RapidDNS connector (subdomain_passive).
func NewRapidDNS(fetch Fetcher) Connector {
	return &httpSource{
		name:       RapidDNSName,
		techniques: []model.Technique{model.TechniqueSubdomainPassive, model.TechniquePassiveDNS},
		rate:       RateSpec{RPS: 0.5, Burst: 1, DailyQuota: 0},
		fetch:      fetch,
		buildReq: func(in RunInput, _ string) (*Request, error) {
			return &Request{
				Method: "GET",
				URL:    "https://rapiddns.io/subdomain/" + url.PathEscape(in.Task.Seed.Value) + "?full=1",
			}, nil
		},
		parse: parseRapidDNS,
	}
}

func parseRapidDNS(body []byte, in RunInput) ([]Finding, error) {
	html := string(body)
	apex := in.Task.Seed.Value
	seenHost := map[string]bool{}
	seenIP := map[string]bool{}
	hostIPs := map[string][]string{}

	// Table rows: <tr>…<td>host</td><td>TYPE</td><td>value</td>…</tr>
	rows := strings.Split(html, "<tr")
	for _, row := range rows[1:] {
		cells := extractTDs(row)
		if len(cells) < 3 {
			continue
		}
		host, _, err := model.CanonicalizeDomain(cells[0])
		if err != nil {
			continue
		}
		typ := strings.ToUpper(strings.TrimSpace(cells[1]))
		val := strings.TrimSpace(cells[2])
		switch typ {
		case "A", "AAAA":
			ip, err := model.CanonicalizeIP(val)
			if err != nil {
				continue
			}
			hostIPs[host] = append(hostIPs[host], ip)
			if !seenIP[ip] {
				seenIP[ip] = true
			}
		case "CNAME":
			target, _, err := model.CanonicalizeDomain(val)
			if err != nil {
				continue
			}
			if !seenHost[host] {
				seenHost[host] = true
			}
			hostIPs[host] = hostIPs[host] // ensure host exists in map
			_ = target                    // cname edges handled below
		}
	}

	var out []Finding
	for ip := range seenIP {
		out = append(out, Finding{Asset: model.Asset{Type: model.AssetIP, Value: ip}})
	}
	for host, ips := range hostIPs {
		typ, ok := model.ClassifyDomainAsset(host, apex)
		if !ok {
			typ = model.AssetSubdomain
		}
		var edges []EdgeRef
		for _, ip := range ips {
			edges = append(edges, EdgeRef{
				Rel: model.RelResolvesTo,
				Src: model.Asset{Type: typ, Value: host},
				Dst: model.Asset{Type: model.AssetIP, Value: ip},
			})
		}
		attrs := map[string]any{}
		if len(ips) > 0 {
			attrs["dns"] = ips
		}
		out = append(out, Finding{Asset: model.Asset{Type: typ, Value: host, Attributes: attrs}, Edges: edges})
	}
	return out, nil
}

// extractTDs pulls the text content of each <td> in a table-row fragment.
func extractTDs(row string) []string {
	var cells []string
	rest := row
	for {
		i := strings.Index(rest, "<td")
		if i < 0 {
			break
		}
		j := strings.Index(rest[i:], ">")
		if j < 0 {
			break
		}
		rest = rest[i+j+1:]
		k := strings.Index(rest, "</td>")
		if k < 0 {
			break
		}
		text := rest[:k]
		text = stripTags(text)
		cells = append(cells, strings.TrimSpace(text))
		rest = rest[k+5:]
	}
	return cells
}

func stripTags(s string) string {
	var b strings.Builder
	depth := 0
	for _, r := range s {
		switch r {
		case '<':
			depth++
		case '>':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}

// --- Wayback Machine CDX (doc 02 §8 MVP connector) --------------------------
//
// GET https://web.archive.org/cdx/search/cdx?url=*.example.com/*&output=json
//   &fl=original&collapse=urlkey&limit=10000
// Response: JSON array of arrays; first row is the header. Hosts are
// extracted from the original URLs.

const WaybackName = "wayback"

// NewWayback builds the Wayback CDX connector (subdomain_passive).
func NewWayback(fetch Fetcher) Connector {
	return &httpSource{
		name:       WaybackName,
		techniques: []model.Technique{model.TechniqueSubdomainPassive},
		rate:       RateSpec{RPS: 0.2, Burst: 1, DailyQuota: 0},
		fetch:      fetch,
		buildReq: func(in RunInput, _ string) (*Request, error) {
			u := "https://web.archive.org/cdx/search/cdx?url=" +
				url.QueryEscape("*."+in.Task.Seed.Value+"/*") +
				"&output=json&fl=original&collapse=urlkey&limit=10000"
			return &Request{Method: "GET", URL: u}, nil
		},
		parse: parseWayback,
	}
}

func parseWayback(body []byte, in RunInput) ([]Finding, error) {
	var rows [][]string
	if err := json.Unmarshal(body, &rows); err != nil {
		return nil, fmt.Errorf("wayback: decode: %w", err)
	}
	var hosts []string
	for i, row := range rows {
		if i == 0 || len(row) == 0 {
			continue // header row
		}
		raw := row[0]
		if !strings.Contains(raw, "://") {
			raw = "http://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		host := u.Host
		if strings.Contains(host, ":") {
			host, _, _ = strings.Cut(host, ":")
		}
		hosts = append(hosts, host)
	}
	return hostnameFindings(hosts, in, WaybackName)
}
