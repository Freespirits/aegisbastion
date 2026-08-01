package connectors

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// --- Censys CT (certificates search; doc 02 §8 MVP connector) --------------
//
// POST https://search.censys.io/api/v2/certificates/search
//   {"q": "names: example.com", "per_page": 100}
// Basic auth with API id:secret (single "api key" string stored as
// "id:secret"). Yields hostname findings AND cert assets keyed by the
// sha256 fingerprint (doc 02 §4.2), with san_of edges cert → host.

const CensysCTName = "censys_ct"

type censysSearchResponse struct {
	Result struct {
		Hits []struct {
			Names             []string `json:"names"`
			FingerprintSHA256 string   `json:"fingerprint_sha256"`
			Parsed            struct {
				SubjectCommonName string `json:"subject_common_name"`
				ValidityPeriod    struct {
					NotAfter string `json:"not_after"`
				} `json:"validity_period"`
			} `json:"parsed"`
		} `json:"hits"`
	} `json:"result"`
}

// NewCensysCT builds the Censys certificate-search connector.
func NewCensysCT(fetch Fetcher, keys KeyProvider) Connector {
	return &httpSource{
		name:          CensysCTName,
		techniques:    []model.Technique{model.TechniqueCT},
		rate:          RateSpec{RPS: 0.4, Burst: 1, DailyQuota: 250},
		requiresCreds: true,
		fetch:         fetch,
		keys:          keys,
		buildReq: func(in RunInput, apiKey string) (*Request, error) {
			return &Request{
				Method: "POST",
				URL:    "https://search.censys.io/api/v2/certificates/search",
				Headers: map[string]string{
					"Content-Type":  "application/json",
					"Authorization": "Basic " + base64.StdEncoding.EncodeToString([]byte(apiKey)),
				},
				Body: fmt.Sprintf(`{"q":%q,"per_page":100}`, "names: "+in.Task.Seed.Value),
			}, nil
		},
		parse: parseCensysCT,
	}
}

func parseCensysCT(body []byte, in RunInput) ([]Finding, error) {
	var resp censysSearchResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("censys_ct: decode: %w", err)
	}
	apex := in.Task.Seed.Value
	seenHost := map[string]bool{}
	seenCert := map[string]bool{}
	var out []Finding
	for _, hit := range resp.Result.Hits {
		fp := strings.ToLower(hit.FingerprintSHA256)
		var sans []string
		for _, raw := range hit.Names {
			host, wildcard, err := model.CanonicalizeDomain(raw)
			if err != nil {
				continue
			}
			sans = append(sans, host)
			if wildcard || seenHost[host] {
				continue
			}
			seenHost[host] = true
			typ, ok := model.ClassifyDomainAsset(host, apex)
			if !ok {
				typ = model.AssetSubdomain // reducer owns scope/quarantine
			}
			var edges []EdgeRef
			if fp != "" {
				edges = append(edges, EdgeRef{
					Rel: model.RelSANOf,
					Src: model.Asset{Type: model.AssetSubdomain, Value: host},
					Dst: model.Asset{Type: model.AssetCert, Value: fp},
				})
			}
			out = append(out, Finding{Asset: model.Asset{Type: typ, Value: host}, Edges: edges})
		}
		if fp == "" || seenCert[fp] {
			continue
		}
		seenCert[fp] = true
		attrs := map[string]any{
			"cert": map[string]any{
				"sans":       sans,
				"not_after":  hit.Parsed.ValidityPeriod.NotAfter,
				"subject_cn": hit.Parsed.SubjectCommonName,
			},
		}
		out = append(out, Finding{Asset: model.Asset{Type: model.AssetCert, Value: fp, Attributes: attrs}})
	}
	return out, nil
}

// --- passive aggregators ---------------------------------------------------

// vtSubdomainsResponse is VirusTotal's /api/v3/domains/{d}/subdomains.
type vtSubdomainsResponse struct {
	Data []struct {
		ID string `json:"id"`
	} `json:"data"`
	Meta struct {
		Cursor string `json:"cursor"`
	} `json:"meta"`
}

// VirusTotalName is the connector id.
const VirusTotalName = "virustotal"

// NewVirusTotal builds the VirusTotal subdomains connector (passive_dns).
func NewVirusTotal(fetch Fetcher, keys KeyProvider) Connector {
	return &httpSource{
		name:          VirusTotalName,
		techniques:    []model.Technique{model.TechniquePassiveDNS, model.TechniqueSubdomainPassive},
		rate:          RateSpec{RPS: 0.25, Burst: 1, DailyQuota: 500},
		requiresCreds: true,
		fetch:         fetch,
		keys:          keys,
		buildReq: func(in RunInput, apiKey string) (*Request, error) {
			return &Request{
				Method: "GET",
				URL:    "https://www.virustotal.com/api/v3/domains/" + url.PathEscape(in.Task.Seed.Value) + "/subdomains?limit=40",
				Headers: map[string]string{
					"x-apikey": apiKey,
				},
			}, nil
		},
		parse: parseHostnameList(func(body []byte) ([]string, error) {
			var r vtSubdomainsResponse
			if err := json.Unmarshal(body, &r); err != nil {
				return nil, err
			}
			var hosts []string
			for _, d := range r.Data {
				hosts = append(hosts, d.ID)
			}
			return hosts, nil
		}, "virustotal"),
	}
}

// SecurityTrailsName is the connector id.
const SecurityTrailsName = "securitytrails"

// NewSecurityTrails builds the SecurityTrails subdomains connector
// (passive_dns). Response carries RELATIVE labels — joined with the apex.
func NewSecurityTrails(fetch Fetcher, keys KeyProvider) Connector {
	return &httpSource{
		name:          SecurityTrailsName,
		techniques:    []model.Technique{model.TechniquePassiveDNS, model.TechniqueSubdomainPassive},
		rate:          RateSpec{RPS: 1, Burst: 2, DailyQuota: 2000},
		requiresCreds: true,
		fetch:         fetch,
		keys:          keys,
		buildReq: func(in RunInput, apiKey string) (*Request, error) {
			return &Request{
				Method: "GET",
				URL:    "https://api.securitytrails.com/v1/domain/" + url.PathEscape(in.Task.Seed.Value) + "/subdomains?children_only=false",
				Headers: map[string]string{
					"APIKEY": apiKey,
				},
			}, nil
		},
		parse: func(body []byte, in RunInput) ([]Finding, error) {
			var r struct {
				Subdomains []string `json:"subdomains"`
			}
			if err := json.Unmarshal(body, &r); err != nil {
				return nil, fmt.Errorf("securitytrails: decode: %w", err)
			}
			hosts := make([]string, 0, len(r.Subdomains))
			for _, label := range r.Subdomains {
				label = strings.TrimSpace(label)
				if label == "" {
					continue
				}
				hosts = append(hosts, label+"."+in.Task.Seed.Value)
			}
			return hostnameFindings(hosts, in, SecurityTrailsName)
		},
	}
}

// ShodanName is the connector id (DNS domain data).
const ShodanName = "shodan_dns"

// NewShodan builds the Shodan DNS-domain connector (passive_dns).
func NewShodan(fetch Fetcher, keys KeyProvider) Connector {
	return &httpSource{
		name:          ShodanName,
		techniques:    []model.Technique{model.TechniquePassiveDNS},
		rate:          RateSpec{RPS: 1, Burst: 1, DailyQuota: 0},
		requiresCreds: true,
		fetch:         fetch,
		keys:          keys,
		buildReq: func(in RunInput, apiKey string) (*Request, error) {
			return &Request{
				Method: "GET",
				URL:    "https://api.shodan.io/dns/domain/" + url.PathEscape(in.Task.Seed.Value) + "?key=" + url.QueryEscape(apiKey),
			}, nil
		},
		parse: parseShodanDNS,
	}
}

func parseShodanDNS(body []byte, in RunInput) ([]Finding, error) {
	var r struct {
		Domain string `json:"domain"`
		Data   []struct {
			Subdomain string `json:"subdomain"`
			Type      string `json:"type"`
			Value     string `json:"value"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("shodan_dns: decode: %w", err)
	}
	apex := in.Task.Seed.Value
	seenHost := map[string]bool{}
	seenIP := map[string]bool{}
	var out []Finding
	hostRecordIPs := map[string][]string{}
	for _, d := range r.Data {
		host, _, err := model.CanonicalizeDomain(d.Subdomain + "." + apex)
		if err != nil {
			continue
		}
		switch strings.ToUpper(d.Type) {
		case "A", "AAAA":
			ip, err := model.CanonicalizeIP(d.Value)
			if err != nil {
				continue
			}
			hostRecordIPs[host] = append(hostRecordIPs[host], ip)
			if !seenIP[ip] {
				seenIP[ip] = true
				out = append(out, Finding{Asset: model.Asset{Type: model.AssetIP, Value: ip}})
			}
		}
	}
	for host, ips := range hostRecordIPs {
		if seenHost[host] {
			continue
		}
		seenHost[host] = true
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
		out = append(out, Finding{
			Asset: model.Asset{Type: typ, Value: host, Attributes: map[string]any{"dns": ips}},
			Edges: edges,
		})
	}
	return out, nil
}

// parseHostnameList adapts a simple JSON → hostnames decoder into a
// ParseFunc (dedup + classify + wildcard handling).
func parseHostnameList(decode func(body []byte) ([]string, error), source string) ParseFunc {
	return func(body []byte, in RunInput) ([]Finding, error) {
		hosts, err := decode(body)
		if err != nil {
			return nil, fmt.Errorf("%s: decode: %w", source, err)
		}
		return hostnameFindings(hosts, in, source)
	}
}

// hostnameFindings canonicalizes raw hostnames into subdomain/domain
// findings (dedup; wildcards become attributes on the base, doc 02 §4.2;
// out-of-scope names are still emitted — the reducer quarantines).
func hostnameFindings(hosts []string, in RunInput, source string) ([]Finding, error) {
	apex := in.Task.Seed.Value
	seen := map[string]bool{}
	var out []Finding
	for _, raw := range hosts {
		host, wildcard, err := model.CanonicalizeDomain(raw)
		if err != nil || seen[host] {
			continue
		}
		seen[host] = true
		if wildcard {
			out = append(out, Finding{Asset: model.Asset{
				Type:       model.AssetDomain,
				Value:      host,
				Attributes: map[string]any{"wildcard": true},
			}})
			continue
		}
		typ, ok := model.ClassifyDomainAsset(host, apex)
		if !ok {
			typ = model.AssetSubdomain
		}
		out = append(out, Finding{Asset: model.Asset{Type: typ, Value: host}})
	}
	return out, nil
}
