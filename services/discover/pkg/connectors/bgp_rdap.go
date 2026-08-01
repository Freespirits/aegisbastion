package connectors

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// --- BGPView (ASN → announced prefixes; doc 02 §8 MVP connector) ------------
//
// GET https://api.bgpview.io/asn/{asn}/prefixes
// → {data:{ipv4_prefixes:[{prefix}], ipv6_prefixes:[{prefix}]}}.

const BGPViewName = "bgpview"

// NewBGPView builds the BGPView connector (ip_netblock).
func NewBGPView(fetch Fetcher) Connector {
	return &httpSource{
		name:       BGPViewName,
		techniques: []model.Technique{model.TechniqueIPNetblock},
		rate:       RateSpec{RPS: 1, Burst: 2, DailyQuota: 0},
		fetch:      fetch,
		buildReq: func(in RunInput, _ string) (*Request, error) {
			asn, err := model.CanonicalizeASN(in.Task.Seed.Value)
			if err != nil {
				return nil, err
			}
			return &Request{
				Method: "GET",
				URL:    "https://api.bgpview.io/asn/" + url.PathEscape(strings.TrimPrefix(asn, "AS")) + "/prefixes",
			}, nil
		},
		parse: parseBGPView,
	}
}

func parseBGPView(body []byte, in RunInput) ([]Finding, error) {
	var r struct {
		Data struct {
			IPv4 []struct {
				Prefix string `json:"prefix"`
				Name   string `json:"name"`
			} `json:"ipv4_prefixes"`
			IPv6 []struct {
				Prefix string `json:"prefix"`
				Name   string `json:"name"`
			} `json:"ipv6_prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("bgpview: decode: %w", err)
	}
	asn, _ := model.CanonicalizeASN(in.Task.Seed.Value)
	seen := map[string]bool{}
	var out []Finding
	add := func(prefix, name string) {
		cidr, err := model.CanonicalizeCIDR(prefix)
		if err != nil || seen[cidr] {
			return
		}
		seen[cidr] = true
		attrs := map[string]any{"asn": asn}
		if name != "" {
			attrs["org_name"] = name
		}
		out = append(out, Finding{Asset: model.Asset{Type: model.AssetNetblock, Value: cidr, Attributes: attrs}})
	}
	for _, p := range r.Data.IPv4 {
		add(p.Prefix, p.Name)
	}
	for _, p := range r.Data.IPv6 {
		add(p.Prefix, p.Name)
	}
	return out, nil
}

// --- RIPEstat (ASN → announced prefixes; doc 02 §8 MVP connector) -----------
//
// GET https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS64500

const RIPEstatName = "ripestat"

// NewRIPEstat builds the RIPEstat connector (ip_netblock).
func NewRIPEstat(fetch Fetcher) Connector {
	return &httpSource{
		name:       RIPEstatName,
		techniques: []model.Technique{model.TechniqueIPNetblock},
		rate:       RateSpec{RPS: 1, Burst: 2, DailyQuota: 0},
		fetch:      fetch,
		buildReq: func(in RunInput, _ string) (*Request, error) {
			asn, err := model.CanonicalizeASN(in.Task.Seed.Value)
			if err != nil {
				return nil, err
			}
			return &Request{
				Method: "GET",
				URL:    "https://stat.ripe.net/data/announced-prefixes/data.json?resource=" + url.QueryEscape(asn),
			}, nil
		},
		parse: parseRIPEstat,
	}
}

func parseRIPEstat(body []byte, in RunInput) ([]Finding, error) {
	var r struct {
		Data struct {
			Prefixes []struct {
				Prefix string `json:"prefix"`
			} `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("ripestat: decode: %w", err)
	}
	asn, _ := model.CanonicalizeASN(in.Task.Seed.Value)
	seen := map[string]bool{}
	var out []Finding
	for _, p := range r.Data.Prefixes {
		cidr, err := model.CanonicalizeCIDR(p.Prefix)
		if err != nil || seen[cidr] {
			continue
		}
		seen[cidr] = true
		out = append(out, Finding{Asset: model.Asset{
			Type:       model.AssetNetblock,
			Value:      cidr,
			Attributes: map[string]any{"asn": asn},
		}})
	}
	return out, nil
}

// --- RDAP (domain + ip registration data; doc 02 §8 MVP connector) ----------
//
// Domain: GET https://rdap.verisign.com/com/v1/domain/{domain} (com/net).
// IP:     GET https://rdap.arin.net/registry/ip/{ip} → netblock CIDRs.
// Base URLs are configurable for tests/offline replay.

const RDAPName = "rdap"

// NewRDAP builds the RDAP connector (ip_netblock; domain registration data
// rides on the seed domain's attributes).
func NewRDAP(fetch Fetcher, domainBaseURL, ipBaseURL string) Connector {
	if domainBaseURL == "" {
		domainBaseURL = "https://rdap.verisign.com/com/v1/domain/"
	}
	if ipBaseURL == "" {
		ipBaseURL = "https://rdap.arin.net/registry/ip/"
	}
	return &httpSource{
		name:       RDAPName,
		techniques: []model.Technique{model.TechniqueIPNetblock},
		rate:       RateSpec{RPS: 1, Burst: 1, DailyQuota: 0},
		fetch:      fetch,
		buildReq: func(in RunInput, _ string) (*Request, error) {
			switch in.Task.Seed.Type {
			case model.SeedDomain:
				return &Request{Method: "GET", URL: domainBaseURL + url.PathEscape(in.Task.Seed.Value)}, nil
			case model.SeedCIDR:
				// Query the network address of the block.
				addr, _, _ := strings.Cut(in.Task.Seed.Value, "/")
				return &Request{Method: "GET", URL: ipBaseURL + url.PathEscape(addr)}, nil
			default:
				return nil, fmt.Errorf("rdap: unsupported seed type %q", in.Task.Seed.Type)
			}
		},
		parse: parseRDAP,
	}
}

func parseRDAP(body []byte, in RunInput) ([]Finding, error) {
	var r struct {
		ObjectClassName string `json:"objectClassName"`
		Handle          string `json:"handle"`
		Name            string `json:"name"`
		StartAddress    string `json:"startAddress"`
		EndAddress      string `json:"endAddress"`
		CIDR0           []struct {
			V4Prefix string `json:"v4prefix"`
			V6Prefix string `json:"v6prefix"`
			Length   int    `json:"length"`
		} `json:"cidr0_cidrs"`
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
		Entities []struct {
			Roles []string `json:"roles"`
		} `json:"entities"`
		Nameservers []struct {
			LdahName string `json:"ldhName"`
		} `json:"nameservers"`
		Status []string `json:"status"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, fmt.Errorf("rdap: decode: %w", err)
	}
	switch r.ObjectClassName {
	case "domain":
		host, _, err := model.CanonicalizeDomain(r.Handle)
		if err != nil || host == "" {
			host = in.Task.Seed.Value
		}
		var ns []string
		for _, n := range r.Nameservers {
			if h, _, err := model.CanonicalizeDomain(n.LdahName); err == nil {
				ns = append(ns, h)
			}
		}
		attrs := map[string]any{
			"rdap": map[string]any{
				"status":      r.Status,
				"nameservers": ns,
				"events":      r.Events,
			},
		}
		return []Finding{{Asset: model.Asset{Type: model.AssetDomain, Value: host, Attributes: attrs}}}, nil
	case "ip network":
		var out []Finding
		for _, c := range r.CIDR0 {
			prefix := c.V4Prefix
			if prefix == "" {
				prefix = c.V6Prefix
			}
			cidr, err := model.CanonicalizeCIDR(fmt.Sprintf("%s/%d", prefix, c.Length))
			if err != nil {
				continue
			}
			out = append(out, Finding{Asset: model.Asset{
				Type:  model.AssetNetblock,
				Value: cidr,
				Attributes: map[string]any{
					"org_name": r.Name,
					"handle":   r.Handle,
				},
			}})
		}
		if len(out) == 0 && r.StartAddress != "" && r.EndAddress != "" {
			// No cidr0_cidrs — record the range as attributes of a netblock
			// keyed by the start address (marked non-canonical range).
			start, err1 := model.CanonicalizeIP(r.StartAddress)
			end, err2 := model.CanonicalizeIP(r.EndAddress)
			if err1 == nil && err2 == nil {
				out = append(out, Finding{Asset: model.Asset{
					Type:  model.AssetNetblock,
					Value: start,
					Attributes: map[string]any{
						"org_name":   r.Name,
						"handle":     r.Handle,
						"range_end":  end,
						"range_form": true,
					},
				}})
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("rdap: unsupported objectClassName %q", r.ObjectClassName)
}
