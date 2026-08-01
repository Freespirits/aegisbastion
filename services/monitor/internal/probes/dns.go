package probes

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/aegisbastion/aegisbastion/services/monitor/internal/snapshot"
)

// DNSQuorumSize / DNSQuorumMin implement doc 03 §6.1: 3 independent resolvers,
// quorum 2-of-3; the system resolver is NEVER used (corporate-DNS blindness).
const (
	DNSQuorumSize = 3
	DNSQuorumMin  = 2
)

// dnsQueryTypes are the record types probed per doc 03 §6.1.
var dnsQueryTypes = []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeNS}

// DNSQuerier issues one DNS query — injectable for fixture/loopback tests.
type DNSQuerier interface {
	Query(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error)
}

// UDPQuerier is the production querier (plain DNS/53 per doc 03 §10;
// DoH-only was rejected for coverage gaps).
type UDPQuerier struct {
	Client *dns.Client
}

// Query implements DNSQuerier.
func (q UDPQuerier) Query(ctx context.Context, server, name string, qtype uint16) (*dns.Msg, error) {
	c := q.Client
	if c == nil {
		c = &dns.Client{Net: "udp", Timeout: 5 * time.Second}
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), qtype)
	m.RecursionDesired = true
	r, _, err := c.ExchangeContext(ctx, m, server)
	return r, err
}

// DNSProbe resolves A/AAAA/CNAME/MX/TXT/NS through 3 independent resolvers
// with a 2-of-3 quorum, follows the CNAME chain, and detects dangling CNAMEs
// (doc 03 §6.1).
type DNSProbe struct {
	// Resolvers are "host:port" resolver addresses (exactly DNSQuorumSize in
	// production; fixture tests may use one).
	Resolvers []string
	// Querier is the wire implementation (UDPQuerier in production).
	Querier DNSQuerier
	// TakeableServices is the module-owned dangling-CNAME service list
	// (defaults to TakeableServicesV1 when nil).
	TakeableServices []string
	// ResolverSetName labels the observation (default "default-3").
	ResolverSetName string
}

// Type implements Probe.
func (p *DNSProbe) Type() string { return snapshot.ProbeDNS }

// resolverAnswer is one resolver's full answer across query types.
type resolverAnswer struct {
	server   string
	records  map[string][]string
	ttls     map[string]uint32
	chain    []string
	dangling *snapshot.DanglingCNAME
	failed   bool
	nxdomain bool
}

// Probe implements Probe.
func (p *DNSProbe) Probe(ctx context.Context, req Request) (*Result, error) {
	ctx, cancel := context.WithTimeout(ctx, DNSTimeout)
	defer cancel()

	querier := p.Querier
	if querier == nil {
		querier = UDPQuerier{}
	}
	takeable := p.TakeableServices
	if len(takeable) == 0 {
		takeable = TakeableServicesV1
	}
	setName := p.ResolverSetName
	if setName == "" {
		setName = fmt.Sprintf("default-%d", len(p.Resolvers))
	}

	answers := make([]resolverAnswer, 0, len(p.Resolvers))
	for _, server := range p.Resolvers {
		answers = append(answers, p.queryResolver(ctx, querier, server, req.Target, takeable))
	}

	doc := &snapshot.Document{
		AssetID:   req.AssetID,
		MissionID: req.MissionID,
		ProbeType: snapshot.ProbeDNS,
		ProbeTS:   req.Now.UTC(),
		Observer: snapshot.Observer{
			WorkerID: req.WorkerID, ResolverSet: setName,
		},
		Authorization: snapshot.Authorization{TokenJTI: req.TokenJTI, ROEVersion: req.ROEVersion},
	}

	// All resolvers say NXDOMAIN → the name is gone (asset.removed tracking
	// happens at the executor's persistence window, doc 03 §12).
	nx := 0
	failed := 0
	for _, a := range answers {
		if a.nxdomain {
			nx++
		}
		if a.failed {
			failed++
		}
	}
	if nx > 0 && nx+failed == len(answers) {
		doc.Status = snapshot.StatusDNSNXDomain
		doc.Data.DNS = &snapshot.DNSData{Records: map[string][]string{}, Quorum: p.quorum(answers, setName)}
		return &Result{Doc: doc}, nil
	}

	// Quorum: group resolvers by identical record sets; the largest group
	// wins (doc 03 §6.3). No 2-of-3 agreement → inconclusive, no state
	// transition (doc 03 §12 resolver poisoning / split horizon).
	group := largestGroup(answers)
	q := p.quorum(answers, setName)
	if len(answers) >= DNSQuorumMin && len(group) < DNSQuorumMin {
		doc.Status = snapshot.StatusInconclusive
		doc.Data.DNS = &snapshot.DNSData{Records: map[string][]string{}, Quorum: q}
		return &Result{Doc: doc}, nil
	}
	winner := group[0]

	doc.Status = snapshot.StatusOK
	doc.Data.DNS = &snapshot.DNSData{
		Records:    winner.records,
		TTLs:       winner.ttls,
		CNAMEChain: winner.chain,
		Dangling:   winner.dangling,
		Quorum:     q,
	}
	return &Result{Doc: doc}, nil
}

// queryResolver collects one resolver's answers for all query types and the
// CNAME-chain/dangling analysis.
func (p *DNSProbe) queryResolver(ctx context.Context, qr DNSQuerier, server, target string, takeable []string) resolverAnswer {
	out := resolverAnswer{server: server, records: map[string][]string{}, ttls: map[string]uint32{}}
	anySuccess := false
	for _, qt := range dnsQueryTypes {
		msg, err := qr.Query(ctx, server, target, qt)
		if err != nil {
			continue
		}
		anySuccess = true
		if msg.Rcode == dns.RcodeNameError {
			out.nxdomain = true
			continue
		}
		if msg.Rcode != dns.RcodeSuccess {
			continue
		}
		rt := dns.TypeToString[qt]
		for _, rr := range msg.Answer {
			v, ok := recordValue(rr)
			if !ok {
				continue
			}
			out.records[rt] = append(out.records[rt], v)
			if ttl := rr.Header().Ttl; out.ttls[rt] == 0 || ttl < out.ttls[rt] {
				out.ttls[rt] = ttl
			}
		}
	}
	if !anySuccess {
		out.failed = true
		return out
	}
	for rt := range out.records {
		sort.Strings(out.records[rt])
		out.records[rt] = dedupStrings(out.records[rt])
	}

	// CNAME chain walk + dangling detection (target NXDOMAIN per §6.1).
	out.chain, out.dangling = p.followChain(ctx, qr, server, target, takeable)
	return out
}

// followChain walks CNAMEs (max 10 hops) and checks the terminal target for
// NXDOMAIN → dangling; takeable when the target matches the service list.
func (p *DNSProbe) followChain(ctx context.Context, qr DNSQuerier, server, target string, takeable []string) ([]string, *snapshot.DanglingCNAME) {
	var chain []string
	current := target
	for i := 0; i < 10; i++ {
		msg, err := qr.Query(ctx, server, current, dns.TypeCNAME)
		if err != nil || msg == nil || msg.Rcode != dns.RcodeSuccess {
			return chain, nil
		}
		var next string
		for _, rr := range msg.Answer {
			if cn, ok := rr.(*dns.CNAME); ok {
				next = strings.TrimSuffix(strings.ToLower(cn.Target), ".")
				break
			}
		}
		if next == "" || next == current {
			break // chain ended — check the terminal for dangling below
		}
		chain = append(chain, next)
		current = next
	}
	if len(chain) == 0 {
		return nil, nil
	}
	// Terminal target: NXDOMAIN on both A and AAAA → dangling (§6.1).
	terminal := chain[len(chain)-1]
	aMsg, aErr := qr.Query(ctx, server, terminal, dns.TypeA)
	aaaaMsg, aaaaErr := qr.Query(ctx, server, terminal, dns.TypeAAAA)
	aNX := aErr == nil && aMsg != nil && aMsg.Rcode == dns.RcodeNameError
	aaaaNX := aaaaErr == nil && aaaaMsg != nil && aaaaMsg.Rcode == dns.RcodeNameError
	if !aNX || !aaaaNX {
		return chain, nil
	}
	d := &snapshot.DanglingCNAME{Target: terminal, Reason: "CNAME target NXDOMAIN"}
	if svc := matchTakeable(terminal, takeable); svc != "" {
		d.TakeableService = svc
		d.Reason = "CNAME target NXDOMAIN and matches takeable service " + svc
	}
	return chain, d
}

// quorum summarizes resolver agreement.
func (p *DNSProbe) quorum(answers []resolverAnswer, setName string) snapshot.Quorum {
	q := snapshot.Quorum{ResolverSet: setName, Resolvers: len(answers)}
	group := largestGroup(answers)
	if len(group) > 0 {
		q.Agreeing = len(group)
		in := map[string]bool{}
		for _, a := range group {
			in[a.server] = true
		}
		for _, a := range answers {
			if !in[a.server] && !a.failed {
				q.Disagreed = append(q.Disagreed, a.server)
			}
		}
	}
	return q
}

// largestGroup buckets answers by canonical record-set signature and returns
// the biggest bucket (failed resolvers excluded).
func largestGroup(answers []resolverAnswer) []resolverAnswer {
	buckets := map[string][]resolverAnswer{}
	var best string
	for _, a := range answers {
		if a.failed || a.nxdomain {
			continue
		}
		sig := answerSignature(a.records)
		buckets[sig] = append(buckets[sig], a)
		if len(buckets[sig]) > len(buckets[best]) {
			best = sig
		}
	}
	return buckets[best]
}

// answerSignature renders record sets canonically for quorum comparison
// (TTL-insensitive, doc 03 §6.3).
func answerSignature(records map[string][]string) string {
	types := make([]string, 0, len(records))
	for rt, vals := range records {
		if len(vals) > 0 {
			types = append(types, rt)
		}
	}
	sort.Strings(types)
	var b strings.Builder
	for _, rt := range types {
		b.WriteString(rt)
		b.WriteByte('=')
		b.WriteString(strings.Join(records[rt], ","))
		b.WriteByte(';')
	}
	return b.String()
}

// recordValue extracts the comparison value of an answer RR.
func recordValue(rr dns.RR) (string, bool) {
	switch v := rr.(type) {
	case *dns.A:
		return v.A.String(), true
	case *dns.AAAA:
		return v.AAAA.String(), true
	case *dns.CNAME:
		return strings.TrimSuffix(strings.ToLower(v.Target), "."), true
	case *dns.MX:
		return fmt.Sprintf("%d %s", v.Preference, strings.TrimSuffix(strings.ToLower(v.Mx), ".")), true
	case *dns.TXT:
		return strings.Join(v.Txt, ""), true
	case *dns.NS:
		return strings.TrimSuffix(strings.ToLower(v.Ns), "."), true
	}
	return "", false
}

// matchTakeable returns the takeable-service suffix the target matches.
func matchTakeable(target string, services []string) string {
	for _, svc := range services {
		if target == svc || strings.HasSuffix(target, "."+svc) {
			return svc
		}
	}
	return ""
}

func dedupStrings(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, v := range in {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

// TakeableServicesV1 is the module-owned known-takeable-service list v1
// (doc 03 §7.2: Azure Traffic Manager, S3, GH Pages, Heroku, …).
var TakeableServicesV1 = []string{
	"azuretrafficmanager.net",
	"trafficmanager.net",
	"cloudapp.net",
	"azurewebsites.net",
	"blob.core.windows.net",
	"s3.amazonaws.com",
	"s3-website-us-east-1.amazonaws.com",
	"github.io",
	"herokuapp.com",
	"herokudns.com",
	"unbouncepages.com",
	"surge.sh",
	"bitbucket.io",
	"pantheonsite.io",
	"myshopify.com",
	"ghost.io",
	"readme.io",
	"zendesk.com",
	"helpscoutdocs.com",
	"ngrok.io",
	"webflow.io",
	"wordpress.com",
	"tumblr.com",
	"fly.io",
	"netlify.app",
	"vercel.app",
}
