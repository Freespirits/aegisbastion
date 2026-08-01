package scanner

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Nmap wraps Nmap 7.9x + NSE for port/service detection and `vuln`-category
// scripts (doc 04 §9). Safe scripts only — the `dos` and `intrusive` NSE
// categories are blocked at the wrapper (doc 04 §10.3).
type Nmap struct {
	// Bin is the nmap binary path (exec mode).
	Bin string
	// FixtureDir maps job.FixtureFile → canned XML output (fixture mode).
	FixtureDir string
	// Timeout bounds one scanner run.
	Timeout time.Duration

	mu     sync.Mutex
	active []*exec.Cmd
}

// NewNmap builds the adapter. fixtureDir non-empty selects fixture mode.
func NewNmap(bin, fixtureDir string) *Nmap {
	return &Nmap{Bin: bin, FixtureDir: fixtureDir, Timeout: 60 * time.Minute}
}

// defaultNmapFixture is used when the job names no fixture.
const defaultNmapFixture = "nmap-basic.xml"

// Name implements Adapter.
func (n *Nmap) Name() string { return AdapterNmap }

// Capabilities implements Adapter.
func (n *Nmap) Capabilities() Capabilities {
	return Capabilities{ChecksSupported: []string{"nmap-nse:vuln", "nmap-nse:ssl*", "nmap-nse:banner"}, SafeModeSupported: true}
}

// ValidateJob implements Adapter — refuses DoS-class scripts and categories.
func (n *Nmap) ValidateJob(job Job) error {
	if err := RejectDoS(job.Checks); err != nil {
		return err
	}
	for _, c := range job.Checks {
		lc := strings.ToLower(c)
		// NSE category form "dos"/"intrusive" must never reach the engine.
		if lc == "dos" || lc == "intrusive" {
			return fmt.Errorf("%w: NSE category %q", ErrDoSClass, c)
		}
	}
	if n.FixtureDir == "" && n.Bin == "" {
		return errors.New("nmap: exec mode requires a binary path")
	}
	return nil
}

// Abort implements Adapter — kills any in-flight nmap child (≤ 5 s).
func (n *Nmap) Abort() {
	n.mu.Lock()
	cmds := append([]*exec.Cmd(nil), n.active...)
	n.mu.Unlock()
	for _, c := range cmds {
		if c.Process != nil {
			_ = c.Process.Kill()
		}
	}
}

// Run implements Adapter.
func (n *Nmap) Run(ctx context.Context, job Job, limiter Limiter, emit Emitter) error {
	if err := n.ValidateJob(job); err != nil {
		return err
	}
	var r io.Reader
	if n.FixtureDir != "" {
		fixture := job.FixtureFile
		if fixture == "" {
			fixture = defaultNmapFixture
		}
		f, err := os.Open(n.FixtureDir + string(os.PathSeparator) + fixture)
		if err != nil {
			return fmt.Errorf("nmap: open fixture: %w", err)
		}
		defer f.Close()
		r = f
	} else {
		stdout, wait, err := n.spawn(ctx, job)
		if err != nil {
			return err
		}
		r = stdout
		defer func() { _ = wait() }()
	}
	return n.parse(ctx, job, limiter, r, emit)
}

// spawn launches nmap with the safe script allowlist. NSE selection is
// restricted to `vuln` + `safe` categories; dos/intrusive never appear
// (doc 04 §10.3). Rate is capped via --max-rate.
func (n *Nmap) spawn(ctx context.Context, job Job) (io.Reader, func() error, error) {
	ports := job.Ports
	if ports == "" {
		ports = "top-1000"
	}
	args := []string{"-oX", "-", "-sV", "--version-light"}
	if ports == "top-1000" {
		args = append(args, "--top-ports", "1000")
	} else {
		args = append(args, "-p", ports)
	}
	scripts := job.Checks
	if len(scripts) == 0 {
		scripts = []string{"vuln", "banner"}
	}
	// Filter one more time at launch (wrapper already refused DoS ids).
	kept, _ := FilterChecks(scripts, nil)
	if len(kept) > 0 {
		args = append(args, "--script", strings.Join(kept, ","))
	}
	if job.RPS > 0 {
		args = append(args, "--max-rate", fmt.Sprintf("%d", job.RPS))
	}
	args = append(args, job.Target)

	ctx, cancel := context.WithTimeout(ctx, n.Timeout)
	cmd := exec.CommandContext(ctx, n.Bin, args...)
	if job.ProxyURL != "" {
		cmd.Env = append(os.Environ(),
			"HTTP_PROXY="+job.ProxyURL, "HTTPS_PROXY="+job.ProxyURL,
			"http_proxy="+job.ProxyURL, "https_proxy="+job.ProxyURL)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, nil, err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, nil, fmt.Errorf("nmap: start: %w", err)
	}
	n.mu.Lock()
	n.active = append(n.active, cmd)
	n.mu.Unlock()
	wait := func() error {
		err := cmd.Wait()
		cancel()
		n.mu.Lock()
		for i, c := range n.active {
			if c == cmd {
				n.active = append(n.active[:i], n.active[i+1:]...)
				break
			}
		}
		n.mu.Unlock()
		if err != nil && !errors.Is(ctx.Err(), context.Canceled) {
			return fmt.Errorf("nmap: run: %w", err)
		}
		return nil
	}
	return stdout, wait, nil
}

// ---------------------------------------------------------------------------
// Nmap XML output model (subset used at MVP)
// ---------------------------------------------------------------------------

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Status      nmapStatus    `xml:"status"`
	Addresses   []nmapAddress `xml:"address"`
	Ports       []nmapPort    `xml:"ports>port"`
	HostScripts []nmapScript  `xml:"hostscript>script"`
}

type nmapStatus struct {
	State string `xml:"state,attr"`
}

type nmapAddress struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapPort struct {
	Protocol string        `xml:"protocol,attr"`
	PortID   int           `xml:"portid,attr"`
	State    nmapPortState `xml:"state"`
	Service  nmapService   `xml:"service"`
	Scripts  []nmapScript  `xml:"script"`
}

type nmapPortState struct {
	State string `xml:"state,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
}

type nmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Tables []nmapTable `xml:"table"`
	Elems  []nmapElem  `xml:"elem"`
}

type nmapTable struct {
	Key    string      `xml:"key,attr"`
	Elems  []nmapElem  `xml:"elem"`
	Tables []nmapTable `xml:"table"`
}

type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

// parse walks the XML output and emits RawResults for vulnerable script
// findings and for weak-TLS service signals (ssl-* scripts reporting issues).
func (n *Nmap) parse(ctx context.Context, job Job, limiter Limiter, r io.Reader, emit Emitter) error {
	var run nmapRun
	dec := xml.NewDecoder(r)
	if err := dec.Decode(&run); err != nil {
		return fmt.Errorf("nmap: parse XML: %w", err)
	}
	for _, host := range run.Hosts {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if !strings.EqualFold(host.Status.State, "up") {
			continue
		}
		addr := hostAddr(host)
		for _, p := range host.Ports {
			if !strings.EqualFold(p.State.State, "open") {
				continue
			}
			svc := p.Service
			for _, s := range p.Scripts {
				if IsDoSCheckID(s.ID) {
					continue // wrapper-level DoS exclusion on output too
				}
				vuln, title, severity, cve := nseVerdict(s)
				if !vuln {
					continue
				}
				if !limiter.TakeRequest() {
					return fmt.Errorf("nmap: request budget exhausted for job %s", job.JobID)
				}
				if err := limiter.Wait(ctx); err != nil {
					return err
				}
				matchedAt := fmt.Sprintf("%s:%d/%s", addr, p.PortID, p.Protocol)
				raw, _ := xml.Marshal(s)
				res := RawResult{
					JobID: job.JobID, TaskID: job.TaskID, Adapter: "nmap-nse",
					Target: job.Target, CheckID: s.ID,
					Title: title, Severity: severity,
					MatchedAt: matchedAt, VulnClass: classifyNSE(s),
					CVE: cve,
					Evidence: map[string]any{
						"output":  s.Output,
						"service": strings.TrimSpace(svc.Name + " " + svc.Product + " " + svc.Version),
						"port":    p.PortID,
					},
					Raw: raw,
				}
				if err := emit.Emit(res); err != nil {
					return err
				}
			}
		}
		for _, s := range host.HostScripts {
			if IsDoSCheckID(s.ID) {
				continue
			}
			vuln, title, severity, cve := nseVerdict(s)
			if !vuln {
				continue
			}
			if !limiter.TakeRequest() {
				return fmt.Errorf("nmap: request budget exhausted for job %s", job.JobID)
			}
			if err := limiter.Wait(ctx); err != nil {
				return err
			}
			raw, _ := xml.Marshal(s)
			res := RawResult{
				JobID: job.JobID, TaskID: job.TaskID, Adapter: "nmap-nse",
				Target: job.Target, CheckID: s.ID,
				Title: title, Severity: severity,
				MatchedAt: addr, VulnClass: classifyNSE(s), CVE: cve,
				Evidence: map[string]any{"output": s.Output},
				Raw:      raw,
			}
			if err := emit.Emit(res); err != nil {
				return err
			}
		}
	}
	return nil
}

func hostAddr(h nmapHost) string {
	for _, a := range h.Addresses {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			return a.Addr
		}
	}
	if len(h.Addresses) > 0 {
		return h.Addresses[0].Addr
	}
	return ""
}

// nseVerdict interprets an NSE script record: is it a positive vulnerability
// signal, and at what severity? `vuln`-category scripts mark VULNERABLE in
// their output table; ssl-* scripts flag weak offers.
func nseVerdict(s nmapScript) (vuln bool, title, severity, cve string) {
	title = s.ID
	severity = "medium"
	// Structured table form: <table><elem key="title">…</elem><elem>CVE-…</elem>…
	for _, t := range s.Tables {
		for _, e := range t.Elems {
			switch strings.ToLower(e.Key) {
			case "title":
				if e.Value != "" {
					title = strings.TrimSpace(e.Value)
				}
			case "state":
				if strings.Contains(strings.ToUpper(e.Value), "VULNERABLE") {
					vuln = true
				}
			case "cve":
				cve = strings.TrimSpace(e.Value)
			case "risk factor", "risk_factor":
				severity = normalizeSeverity(strings.ToLower(e.Value))
			}
		}
		for _, e := range t.Elems {
			if cve == "" && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(e.Value)), "CVE-") {
				cve = strings.ToUpper(strings.TrimSpace(e.Value))
			}
		}
	}
	out := strings.ToUpper(s.Output)
	switch {
	case strings.Contains(out, "VULNERABLE"):
		vuln = true
	case strings.HasPrefix(s.ID, "ssl-") &&
		(strings.Contains(out, "WEAK") || strings.Contains(out, "BROKEN") ||
			strings.Contains(out, "DEPRECATED") || strings.Contains(out, "VULNERABLE")):
		vuln = true
	}
	if cve == "" {
		if idx := strings.Index(out, "CVE-"); idx >= 0 {
			rest := s.Output[idx:]
			end := strings.IndexAny(rest, " \t\r\n,;)")
			if end < 0 {
				end = len(rest)
			}
			cve = strings.ToUpper(rest[:end])
		}
	}
	if severity == "medium" && strings.HasPrefix(s.ID, "ssl-") {
		severity = "low"
	}
	return vuln, title, severity, cve
}

// classifyNSE maps an NSE script to a vuln class for AVE routing.
func classifyNSE(s nmapScript) string {
	id := strings.ToLower(s.ID)
	switch {
	case strings.HasPrefix(id, "ssl-") || strings.HasPrefix(id, "tls-"):
		return ClassTLSMisconfig
	case strings.Contains(id, "heartbleed"), strings.Contains(id, "poodle"):
		return ClassTLSMisconfig
	case strings.Contains(id, "smb-vuln"), strings.Contains(id, "ms17-010"):
		return ClassVersionCVE
	case strings.Contains(id, "http-vuln"):
		return ClassVersionCVE
	case strings.Contains(id, "ftp-anon"), strings.Contains(id, "anon"):
		return ClassDefaultCreds
	case strings.Contains(id, "http-headers"), strings.Contains(id, "http-security-headers"):
		return ClassSecurityHeader
	default:
		return ClassVersionCVE
	}
}
