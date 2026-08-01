package risk

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Mirror is the local EPSS/KEV threat-intel mirror (doc 04 §8): daily
// refreshed from the FIRST EPSS CSV and the CISA KEV JSON so scoring has no
// runtime internet dependency and stays reproducible. The mirror version is
// recorded in every finding's risk factors; a mirror older than 48 h sets
// factors.intel_stale (doc 04 §12).
type Mirror struct {
	mu      sync.RWMutex
	epss    map[string]float64 // CVE (upper) → probability
	kev     map[string]bool    // CVE (upper) → true
	version string             // mirror version, e.g. "2026-07-31T05:00:00Z"
	loaded  time.Time

	// HTTP is the fetch client for Refresh (injectable in tests).
	HTTP *http.Client
	// Now is the clock (tests).
	Now func() time.Time
}

// NewMirror builds an empty mirror.
func NewMirror() *Mirror {
	return &Mirror{
		epss: map[string]float64{},
		kev:  map[string]bool{},
		HTTP: &http.Client{Timeout: 60 * time.Second},
		Now:  func() time.Time { return time.Now().UTC() },
	}
}

// snapshot is the seed/persisted mirror form (JSON).
type snapshot struct {
	Version string             `json:"version"`
	EPSS    map[string]float64 `json:"epss"`
	KEV     []string           `json:"kev"`
}

// LoadSeed installs a mirror snapshot from a JSON seed file (config
// DETECT_INTEL_SEED_FILE).
func (m *Mirror) LoadSeed(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("risk: read intel seed: %w", err)
	}
	return m.LoadSeedBytes(data)
}

// LoadSeedBytes installs a mirror snapshot from JSON bytes.
func (m *Mirror) LoadSeedBytes(data []byte) error {
	var s snapshot
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("risk: decode intel seed: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.epss = map[string]float64{}
	for cve, p := range s.EPSS {
		m.epss[strings.ToUpper(cve)] = p
	}
	m.kev = map[string]bool{}
	for _, cve := range s.KEV {
		m.kev[strings.ToUpper(cve)] = true
	}
	if s.Version == "" {
		s.Version = m.now().Format(time.RFC3339)
	}
	m.version = s.Version
	m.loaded = m.now()
	return nil
}

// SnapshotBytes renders the current mirror as a seed JSON (cron persistence /
// replica sharing via the detect_dedup KV bucket, doc 04 §11).
func (m *Mirror) SnapshotBytes() ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s := snapshot{Version: m.version, EPSS: m.epss}
	for cve := range m.kev {
		s.KEV = append(s.KEV, cve)
	}
	return json.Marshal(s)
}

// Refresh pulls the upstream sources (FIRST EPSS CSV, CISA KEV JSON) and
// atomically swaps the mirror. Empty URLs skip that source (doc 04 §8: local
// mirror; no runtime internet dependency for scoring itself).
func (m *Mirror) Refresh(ctx context.Context, epssURL, kevURL string) error {
	epss := map[string]float64{}
	kev := map[string]bool{}
	if epssURL != "" {
		body, err := m.fetch(ctx, epssURL)
		if err != nil {
			return fmt.Errorf("risk: fetch EPSS: %w", err)
		}
		if err := parseEPSSCSV(body, epss); err != nil {
			return fmt.Errorf("risk: parse EPSS CSV: %w", err)
		}
	}
	if kevURL != "" {
		body, err := m.fetch(ctx, kevURL)
		if err != nil {
			return fmt.Errorf("risk: fetch KEV: %w", err)
		}
		if err := parseKEVJSON(body, kev); err != nil {
			return fmt.Errorf("risk: parse KEV JSON: %w", err)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if epssURL != "" {
		m.epss = epss
	}
	if kevURL != "" {
		m.kev = kev
	}
	m.version = m.now().Format(time.RFC3339)
	m.loaded = m.now()
	return nil
}

// Lookup returns the intel for one CVE: EPSS probability (0 when unknown) and
// KEV membership.
func (m *Mirror) Lookup(cve string) (epss float64, kev bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	cve = strings.ToUpper(strings.TrimSpace(cve))
	return m.epss[cve], m.kev[cve]
}

// Version reports the mirror version recorded into scoring factors.
func (m *Mirror) Version() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.version
}

// Stale reports whether the mirror is older than 48 h (doc 04 §12).
func (m *Mirror) Stale() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.loaded.IsZero() {
		return true
	}
	return m.now().Sub(m.loaded) > 48*time.Hour
}

func (m *Mirror) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now().UTC()
}

func (m *Mirror) fetch(ctx context.Context, url string) ([]byte, error) {
	hc := m.HTTP
	if hc == nil {
		hc = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 256<<20))
}

// parseEPSSCSV reads the FIRST EPSS CSV ("cve,epss,percentile" with a
// "#model_version" comment header line).
func parseEPSSCSV(data []byte, out map[string]float64) error {
	r := csv.NewReader(strings.NewReader(strings.TrimPrefix(string(data), "\ufeff")))
	r.Comment = '#'
	r.FieldsPerRecord = -1
	header := true
	for {
		rec, err := r.Read()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if header {
			header = false
			if len(rec) > 0 && strings.EqualFold(rec[0], "cve") {
				continue
			}
		}
		if len(rec) < 2 {
			continue
		}
		p, err := strconv.ParseFloat(rec[1], 64)
		if err != nil {
			continue
		}
		out[strings.ToUpper(rec[0])] = p
	}
}

// parseKEVJSON reads the CISA Known Exploited Vulnerabilities catalog.
func parseKEVJSON(data []byte, out map[string]bool) error {
	var doc struct {
		Vulnerabilities []struct {
			CveID string `json:"cveID"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return err
	}
	for _, v := range doc.Vulnerabilities {
		if v.CveID != "" {
			out[strings.ToUpper(v.CveID)] = true
		}
	}
	return nil
}
