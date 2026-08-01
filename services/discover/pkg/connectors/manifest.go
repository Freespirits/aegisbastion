package connectors

import (
	"context"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// ManifestEntry is one connectors.yaml row (doc 02 §4.3: per-tenant enable
// flags + credential references; rate specs are declarative overrides).
type ManifestEntry struct {
	Name     string    `yaml:"name"`
	Enabled  bool      `yaml:"enabled"`
	Tenants  []string  `yaml:"tenants"` // ["*"] = all; enable flags per tenant
	RateSpec *RateSpec `yaml:"rate_spec,omitempty"`
}

// Manifest is the parsed connectors.yaml.
type Manifest struct {
	Connectors []ManifestEntry `yaml:"connectors"`
}

// LoadManifest parses connectors.yaml.
func LoadManifest(path string) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("connectors manifest: %w", err)
	}
	var m Manifest
	if err := yaml.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("connectors manifest %s: %w", path, err)
	}
	return &m, nil
}

// EnabledFor reports whether a manifest entry enables a tenant.
func (e ManifestEntry) EnabledFor(tenantID string) bool {
	if !e.Enabled {
		return false
	}
	for _, t := range e.Tenants {
		if t == "*" || t == tenantID {
			return true
		}
	}
	return len(e.Tenants) == 0
}

// Catalog maps connector names to constructors (passive/CT/BGP/RDAP set;
// cloud connectors are registered by the cloud package).
type Catalog struct {
	fetch Fetcher
	keys  KeyProvider
	ctors map[string]func() Connector
}

// NewCatalog wires the doc 02 §8 MVP connector set: crt.sh, Censys,
// VirusTotal, SecurityTrails, Shodan, RapidDNS, Wayback; BGP: bgpview +
// RIPEstat; RDAP.
func NewCatalog(fetch Fetcher, keys KeyProvider) *Catalog {
	return &Catalog{
		fetch: fetch,
		keys:  keys,
		ctors: map[string]func() Connector{
			CrtSHName:          func() Connector { return NewCrtSH(fetch) },
			CensysCTName:       func() Connector { return NewCensysCT(fetch, keys) },
			VirusTotalName:     func() Connector { return NewVirusTotal(fetch, keys) },
			SecurityTrailsName: func() Connector { return NewSecurityTrails(fetch, keys) },
			ShodanName:         func() Connector { return NewShodan(fetch, keys) },
			RapidDNSName:       func() Connector { return NewRapidDNS(fetch) },
			WaybackName:        func() Connector { return NewWayback(fetch) },
			BGPViewName:        func() Connector { return NewBGPView(fetch) },
			RIPEstatName:       func() Connector { return NewRIPEstat(fetch) },
			RDAPName:           func() Connector { return NewRDAP(fetch, "", "") },
		},
	}
}

// Register extra constructor (cloud package hooks its connectors here).
func (c *Catalog) Register(name string, ctor func() Connector) {
	c.ctors[name] = ctor
}

// BuildRegistry instantiates the manifest-enabled connectors into a Registry.
// A nil/empty manifest enables everything (the doc 02 §8 default set).
func (c *Catalog) BuildRegistry(m *Manifest) (*Registry, error) {
	reg := NewRegistry(c.keys)
	if m == nil || len(m.Connectors) == 0 {
		for name, ctor := range c.ctors {
			_ = name
			reg.Register(ctor())
		}
		return reg, nil
	}
	for _, e := range m.Connectors {
		if !e.Enabled {
			continue
		}
		ctor, ok := c.ctors[e.Name]
		if !ok {
			return nil, fmt.Errorf("connectors manifest: unknown connector %q", e.Name)
		}
		conn := ctor()
		reg.Register(conn)
	}
	return reg, nil
}

// TechniquesEnabled reports the union of techniques the registry serves.
func TechniquesEnabled(reg *Registry) map[model.Technique]bool {
	out := map[model.Technique]bool{}
	for _, name := range reg.Names() {
		c, _ := reg.Get(name)
		for _, t := range c.Techniques() {
			out[t] = true
		}
	}
	return out
}

// BuildRegistryFor instantiates a subset of connectors by name (worker pools
// register only the connectors their lane serves). names nil ⇒ same as
// BuildRegistry (manifest-enabled set).
func (c *Catalog) BuildRegistryFor(m *Manifest, names map[string]bool) (*Registry, error) {
	if names == nil {
		return c.BuildRegistry(m)
	}
	reg := NewRegistry(c.keys)
	for name, ctor := range c.ctors {
		if !names[name] {
			continue
		}
		if m != nil && len(m.Connectors) > 0 {
			enabled := false
			for _, e := range m.Connectors {
				if e.Name == name {
					enabled = e.Enabled
					break
				}
			}
			if !enabled {
				continue
			}
		}
		reg.Register(ctor())
	}
	return reg, nil
}

// SetArchive wires the evidence-archive hook onto every registered
// http-source connector (cloud connectors carry no raw HTTP body to
// archive). fn receives the connector name + raw body and returns the
// evidence URI ("" = not archived).
func (r *Registry) SetArchive(fn func(ctx context.Context, source string, body []byte) string) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, e := range r.entries {
		if hs, ok := e.Connector.(*httpSource); ok {
			name := hs.name
			hs.Archive = func(ctx context.Context, body []byte) string {
				return fn(ctx, name, body)
			}
		}
	}
}
