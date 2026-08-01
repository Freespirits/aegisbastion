package cloud

import (
	"context"
	"fmt"
	"sync"

	"github.com/aegisbastion/aegisbastion/services/discover/pkg/connectors"
	"github.com/aegisbastion/aegisbastion/services/discover/pkg/model"
)

// Connector names (doc 02 §8 MVP cloud set; weight 1.0 — credentialed cloud
// API, doc 02 §4.4).
const (
	AWSResourceExplorerName = "aws_resource_explorer"
	AzureResourceGraphName  = "azure_resource_graph"
	GCPAssetInventoryName   = "gcp_cloud_asset_inventory"
)

// Connector adapts a cloud Provider to the connectors.Connector interface so
// worker-cloud runs through the same registry (rate limits, circuit
// breakers, health) as passive connectors.
type Connector struct {
	name     string
	provider Provider
	creds    CredentialProvider

	mu     sync.Mutex
	health connectors.Health
}

// NewConnector wraps a provider as a connectors.Connector.
func NewConnector(name string, p Provider, creds CredentialProvider) connectors.Connector {
	return &Connector{name: name, provider: p, creds: creds}
}

// Name implements connectors.Connector.
func (c *Connector) Name() string { return c.name }

// Techniques implements connectors.Connector.
func (c *Connector) Techniques() []model.Technique {
	return []model.Technique{model.TechniqueCloudCredentialed}
}

// RateSpec implements connectors.Connector — provider management planes are
// gently polled (read-only enumeration).
func (c *Connector) RateSpec() connectors.RateSpec {
	return connectors.RateSpec{RPS: 2, Burst: 4, DailyQuota: 0}
}

// RequiresCredentials implements connectors.Connector.
func (c *Connector) RequiresCredentials() bool { return true }

// Healthcheck implements connectors.Connector.
func (c *Connector) Healthcheck(context.Context) connectors.Health {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.health == "" {
		return connectors.HealthOK
	}
	return c.health
}

func (c *Connector) setHealth(h connectors.Health) {
	c.mu.Lock()
	c.health = h
	c.mu.Unlock()
}

// Run implements connectors.Connector: resolve tenant credentials at task
// time, enumerate accounts + resources read-only, emit cloud_resource
// findings (weight 1.0 per doc 02 §4.4 — set as ConfidenceHint).
func (c *Connector) Run(ctx context.Context, in connectors.RunInput, emit connectors.EmitFunc) error {
	if c.creds == nil {
		c.setHealth(connectors.HealthDegraded)
		return &connectors.CredentialError{Connector: c.name}
	}
	_, accountID, err := ParseAccountRef(in.Task.Seed.Value)
	if err != nil {
		return err
	}
	creds, err := c.creds.CredentialsFor(ctx, in.Task.TenantID, in.Task.Seed.Value)
	if err != nil {
		c.setHealth(connectors.HealthDegraded)
		return &connectors.CredentialError{Connector: c.name, Err: err}
	}

	// Account listing (AWS Organizations across linked accounts; Azure/GCP
	// their configured scope) — failure here is not fatal for single-account
	// enumeration of the seed account.
	accounts := []Account{{Provider: creds.Provider, ID: accountID, Name: accountID}}
	if listed, err := c.provider.ListAccounts(ctx, creds); err == nil && len(listed) > 0 {
		accounts = listed
	}

	emitted := 0
	var firstErr error
	for _, acct := range accounts {
		// Only enumerate the seed account's org peers when the seed targets
		// the organization root (aws:ou-… / aws:r-…); otherwise stay on the
		// seed account itself — the RoE scopes cloud_accounts explicitly.
		if acct.ID != accountID && !isOrgRoot(accountID) {
			continue
		}
		resources, err := c.provider.ListResources(ctx, creds, acct.ID)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		for _, r := range resources {
			value, err := model.CanonicalizeCloudResource(r.ID)
			if err != nil {
				continue
			}
			asset := model.Asset{
				Type:  model.AssetCloudResource,
				Value: value,
				Attributes: map[string]any{
					"cloud": map[string]any{
						"provider": c.provider.Name(),
						"service":  r.Service,
						"region":   r.Region,
						"account":  firstNonEmpty(r.AccountID, acct.ID),
					},
					"resource_type": r.Type,
				},
			}
			for k, v := range r.Extra {
				asset.Attributes[k] = v
			}
			rf := model.RawFinding{
				TaskID:         in.Task.TaskID,
				OrderID:        in.Task.OrderID,
				Asset:          asset,
				Source:         c.name,
				ObservedAt:     in.ObservedAt,
				ConfidenceHint: model.WeightCredentialedCloud,
			}
			if err := emit(rf, nil); err != nil {
				return err
			}
			emitted++
		}
	}
	if emitted == 0 && firstErr != nil {
		c.setHealth(connectors.HealthDegraded)
		return fmt.Errorf("%s: %w", c.name, firstErr)
	}
	c.setHealth(connectors.HealthOK)
	return nil
}

func isOrgRoot(accountID string) bool {
	return len(accountID) >= 3 && (accountID[:3] == "ou-" || accountID[:2] == "r-")
}

// DefaultProviders builds the live provider set.
func DefaultProviders() map[string]Provider {
	return map[string]Provider{
		"aws":   &AWSProvider{},
		"azure": &AzureProvider{},
		"gcp":   &GCPProvider{},
	}
}

// RegisterCloudConnectors registers the doc 02 §8 credentialed-cloud
// connector set into a connectors.Catalog.
func RegisterCloudConnectors(cat *connectors.Catalog, creds CredentialProvider, providers map[string]Provider) {
	if providers == nil {
		providers = DefaultProviders()
	}
	cat.Register(AWSResourceExplorerName, func() connectors.Connector {
		return NewConnector(AWSResourceExplorerName, providers["aws"], creds)
	})
	cat.Register(AzureResourceGraphName, func() connectors.Connector {
		return NewConnector(AzureResourceGraphName, providers["azure"], creds)
	})
	cat.Register(GCPAssetInventoryName, func() connectors.Connector {
		return NewConnector(GCPAssetInventoryName, providers["gcp"], creds)
	})
}
