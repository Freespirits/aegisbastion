// Package cloud implements doc 02 §2.2 worker-cloud: credentialed, read-only
// cloud asset discovery across AWS (Resource Explorer + Organizations), Azure
// (Resource Graph) and GCP (Cloud Asset Inventory).
//
// Hard rules (doc 02 §6.3):
//   - read-only by construction: only List|Get|Describe|Search-style calls;
//     an SDK middleware refuses anything else.
//   - credentials are customer-provided, read-only roles (AWS
//     ViewOnlyAccess/SecurityAudit, Azure Reader, GCP
//     roles/iam.securityReviewer + Cloud Asset Viewer), pulled from the
//     platform secrets vault at task time (MVP-A: a local credentials file;
//     never embedded in task payloads).
//   - every provider is interface-driven with fixture implementations so
//     tests run without internet or credentials.
package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// Credentials carries one tenant's read-only cloud credentials. Fields are
// provider-specific; only the relevant set is populated.
type Credentials struct {
	Provider string `json:"provider"` // aws|azure|gcp

	// AWS — static keys or a role to assume (read-only).
	AWSAccessKeyID     string   `json:"aws_access_key_id,omitempty"`
	AWSSecretAccessKey string   `json:"aws_secret_access_key,omitempty"`
	AWSSessionToken    string   `json:"aws_session_token,omitempty"`
	AWSRoleARN         string   `json:"aws_role_arn,omitempty"`
	AWSRegions         []string `json:"aws_regions,omitempty"` // empty = default scan set

	// Azure — client credentials (Reader).
	AzureTenantID       string `json:"azure_tenant_id,omitempty"`
	AzureClientID       string `json:"azure_client_id,omitempty"`
	AzureClientSecret   string `json:"azure_client_secret,omitempty"`
	AzureSubscriptionID string `json:"azure_subscription_id,omitempty"`

	// GCP — service account (iam.securityReviewer + Cloud Asset Viewer).
	GCPServiceAccountJSON string `json:"gcp_service_account_json,omitempty"`
	GCPProjectID          string `json:"gcp_project_id,omitempty"`
	GCPOrganizationID     string `json:"gcp_organization_id,omitempty"`
}

// Account is one cloud account/subscription/project.
type Account struct {
	Provider string `json:"provider"`
	ID       string `json:"id"`
	Name     string `json:"name"`
}

// Resource is one enumerated cloud resource.
type Resource struct {
	ID        string         `json:"id"` // ARN / Azure resource id / GCP resource name
	Service   string         `json:"service"`
	Type      string         `json:"type"`
	Region    string         `json:"region"`
	AccountID string         `json:"account_id"`
	Extra     map[string]any `json:"extra,omitempty"`
}

// Provider enumerates resources in one cloud. Implementations: AWS (Resource
// Explorer + Organizations), Azure (Resource Graph), GCP (Cloud Asset
// Inventory), plus fixtures for tests/offline mode.
type Provider interface {
	Name() string
	// ListAccounts returns the accounts visible to the credentials (AWS
	// Organizations; single-account Azure/GCP return their configured scope).
	ListAccounts(ctx context.Context, creds Credentials) ([]Account, error)
	// ListResources enumerates resources in one account (read-only).
	ListResources(ctx context.Context, creds Credentials, accountID string) ([]Resource, error)
}

// CredentialProvider resolves tenant credentials at task time (doc 02 §2.2 —
// from the platform vault; MVP-A reads a local JSON file, README documents
// the substitution).
type CredentialProvider interface {
	CredentialsFor(ctx context.Context, tenantID, accountRef string) (Credentials, error)
}

// CredentialProviderFunc adapts a function.
type CredentialProviderFunc func(ctx context.Context, tenantID, accountRef string) (Credentials, error)

// CredentialsFor implements CredentialProvider.
func (f CredentialProviderFunc) CredentialsFor(ctx context.Context, tenantID, accountRef string) (Credentials, error) {
	return f(ctx, tenantID, accountRef)
}

// FileCredentials is a JSON-file CredentialProvider:
//
//	{ "<tenant_id>": { "aws:123456789012": {Credentials}, "azure:<sub>": {…} },
//	  "*": { "aws:*": {Credentials} } }
//
// accountRef is the seed value (e.g. "aws:123456789012"); "aws:*" is the
// provider wildcard fallback.
type FileCredentials map[string]map[string]Credentials

// LoadFileCredentials reads the credentials file.
func LoadFileCredentials(path string) (FileCredentials, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cloud credentials file: %w", err)
	}
	var fc FileCredentials
	if err := json.Unmarshal(raw, &fc); err != nil {
		return nil, fmt.Errorf("cloud credentials file %s: %w", path, err)
	}
	return fc, nil
}

// CredentialsFor implements CredentialProvider.
func (fc FileCredentials) CredentialsFor(_ context.Context, tenantID, accountRef string) (Credentials, error) {
	provider, _, _ := strings.Cut(accountRef, ":")
	lookups := []struct{ tenant, ref string }{
		{tenantID, accountRef},
		{tenantID, provider + ":*"},
		{"*", accountRef},
		{"*", provider + ":*"},
	}
	for _, l := range lookups {
		if byRef, ok := fc[l.tenant]; ok {
			if c, ok := byRef[l.ref]; ok {
				c.Provider = provider
				return c, nil
			}
		}
	}
	return Credentials{}, fmt.Errorf("no %s credentials for tenant %s account %q", provider, tenantID, accountRef)
}

// ErrMutationBlocked is returned by the read-only middleware when a non
// List|Get|Describe|Search call is attempted (doc 02 §6.3/§7.2 — violation ⇒
// audit event + order PARTIAL).
var ErrMutationBlocked = fmt.Errorf("cloud: mutating API call refused by read-only middleware")

// AssertReadOnly enforces the doc 02 §6.3 allowlist on an operation name.
func AssertReadOnly(operation string) error {
	for _, p := range []string{"List", "Get", "Describe", "Search", "BatchGet"} {
		if strings.HasPrefix(operation, p) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s", ErrMutationBlocked, operation)
}

// ParseAccountRef splits a cloud_account seed value ("aws:123456789012") into
// provider and account id.
func ParseAccountRef(value string) (provider, accountID string, err error) {
	p, id, ok := strings.Cut(strings.TrimSpace(value), ":")
	if !ok || id == "" {
		return "", "", fmt.Errorf("cloud_account seed %q must be provider:account-id (aws|azure|gcp)", value)
	}
	switch strings.ToLower(p) {
	case "aws":
		return "aws", id, nil
	case "azure":
		return "azure", id, nil
	case "gcp":
		return "gcp", id, nil
	}
	return "", "", fmt.Errorf("cloud_account seed %q: unknown provider %q", value, p)
}

// FixtureProvider replays recorded provider responses (tests + offline mode).
type FixtureProvider struct {
	ProviderName string
	Accounts     []Account
	Resources    []Resource
	Err          error
}

// Name implements Provider.
func (f *FixtureProvider) Name() string { return f.ProviderName }

// ListAccounts implements Provider.
func (f *FixtureProvider) ListAccounts(context.Context, Credentials) ([]Account, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	return f.Accounts, nil
}

// ListResources implements Provider.
func (f *FixtureProvider) ListResources(_ context.Context, _ Credentials, accountID string) ([]Resource, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	if accountID == "" {
		return f.Resources, nil
	}
	var out []Resource
	for _, r := range f.Resources {
		if r.AccountID == accountID || r.AccountID == "" {
			out = append(out, r)
		}
	}
	return out, nil
}
