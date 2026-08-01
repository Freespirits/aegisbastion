package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2/google"
)

// GCPProvider enumerates via GCP Cloud Asset Inventory searchAllResources
// (read-only: roles/iam.securityReviewer + Cloud Asset Viewer, doc 02 §6.3).
// Auth: service-account JWT bearer (x/oauth2/google). HTTPClient injectable
// for fixtures/tests.
type GCPProvider struct {
	HTTPClient *http.Client
	// BaseURL override (tests); default https://cloudasset.googleapis.com.
	BaseURL string
}

// Name implements Provider.
func (p *GCPProvider) Name() string { return "gcp" }

func (p *GCPProvider) client(ctx context.Context, creds Credentials) (*http.Client, error) {
	if p.HTTPClient != nil {
		return p.HTTPClient, nil
	}
	if creds.GCPServiceAccountJSON == "" {
		return nil, fmt.Errorf("gcp credentials: gcp_service_account_json is required")
	}
	jwtCfg, err := google.JWTConfigFromJSON(
		[]byte(creds.GCPServiceAccountJSON),
		"https://www.googleapis.com/auth/cloud-platform.read-only",
	)
	if err != nil {
		return nil, fmt.Errorf("gcp credentials: %w", err)
	}
	return jwtCfg.Client(ctx), nil
}

// ListAccounts implements Provider — the configured project/org scope.
func (p *GCPProvider) ListAccounts(_ context.Context, creds Credentials) ([]Account, error) {
	var out []Account
	if creds.GCPProjectID != "" {
		out = append(out, Account{Provider: "gcp", ID: creds.GCPProjectID, Name: "projects/" + creds.GCPProjectID})
	}
	if creds.GCPOrganizationID != "" {
		out = append(out, Account{Provider: "gcp", ID: creds.GCPOrganizationID, Name: "organizations/" + creds.GCPOrganizationID})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("gcp credentials: gcp_project_id or gcp_organization_id is required")
	}
	return out, nil
}

type gcpSearchResponse struct {
	Results []struct {
		Name           string         `json:"name"`
		AssetType      string         `json:"assetType"`
		Project        string         `json:"project"`
		DisplayName    string         `json:"displayName"`
		Location       string         `json:"location"`
		AdditionalAttr map[string]any `json:"additionalAttributes"`
	} `json:"results"`
	NextPageToken string `json:"nextPageToken"`
}

// ListResources implements Provider (searchAllResources, paginated).
func (p *GCPProvider) ListResources(ctx context.Context, creds Credentials, accountID string) ([]Resource, error) {
	if err := AssertReadOnly("SearchAllResources"); err != nil {
		return nil, err
	}
	scope := accountID
	if scope == "" {
		scope = creds.GCPProjectID
	}
	if scope == "" {
		return nil, fmt.Errorf("gcp: account scope (project id) is required")
	}
	if !strings.Contains(scope, "/") {
		scope = "projects/" + scope
	}
	client, err := p.client(ctx, creds)
	if err != nil {
		return nil, err
	}
	base := p.BaseURL
	if base == "" {
		base = "https://cloudasset.googleapis.com"
	}
	var out []Resource
	pageToken := ""
	for {
		u := fmt.Sprintf("%s/v1/%s:searchAllResources?pageSize=500&pageToken=%s",
			base, scope, url.QueryEscape(pageToken))
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return nil, err
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("gcp cloud asset: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("gcp cloud asset: status %d: %s", resp.StatusCode, truncate(string(body), 200))
		}
		var sr gcpSearchResponse
		if err := json.Unmarshal(body, &sr); err != nil {
			return nil, fmt.Errorf("gcp cloud asset: decode: %w", err)
		}
		for _, r := range sr.Results {
			service, typ := parseGCPAssetType(r.AssetType)
			out = append(out, Resource{
				ID:        r.Name,
				Service:   service,
				Type:      typ,
				Region:    r.Location,
				AccountID: strings.TrimPrefix(r.Project, "projects/"),
				Extra: map[string]any{
					"display_name": r.DisplayName,
					"asset_type":   r.AssetType,
				},
			})
		}
		if sr.NextPageToken == "" {
			return out, nil
		}
		pageToken = sr.NextPageToken
	}
}

// parseGCPAssetType splits "compute.googleapis.com/Instance" →
// ("compute.googleapis.com", "instance").
func parseGCPAssetType(t string) (service, typ string) {
	svc, res, ok := strings.Cut(t, "/")
	if !ok {
		return strings.ToLower(t), ""
	}
	return strings.ToLower(svc), strings.ToLower(res)
}
