package cloud

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AzureProvider enumerates via Azure Resource Graph (read-only; Reader role,
// doc 02 §6.3). Auth: client-credentials bearer from the tenant's login
// endpoint. HTTPDoer is injectable for fixtures/tests.
type AzureProvider struct {
	HTTPDoer interface {
		Do(*http.Request) (*http.Response, error)
	}
	// TokenURL/GraphURL are overrideable (sovereign clouds, tests).
	TokenURL string // default https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token
	GraphURL string // default https://management.azure.com/providers/Microsoft.ResourceGraph/resources
}

// Name implements Provider.
func (p *AzureProvider) Name() string { return "azure" }

func (p *AzureProvider) doer() interface {
	Do(*http.Request) (*http.Response, error)
} {
	if p.HTTPDoer != nil {
		return p.HTTPDoer
	}
	return &http.Client{Timeout: 45 * time.Second}
}

// ListAccounts implements Provider — the configured subscription scope.
func (p *AzureProvider) ListAccounts(_ context.Context, creds Credentials) ([]Account, error) {
	if creds.AzureSubscriptionID == "" {
		return nil, fmt.Errorf("azure credentials: azure_subscription_id is required")
	}
	return []Account{{Provider: "azure", ID: creds.AzureSubscriptionID, Name: creds.AzureSubscriptionID}}, nil
}

type azureTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
	TokenType   string `json:"token_type"`
}

func (p *AzureProvider) token(ctx context.Context, creds Credentials) (string, error) {
	tokenURL := p.TokenURL
	if tokenURL == "" {
		if creds.AzureTenantID == "" {
			return "", fmt.Errorf("azure credentials: azure_tenant_id is required")
		}
		tokenURL = "https://login.microsoftonline.com/" + url.PathEscape(creds.AzureTenantID) + "/oauth2/v2.0/token"
	}
	form := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {creds.AzureClientID},
		"client_secret": {creds.AzureClientSecret},
		"scope":         {"https://management.azure.com/.default"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := p.doer().Do(req)
	if err != nil {
		return "", fmt.Errorf("azure token: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("azure token: status %d: %s", resp.StatusCode, truncate(string(body), 200))
	}
	var tr azureTokenResponse
	if err := json.Unmarshal(body, &tr); err != nil || tr.AccessToken == "" {
		return "", fmt.Errorf("azure token: decode: %v", err)
	}
	return tr.AccessToken, nil
}

type azureGraphResponse struct {
	Data []struct {
		ID             string `json:"id"`
		Name           string `json:"name"`
		Type           string `json:"type"`
		Location       string `json:"location"`
		ResourceGroup  string `json:"resourceGroup"`
		SubscriptionID string `json:"subscriptionId"`
	} `json:"data"`
	SkipToken string `json:"$skipToken"`
}

// ListResources implements Provider (Resource Graph query, paginated).
func (p *AzureProvider) ListResources(ctx context.Context, creds Credentials, accountID string) ([]Resource, error) {
	if err := AssertReadOnly("SearchResources"); err != nil {
		return nil, err
	}
	sub := accountID
	if sub == "" {
		sub = creds.AzureSubscriptionID
	}
	if sub == "" {
		return nil, fmt.Errorf("azure credentials: azure_subscription_id is required")
	}
	tok, err := p.token(ctx, creds)
	if err != nil {
		return nil, err
	}
	graphURL := p.GraphURL
	if graphURL == "" {
		graphURL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01"
	}
	var out []Resource
	skipToken := ""
	for {
		reqBody := map[string]any{
			"query":         "Resources | project id, name, type, location, resourceGroup, subscriptionId",
			"subscriptions": []string{sub},
			"options":       map[string]any{"$top": 1000, "$skipToken": skipToken},
		}
		payload, _ := json.Marshal(reqBody)
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, graphURL, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := p.doer().Do(req)
		if err != nil {
			return nil, fmt.Errorf("azure resource graph: %w", err)
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("azure resource graph: status %d: %s", resp.StatusCode, truncate(string(body), 200))
		}
		var gr azureGraphResponse
		if err := json.Unmarshal(body, &gr); err != nil {
			return nil, fmt.Errorf("azure resource graph: decode: %w", err)
		}
		for _, r := range gr.Data {
			service, typ := parseAzureType(r.Type)
			out = append(out, Resource{
				ID:        r.ID,
				Service:   service,
				Type:      typ,
				Region:    r.Location,
				AccountID: r.SubscriptionID,
				Extra:     map[string]any{"name": r.Name, "resource_group": r.ResourceGroup},
			})
		}
		if gr.SkipToken == "" {
			return out, nil
		}
		skipToken = gr.SkipToken
	}
}

// parseAzureType splits "Microsoft.Compute/virtualMachines" →
// ("microsoft.compute", "virtualmachines").
func parseAzureType(t string) (service, typ string) {
	provider, res, ok := strings.Cut(t, "/")
	if !ok {
		return strings.ToLower(t), ""
	}
	return strings.ToLower(provider), strings.ToLower(res)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
