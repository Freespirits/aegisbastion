package cloud

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsmiddleware "github.com/aws/aws-sdk-go-v2/aws/middleware"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/resourceexplorer2"
	retypes "github.com/aws/aws-sdk-go-v2/service/resourceexplorer2/types"
	"github.com/aws/smithy-go/middleware"
)

// AWSProvider enumerates via AWS Resource Explorer (resource search) and AWS
// Organizations (account listing) — read-only (ViewOnlyAccess/SecurityAudit
// equivalent roles, doc 02 §6.3), enforced additionally by the read-only
// middleware below.
type AWSProvider struct {
	// NewConfig is injectable for tests; nil = config.LoadDefaultConfig.
	LoadConfig func(ctx context.Context, optFns ...func(*config.LoadOptions) error) (aws.Config, error)
}

// Name implements Provider.
func (p *AWSProvider) Name() string { return "aws" }

// readOnlyAPIOption is the SDK middleware refusing any non read-only
// operation (doc 02 §6.3: "the worker additionally refuses any
// non-List|Get|Describe API call at the SDK middleware layer").
func readOnlyAPIOption(stack *middleware.Stack) error {
	return stack.Initialize.Add(
		middleware.InitializeMiddlewareFunc("AegisBastionReadOnly", func(
			ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
		) (middleware.InitializeOutput, middleware.Metadata, error) {
			if err := AssertReadOnly(awsmiddleware.GetOperationName(ctx)); err != nil {
				return middleware.InitializeOutput{}, middleware.Metadata{}, err
			}
			return next.HandleInitialize(ctx, in)
		}), middleware.Before)
}

func (p *AWSProvider) awsConfig(ctx context.Context, creds Credentials) (aws.Config, error) {
	load := p.LoadConfig
	if load == nil {
		load = config.LoadDefaultConfig
	}
	opts := []func(*config.LoadOptions) error{}
	if creds.AWSAccessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(
			credentials.NewStaticCredentialsProvider(
				creds.AWSAccessKeyID, creds.AWSSecretAccessKey, creds.AWSSessionToken)))
	}
	region := "us-east-1"
	if len(creds.AWSRegions) > 0 {
		region = creds.AWSRegions[0]
	}
	opts = append(opts, config.WithRegion(region))
	cfg, err := load(ctx, opts...)
	if err != nil {
		return aws.Config{}, fmt.Errorf("aws config: %w", err)
	}
	cfg.APIOptions = append(cfg.APIOptions, readOnlyAPIOption)
	return cfg, nil
}

// ListAccounts implements Provider (AWS Organizations ListAccounts — falls
// back to the credential's own account when Organizations is not available).
func (p *AWSProvider) ListAccounts(ctx context.Context, creds Credentials) ([]Account, error) {
	if err := AssertReadOnly("ListAccounts"); err != nil {
		return nil, err
	}
	cfg, err := p.awsConfig(ctx, creds)
	if err != nil {
		return nil, err
	}
	client := organizations.NewFromConfig(cfg)
	var out []Account
	var token *string
	for {
		resp, err := client.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: token})
		if err != nil {
			return nil, fmt.Errorf("aws organizations ListAccounts: %w", err)
		}
		for _, a := range resp.Accounts {
			out = append(out, Account{Provider: "aws", ID: aws.ToString(a.Id), Name: aws.ToString(a.Name)})
		}
		if resp.NextToken == nil {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

// ListResources implements Provider (Resource Explorer Search across the
// configured regions; requires a Resource Explorer index + default view in
// the account).
func (p *AWSProvider) ListResources(ctx context.Context, creds Credentials, accountID string) ([]Resource, error) {
	if err := AssertReadOnly("Search"); err != nil {
		return nil, err
	}
	regions := creds.AWSRegions
	if len(regions) == 0 {
		regions = []string{"us-east-1"}
	}
	var out []Resource
	var firstErr error
	for _, region := range regions {
		regionCreds := creds
		regionCreds.AWSRegions = []string{region}
		cfg, err := p.awsConfig(ctx, regionCreds)
		if err != nil {
			return nil, err
		}
		client := resourceexplorer2.NewFromConfig(cfg)
		// Discover the default view (Resource Explorer requires a view ARN).
		views, err := client.ListViews(ctx, &resourceexplorer2.ListViewsInput{})
		if err != nil {
			firstErr = fmt.Errorf("aws resourceexplorer2 ListViews %s: %w", region, err)
			continue
		}
		if len(views.Views) == 0 {
			continue // no index in this region
		}
		var nextToken *string
		for {
			resp, err := client.Search(ctx, &resourceexplorer2.SearchInput{
				QueryString: aws.String("*"),
				ViewArn:     aws.String(views.Views[0]),
				NextToken:   nextToken,
				MaxResults:  aws.Int32(100),
			})
			if err != nil {
				firstErr = fmt.Errorf("aws resourceexplorer2 Search %s: %w", region, err)
				break
			}
			for _, r := range resp.Resources {
				out = append(out, awsResourceToCloud(r, region, accountID))
			}
			if resp.NextToken == nil {
				break
			}
			nextToken = resp.NextToken
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

func awsResourceToCloud(r retypes.Resource, region, accountID string) Resource {
	arn := aws.ToString(r.Arn)
	service, typ := parseARNServiceType(arn)
	return Resource{
		ID:        arn,
		Service:   service,
		Type:      typ,
		Region:    aws.ToString(r.Region),
		AccountID: firstNonEmpty(aws.ToString(r.OwningAccountId), accountID),
		Extra: map[string]any{
			"resource_type": aws.ToString(r.ResourceType),
			"scan_region":   region,
			"last_reported": r.LastReportedAt,
		},
	}
}

// parseARNServiceType extracts service + resource type from an ARN:
// arn:aws:s3:::bucket → ("s3","bucket"); arn:aws:ec2:…:instance/i-… →
// ("ec2","instance").
func parseARNServiceType(arn string) (service, typ string) {
	parts := strings.SplitN(arn, ":", 6)
	if len(parts) < 6 || parts[0] != "arn" {
		return "", ""
	}
	service = parts[2]
	res := parts[5]
	if i := strings.IndexAny(res, "/:"); i > 0 {
		typ = res[:i]
	} else {
		typ = res
	}
	if parts[2] == "s3" && typ == "" {
		typ = "bucket"
	}
	return service, typ
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
