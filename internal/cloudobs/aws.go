package cloudobs

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
	"github.com/aws/aws-sdk-go-v2/service/acmpca"
	pcatypes "github.com/aws/aws-sdk-go-v2/service/acmpca/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// AWSAccountConfig is one AWS account read through the SDK's default
// credential chain, optionally narrowed to a profile or a shared
// credentials file, and optionally through an assumed role.
type AWSAccountConfig struct {
	Name            string   `json:"name"`
	Regions         []string `json:"regions"`
	Profile         string   `json:"profile,omitempty"`
	CredentialsFile string   `json:"credentials_file,omitempty"`
	AssumeRoleARN   string   `json:"assume_role_arn,omitempty"`
	ExternalID      string   `json:"external_id,omitempty"`
	// PrivateCA also lists AWS Private CA authorities.
	PrivateCA bool `json:"private_ca,omitempty"`
	// EndpointURL overrides the service endpoint (VPC endpoints,
	// emulators). It applies to ACM and Private CA alike.
	EndpointURL string `json:"endpoint_url,omitempty"`
	// AccessKeyID and SecretAccessKey are a static key held in memory
	// (certloomd); SessionName names assumed-role sessions.
	AccessKeyID     string `json:"-"`
	SecretAccessKey string `json:"-"`
	SessionName     string `json:"-"`
}

func (a AWSAccountConfig) scopeNames() []string {
	var s []string
	for _, r := range a.Regions {
		s = append(s, a.Name+"/"+r)
	}
	return s
}

func awsScopes(ctx context.Context, acct AWSAccountConfig, hc *http.Client) ([]cloudScope, error) {
	opts := []func(*config.LoadOptions) error{}
	if acct.Profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(acct.Profile))
	}
	if acct.CredentialsFile != "" {
		opts = append(opts, config.WithSharedCredentialsFiles([]string{acct.CredentialsFile}))
	}
	if acct.AccessKeyID != "" {
		opts = append(opts, config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(acct.AccessKeyID, acct.SecretAccessKey, "")))
	}
	if hc == nil {
		hc = cloudHTTPClient()
	}
	opts = append(opts, config.WithHTTPClient(hc), config.WithRetryMaxAttempts(5))
	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, err
	}
	if acct.AssumeRoleARN != "" {
		cfg.Credentials = aws.NewCredentialsCache(stscreds.NewAssumeRoleProvider(sts.NewFromConfig(cfg), acct.AssumeRoleARN,
			func(o *stscreds.AssumeRoleOptions) {
				o.RoleSessionName = "certloom-agent"
				if acct.SessionName != "" {
					o.RoleSessionName = acct.SessionName
				}
				if acct.ExternalID != "" {
					o.ExternalID = aws.String(acct.ExternalID)
				}
			}))
	}
	var scopes []cloudScope
	for _, region := range acct.Regions {
		rc := cfg.Copy()
		rc.Region = region
		if acct.EndpointURL != "" {
			rc.BaseEndpoint = aws.String(acct.EndpointURL)
		}
		scope := acct.Name + "/" + region
		cm := acm.NewFromConfig(rc)
		scopes = append(scopes, cloudScope{provider: agentproto.CloudAWSACM, scope: scope,
			read: func(ctx context.Context, emit func(agentproto.CloudObject) bool) error { return readACM(ctx, cm, emit) }})
		if acct.PrivateCA {
			pca := acmpca.NewFromConfig(rc)
			scopes = append(scopes, cloudScope{provider: agentproto.CloudAWSPCA, scope: scope,
				read: func(ctx context.Context, emit func(agentproto.CloudObject) bool) error {
					return readPCA(ctx, pca, emit)
				}})
		}
	}
	return scopes, nil
}

// acmAPI is the part of the ACM client used here; nothing in it returns a
// private key.
type acmAPI interface {
	acm.ListCertificatesAPIClient
	DescribeCertificate(context.Context, *acm.DescribeCertificateInput, ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
	GetCertificate(context.Context, *acm.GetCertificateInput, ...func(*acm.Options)) (*acm.GetCertificateOutput, error)
}

func readACM(ctx context.Context, c acmAPI, emit func(agentproto.CloudObject) bool) error {
	// Without Includes, ListCertificates returns only RSA 1024 and 2048
	// certificates.
	in := &acm.ListCertificatesInput{Includes: &acmtypes.Filters{KeyTypes: acmtypes.KeyAlgorithm("").Values()}}
	p := acm.NewListCertificatesPaginator(c, in)
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, s := range page.CertificateSummaryList {
			d, err := c.DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: s.CertificateArn})
			if err != nil {
				var nf *acmtypes.ResourceNotFoundException
				if errors.As(err, &nf) {
					continue // deleted since the list call
				}
				return err
			}
			o := acmObject(d.Certificate)
			if d.Certificate.Status == acmtypes.CertificateStatusIssued {
				g, err := c.GetCertificate(ctx, &acm.GetCertificateInput{CertificateArn: s.CertificateArn})
				if err != nil {
					return err
				}
				o.ChainPEM = joinPEM(aws.ToString(g.Certificate), aws.ToString(g.CertificateChain))
			}
			if !emit(o) {
				return nil
			}
		}
	}
	return nil
}

func acmObject(d *acmtypes.CertificateDetail) agentproto.CloudObject {
	o := agentproto.CloudObject{
		ID:       aws.ToString(d.CertificateArn),
		Name:     aws.ToString(d.DomainName),
		DNSNames: sortedUnique(d.SubjectAlternativeNames),
		NotAfter: rfc3339(d.NotAfter),
		Status:   string(d.Status),
		InUseBy:  d.InUseBy,
		// ACM renews certificates it issued while they are eligible, which
		// in practice means in use. Imported ones are never renewed.
		Managed: d.Type != acmtypes.CertificateTypeImported && d.RenewalEligibility == acmtypes.RenewalEligibilityEligible,
	}
	switch d.Status {
	case acmtypes.CertificateStatusPendingValidation:
		o.Renewal, o.RenewalSince = agentproto.RenewalPending, rfc3339(d.CreatedAt)
	case acmtypes.CertificateStatusFailed, acmtypes.CertificateStatusValidationTimedOut:
		o.Renewal, o.RenewalReason, o.RenewalSince = agentproto.RenewalFailed, string(d.FailureReason), rfc3339(d.CreatedAt)
	}
	if r := d.RenewalSummary; r != nil {
		switch r.RenewalStatus {
		case acmtypes.RenewalStatusFailed:
			o.Renewal, o.RenewalReason = agentproto.RenewalFailed, string(r.RenewalStatusReason)
		case acmtypes.RenewalStatusPendingValidation:
			o.Renewal, o.RenewalReason = agentproto.RenewalPending, string(r.RenewalStatusReason)
		}
		if o.Renewal != "" {
			o.RenewalSince = rfc3339(r.UpdatedAt)
		}
	}
	return o
}

type pcaAPI interface {
	acmpca.ListCertificateAuthoritiesAPIClient
	GetCertificateAuthorityCertificate(context.Context, *acmpca.GetCertificateAuthorityCertificateInput, ...func(*acmpca.Options)) (*acmpca.GetCertificateAuthorityCertificateOutput, error)
}

func readPCA(ctx context.Context, c pcaAPI, emit func(agentproto.CloudObject) bool) error {
	p := acmpca.NewListCertificateAuthoritiesPaginator(c, &acmpca.ListCertificateAuthoritiesInput{})
	for p.HasMorePages() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, ca := range page.CertificateAuthorities {
			o := agentproto.CloudObject{ID: aws.ToString(ca.Arn), CA: true, NotAfter: rfc3339(ca.NotAfter), Status: string(ca.Status)}
			if cfg := ca.CertificateAuthorityConfiguration; cfg != nil && cfg.Subject != nil {
				o.Name = aws.ToString(cfg.Subject.CommonName)
			}
			switch ca.Status {
			case pcatypes.CertificateAuthorityStatusActive, pcatypes.CertificateAuthorityStatusDisabled, pcatypes.CertificateAuthorityStatusExpired:
				g, err := c.GetCertificateAuthorityCertificate(ctx, &acmpca.GetCertificateAuthorityCertificateInput{CertificateAuthorityArn: ca.Arn})
				if err != nil {
					return err
				}
				o.ChainPEM = joinPEM(aws.ToString(g.Certificate), aws.ToString(g.CertificateChain))
			}
			if !emit(o) {
				return nil
			}
		}
	}
	return nil
}

func joinPEM(parts ...string) string {
	var b strings.Builder
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			b.WriteString(p)
			b.WriteString("\n")
		}
	}
	return b.String()
}
