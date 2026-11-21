package agent

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"golang.org/x/oauth2"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// CloudConfig turns on read-only observation of cloud certificate services
// (ADR-0024). Credentials come from each provider's ambient identity unless
// a file is named.
type CloudConfig struct {
	// IntervalSeconds is how often the control plane should ask for an
	// inventory; default 3600, at least 300.
	IntervalSeconds int                `json:"interval_seconds,omitempty"`
	AWS             []AWSAccountConfig `json:"aws,omitempty"`
	Azure           []AzureConfig      `json:"azure,omitempty"`
	GCP             []GCPConfig        `json:"gcp,omitempty"`
	Cloudflare      []CloudflareConfig `json:"cloudflare,omitempty"`
}

const (
	cloudDefaultInterval = 3600
	cloudMinInterval     = 300
	// cloudMaxObjects bounds one inventory; a scope with more is reported
	// as truncated.
	cloudMaxObjects   = 20000
	cloudScopeTimeout = 10 * time.Minute
)

func (c *Config) validateCloud() []string {
	cc := c.Cloud
	var p []string
	if cc.IntervalSeconds != 0 && cc.IntervalSeconds < cloudMinInterval {
		p = append(p, fmt.Sprintf("cloud.interval_seconds must be at least %d", cloudMinInterval))
	}
	if len(cc.AWS)+len(cc.Azure)+len(cc.GCP)+len(cc.Cloudflare) == 0 {
		p = append(p, "cloud: configure at least one of aws, azure, gcp, cloudflare")
	}
	names := map[string]bool{}
	name := func(kind, n string) {
		switch {
		case n == "" || strings.ContainsAny(n, "/ "):
			p = append(p, fmt.Sprintf("cloud.%s: name %q must be non-empty without / or spaces", kind, n))
		case names[kind+"/"+n]:
			p = append(p, fmt.Sprintf("cloud.%s: duplicate name %s", kind, n))
		}
		names[kind+"/"+n] = true
	}
	file := func(where, f string) {
		if f != "" && !filepath.IsAbs(f) {
			p = append(p, where+" must be an absolute path")
		}
	}
	for _, a := range cc.AWS {
		name("aws", a.Name)
		if len(a.Regions) == 0 {
			p = append(p, "cloud.aws "+a.Name+": regions is required")
		}
		if a.ExternalID != "" && a.AssumeRoleARN == "" {
			p = append(p, "cloud.aws "+a.Name+": external_id needs assume_role_arn")
		}
		file("cloud.aws "+a.Name+": credentials_file", a.CredentialsFile)
		p = append(p, endpointProblem("cloud.aws "+a.Name+": endpoint_url", a.EndpointURL)...)
	}
	for _, a := range cc.Azure {
		name("azure", a.Name)
		p = append(p, a.validate()...)
	}
	for _, g := range cc.GCP {
		name("gcp", g.Name)
		p = append(p, g.validate()...)
	}
	for _, f := range cc.Cloudflare {
		name("cloudflare", f.Name)
		if !filepath.IsAbs(f.APITokenFile) {
			p = append(p, "cloud.cloudflare "+f.Name+": api_token_file must be an absolute path")
		}
		p = append(p, endpointProblem("cloud.cloudflare "+f.Name+": api_url", f.APIURL)...)
	}
	return p
}

// endpointProblem checks an endpoint override (for private endpoints and
// emulators): https, or http only to the local host.
func endpointProblem(where, u string) []string {
	if u == "" || strings.HasPrefix(u, "https://") ||
		strings.HasPrefix(u, "http://127.0.0.1") || strings.HasPrefix(u, "http://localhost") || strings.HasPrefix(u, "http://[::1]") {
		return nil
	}
	return []string{where + " must be https (http only to the local host)"}
}

// cloudScope collects the objects of one provider scope.
type cloudScope struct {
	provider, scope string
	read            func(ctx context.Context, emit func(agentproto.CloudObject) bool) error
}

// inventoryCloud reads every configured scope. A scope that fails is
// reported with its error and does not stop the others.
func (a *Agent) inventoryCloud(ctx context.Context) *agentproto.CloudInventory {
	out := &agentproto.CloudInventory{Objects: []agentproto.CloudObject{}}
	for _, sc := range a.cloudScopes(ctx, out) {
		sctx, cancel := context.WithTimeout(ctx, cloudScopeTimeout)
		truncated := false
		err := sc.read(sctx, func(o agentproto.CloudObject) bool {
			if len(out.Objects) >= cloudMaxObjects {
				truncated = true
				return false
			}
			o.Provider, o.Scope = sc.provider, sc.scope
			out.Objects = append(out.Objects, o)
			return true
		})
		cancel()
		if err == nil && truncated {
			err = fmt.Errorf("more than %d objects; the rest were not read", cloudMaxObjects)
		}
		if err != nil {
			out.Errors = append(out.Errors, agentproto.CloudScopeError{Provider: sc.provider, Scope: sc.scope, Error: err.Error()})
			a.log.Warn("cloud inventory", "provider", sc.provider, "scope", sc.scope, "err", err)
		}
	}
	return out
}

// cloudScopes builds the readers. Setup failures (bad credentials file,
// unknown profile) are recorded against every scope of that entry.
func (a *Agent) cloudScopes(ctx context.Context, out *agentproto.CloudInventory) []cloudScope {
	cc := a.cfg.Cloud
	h := a.cloudTest
	if h == nil {
		h = &cloudHooks{}
	}
	if h.hc == nil {
		h.hc = cloudHTTPClient()
	}
	var scopes []cloudScope
	fail := func(provider string, scopeNames []string, err error) {
		for _, s := range scopeNames {
			out.Errors = append(out.Errors, agentproto.CloudScopeError{Provider: provider, Scope: s, Error: err.Error()})
		}
	}
	for _, acct := range cc.AWS {
		s, err := awsScopes(ctx, acct, h.hc)
		if err != nil {
			fail(agentproto.CloudAWSACM, acct.scopeNames(), err)
			continue
		}
		scopes = append(scopes, s...)
	}
	for _, az := range cc.Azure {
		s, err := azureScopes(az, h)
		if err != nil {
			fail(agentproto.CloudAzureKeyVault, az.Vaults, err)
			continue
		}
		scopes = append(scopes, s...)
	}
	for _, g := range cc.GCP {
		s, err := gcpScopes(ctx, g, h)
		if err != nil {
			fail(agentproto.CloudGCPCertManager, g.scopeNames(), err)
			continue
		}
		scopes = append(scopes, s...)
	}
	for _, f := range cc.Cloudflare {
		s, err := cloudflareScopes(f, h)
		if err != nil {
			fail(agentproto.CloudCloudflareEdge, []string{f.Name}, err)
			continue
		}
		scopes = append(scopes, s...)
	}
	return scopes
}

// cloudHooks lets tests point providers at fake servers.
type cloudHooks struct {
	hc        *http.Client
	azureCred azcore.TokenCredential
	// azureAnyResource accepts a token challenge from a host that is not a
	// Key Vault domain (a test server).
	azureAnyResource bool
	gcpTokens        oauth2.TokenSource
	// gcpBase maps a Google API host to a test server URL.
	gcpBase map[string]string
}

// cloudHTTPClient is the client for provider calls when no test client is
// set: no cookies, sane timeouts, proxy from the environment.
func cloudHTTPClient() *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = time.Minute
	return &http.Client{Transport: t, Timeout: 2 * time.Minute}
}

func rfc3339(t *time.Time) string {
	if t == nil || t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func sortedUnique(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return slices.Compact(s)
}
