package cloudobs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// GCPConfig is one Google Cloud project. Credentials are Application
// Default Credentials (metadata server, GOOGLE_APPLICATION_CREDENTIALS)
// unless CredentialsFile names a service account key or a workload
// identity federation config.
type GCPConfig struct {
	Name      string   `json:"name"`
	Project   string   `json:"project"`
	Locations []string `json:"locations,omitempty"` // default ["global"]
	// CertificateManager defaults to true; CAS lists CA Service authorities.
	CertificateManager *bool  `json:"certificate_manager,omitempty"`
	CAS                bool   `json:"cas,omitempty"`
	CredentialsFile    string `json:"credentials_file,omitempty"`
	// CredentialsJSON is a service account key held in memory (certloomd).
	CredentialsJSON []byte `json:"-"`
}

const (
	gcpScope       = "https://www.googleapis.com/auth/cloud-platform"
	gcpCertManager = "certificatemanager.googleapis.com"
	gcpPrivateCA   = "privateca.googleapis.com"
	gcpPageSize    = 500
)

func (g GCPConfig) locations() []string {
	if len(g.Locations) == 0 {
		return []string{"global"}
	}
	return g.Locations
}

func (g GCPConfig) scopeNames() []string {
	var s []string
	for _, l := range g.locations() {
		s = append(s, g.Project+"/"+l)
	}
	return s
}

func (g GCPConfig) validate() []string {
	var p []string
	w := "cloud.gcp " + g.Name
	if g.Project == "" || strings.ContainsAny(g.Project, "/ ") {
		p = append(p, w+": project id is required")
	}
	for _, l := range g.Locations {
		if l == "" || strings.ContainsAny(l, "/ ") {
			p = append(p, w+": invalid location "+strconv.Quote(l))
		}
	}
	if g.CertificateManager != nil && !*g.CertificateManager && !g.CAS {
		p = append(p, w+": nothing to read; enable certificate_manager or cas")
	}
	if g.CredentialsFile != "" && !filepath.IsAbs(g.CredentialsFile) {
		p = append(p, w+": credentials_file must be an absolute path")
	}
	return p
}

func (g GCPConfig) tokenSource(ctx context.Context) (oauth2.TokenSource, error) {
	if len(g.CredentialsJSON) > 0 {
		// Only plain keys: federation configs can name local files and
		// token endpoints, which a stored credential must not.
		c, err := google.CredentialsFromJSONWithType(ctx, g.CredentialsJSON, google.ServiceAccount, gcpScope)
		if err != nil {
			return nil, err
		}
		return c.TokenSource, nil
	}
	if g.CredentialsFile == "" {
		c, err := google.FindDefaultCredentials(ctx, gcpScope)
		if err != nil {
			return nil, err
		}
		return c.TokenSource, nil
	}
	b, err := os.ReadFile(g.CredentialsFile)
	if err != nil {
		return nil, err
	}
	var head struct {
		Type google.CredentialsType `json:"type"`
	}
	if err := json.Unmarshal(b, &head); err != nil {
		return nil, fmt.Errorf("%s: %w", g.CredentialsFile, err)
	}
	// Only key and federation files; other types can point at arbitrary
	// token endpoints.
	switch head.Type {
	case google.ServiceAccount, google.ExternalAccount, google.ImpersonatedServiceAccount:
	default:
		return nil, fmt.Errorf("%s: credential type %q is not supported", g.CredentialsFile, head.Type)
	}
	c, err := google.CredentialsFromJSONWithType(ctx, b, head.Type, gcpScope)
	if err != nil {
		return nil, err
	}
	return c.TokenSource, nil
}

type gcpClient struct {
	hc   *http.Client
	ts   oauth2.TokenSource
	base map[string]string
}

func gcpScopes(ctx context.Context, g GCPConfig, h *Hooks) ([]cloudScope, error) {
	ts := h.GCPTokens
	if ts == nil {
		// Token requests go through the same client (proxy, timeouts).
		var err error
		ts, err = g.tokenSource(context.WithValue(ctx, oauth2.HTTPClient, h.HTTPClient))
		if err != nil {
			return nil, err
		}
	}
	c := &gcpClient{hc: h.HTTPClient, ts: ts, base: h.GCPBase}
	var scopes []cloudScope
	for _, loc := range g.locations() {
		parent := "projects/" + g.Project + "/locations/" + loc
		scope := g.Project + "/" + loc
		if g.CertificateManager == nil || *g.CertificateManager {
			scopes = append(scopes, cloudScope{provider: agentproto.CloudGCPCertManager, scope: scope,
				read: func(ctx context.Context, emit func(agentproto.CloudObject) bool) error {
					return c.readCertManager(ctx, parent, emit)
				}})
		}
		if g.CAS {
			scopes = append(scopes, cloudScope{provider: agentproto.CloudGCPCAS, scope: scope,
				read: func(ctx context.Context, emit func(agentproto.CloudObject) bool) error {
					return c.readCAS(ctx, parent, emit)
				}})
		}
	}
	return scopes, nil
}

func (c *gcpClient) url(host, p string, q url.Values) string {
	base := "https://" + host
	if b, ok := c.base[host]; ok {
		base = b
	}
	return base + "/v1/" + p + "?" + q.Encode()
}

// list pages through a Google list method and decodes the items under
// field into T.
func gcpList[T any](ctx context.Context, c *gcpClient, host, p, field string) ([]T, error) {
	var out []T
	tok := ""
	for {
		q := url.Values{"pageSize": {strconv.Itoa(gcpPageSize)}}
		if tok != "" {
			q.Set("pageToken", tok)
		}
		var page map[string]json.RawMessage
		if err := c.get(ctx, c.url(host, p, q), &page); err != nil {
			return out, err
		}
		if raw, ok := page[field]; ok {
			var items []T
			if err := json.Unmarshal(raw, &items); err != nil {
				return out, err
			}
			out = append(out, items...)
		}
		if raw, ok := page["unreachable"]; ok && string(raw) != "[]" {
			return out, fmt.Errorf("locations unreachable: %s", raw)
		}
		tok = ""
		if raw, ok := page["nextPageToken"]; ok {
			_ = json.Unmarshal(raw, &tok)
		}
		if tok == "" || len(out) >= cloudMaxObjects {
			return out, nil
		}
	}
}

func (c *gcpClient) get(ctx context.Context, u string, v any) error {
	for attempt := 0; ; attempt++ {
		t, err := c.ts.Token()
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
		if err != nil {
			return err
		}
		t.SetAuthHeader(req)
		req.Header.Set("Accept", "application/json")
		resp, err := c.hc.Do(req)
		if err != nil {
			return err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		_ = resp.Body.Close()
		if err != nil {
			return err
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < 4 {
			if err := sleepCtx(ctx, retryAfter(resp, attempt)); err != nil {
				return err
			}
			continue
		}
		if resp.StatusCode != http.StatusOK {
			var e struct {
				Error struct {
					Status, Message string
				} `json:"error"`
			}
			_ = json.Unmarshal(body, &e)
			return fmt.Errorf("GET %s: %d %s %s", path.Base(strings.SplitN(u, "?", 2)[0]), resp.StatusCode, e.Error.Status, e.Error.Message)
		}
		return json.Unmarshal(body, v)
	}
}

type gcpCertificate struct {
	Name           string   `json:"name"`
	SANDNSNames    []string `json:"sanDnsnames"`
	PEMCertificate string   `json:"pemCertificate"`
	ExpireTime     string   `json:"expireTime"`
	UpdateTime     string   `json:"updateTime"`
	UsedBy         []struct {
		Name string `json:"name"`
	} `json:"usedBy"`
	Managed *struct {
		State             string `json:"state"`
		ProvisioningIssue *struct {
			Reason  string `json:"reason"`
			Details string `json:"details"`
		} `json:"provisioningIssue"`
		AuthorizationAttemptInfo []struct {
			Domain        string `json:"domain"`
			State         string `json:"state"`
			FailureReason string `json:"failureReason"`
			Details       string `json:"details"`
		} `json:"authorizationAttemptInfo"`
	} `json:"managed"`
}

type gcpMapEntry struct {
	Name         string   `json:"name"`
	Hostname     string   `json:"hostname"`
	Matcher      string   `json:"matcher"`
	Certificates []string `json:"certificates"`
}

func (c *gcpClient) readCertManager(ctx context.Context, parent string, emit func(agentproto.CloudObject) bool) error {
	certs, err := gcpList[gcpCertificate](ctx, c, gcpCertManager, parent+"/certificates", "certificates")
	if err != nil {
		return err
	}
	// Map entries say which hostnames a certificate serves; usedBy is
	// filled only for some attachment types.
	maps, err := gcpList[struct {
		Name string `json:"name"`
	}](ctx, c, gcpCertManager, parent+"/certificateMaps", "certificateMaps")
	if err != nil {
		return err
	}
	servedAs := map[string][]string{}
	for _, m := range maps {
		entries, err := gcpList[gcpMapEntry](ctx, c, gcpCertManager, m.Name+"/certificateMapEntries", "certificateMapEntries")
		if err != nil {
			return err
		}
		for _, e := range entries {
			host := e.Hostname
			if host == "" {
				host = e.Matcher
			}
			for _, cn := range e.Certificates {
				servedAs[cn] = append(servedAs[cn], path.Base(m.Name)+": "+host)
			}
		}
	}
	for _, gc := range certs {
		if !emit(gcpCertObject(gc, servedAs[gc.Name])) {
			return nil
		}
	}
	return nil
}

func gcpCertObject(gc gcpCertificate, servedAs []string) agentproto.CloudObject {
	o := agentproto.CloudObject{ID: gc.Name, Name: path.Base(gc.Name), DNSNames: sortedUnique(gc.SANDNSNames),
		NotAfter: normTime(gc.ExpireTime), ChainPEM: gc.PEMCertificate}
	for _, u := range gc.UsedBy {
		o.InUseBy = append(o.InUseBy, u.Name)
	}
	o.InUseBy = sortedUnique(append(o.InUseBy, servedAs...))
	if m := gc.Managed; m != nil {
		o.Managed, o.Status = true, m.State
		var reasons []string
		if m.ProvisioningIssue != nil {
			reasons = append(reasons, strings.TrimSpace(m.ProvisioningIssue.Reason+" "+m.ProvisioningIssue.Details))
		}
		for _, a := range m.AuthorizationAttemptInfo {
			if a.State == "FAILED" {
				reasons = append(reasons, strings.TrimSpace(a.Domain+": "+a.FailureReason+" "+a.Details))
			}
		}
		switch {
		case m.State == "FAILED" || (len(reasons) > 0 && m.State != "ACTIVE"):
			o.Renewal = agentproto.RenewalFailed
		case m.State == "PROVISIONING":
			o.Renewal = agentproto.RenewalPending
		}
		if o.Renewal != "" {
			o.RenewalReason, o.RenewalSince = strings.Join(reasons, "; "), normTime(gc.UpdateTime)
		}
	}
	return o
}

type gcpCA struct {
	Name              string   `json:"name"`
	State             string   `json:"state"`
	PEMCACertificates []string `json:"pemCaCertificates"`
	ExpireTime        string   `json:"expireTime"`
}

func (c *gcpClient) readCAS(ctx context.Context, parent string, emit func(agentproto.CloudObject) bool) error {
	pools, err := gcpList[struct {
		Name string `json:"name"`
	}](ctx, c, gcpPrivateCA, parent+"/caPools", "caPools")
	if err != nil {
		return err
	}
	for _, p := range pools {
		cas, err := gcpList[gcpCA](ctx, c, gcpPrivateCA, p.Name+"/certificateAuthorities", "certificateAuthorities")
		if err != nil {
			return err
		}
		for _, ca := range cas {
			o := agentproto.CloudObject{ID: ca.Name, Name: path.Base(ca.Name), CA: true, Status: ca.State,
				NotAfter: normTime(ca.ExpireTime), ChainPEM: joinPEM(ca.PEMCACertificates...)}
			if !emit(o) {
				return nil
			}
		}
	}
	return nil
}

// normTime turns a provider timestamp into the second-precision UTC
// RFC 3339 form used in the protocol. Go's time.String form is accepted
// as a fallback.
func normTime(s string) string {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999 -0700 MST"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}

// retryAfter honours Retry-After in seconds, else backs off exponentially.
func retryAfter(resp *http.Response, attempt int) time.Duration {
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s >= 0 && s <= 300 {
		return time.Duration(s) * time.Second
	}
	return time.Duration(1<<attempt) * time.Second
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
