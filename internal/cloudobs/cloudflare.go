package cloudobs

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// CloudflareConfig reads edge certificate packs (and optionally Origin CA
// certificates) of a Cloudflare account with an API token that has
// Zone - SSL and Certificates - Read, plus Zone - Zone - Read when Zones
// is empty.
type CloudflareConfig struct {
	Name         string `json:"name"`
	APITokenFile string `json:"api_token_file"`
	// APIToken is the token held in memory (certloomd); it wins over the file.
	APIToken string   `json:"-"`
	Zones    []string `json:"zones,omitempty"` // zone names; empty = every zone the token sees
	OriginCA bool     `json:"origin_ca,omitempty"`
	// APIURL overrides https://api.cloudflare.com/client/v4 (tests,
	// egress proxies), as for the DNS solver.
	APIURL string `json:"api_url,omitempty"`
}

const (
	cloudflareAPI     = "https://api.cloudflare.com/client/v4"
	cloudflarePerPage = 50
)

type cfClient struct {
	hc    *http.Client
	base  string
	token string
}

type cfZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func cloudflareScopes(f CloudflareConfig, h *Hooks) ([]cloudScope, error) {
	tok := []byte(f.APIToken)
	if len(tok) == 0 {
		var err error
		if tok, err = os.ReadFile(f.APITokenFile); err != nil {
			return nil, err
		}
	}
	base := strings.TrimSuffix(f.APIURL, "/")
	if base == "" {
		base = cloudflareAPI
	}
	c := &cfClient{hc: h.HTTPClient, base: base, token: strings.TrimSpace(string(tok))}
	// Zones are resolved when the scope is read, so a zone listing failure
	// is reported like any other read error.
	read := func(ctx context.Context, emit func(agentproto.CloudObject) bool) error {
		zones, err := c.zones(ctx, f.Zones)
		if err != nil {
			return err
		}
		var failed []string
		for _, z := range zones {
			if err := c.readPacks(ctx, z, emit); err != nil {
				failed = append(failed, z.Name+": "+err.Error())
			}
		}
		if len(failed) > 0 {
			return fmt.Errorf("certificate packs: %s", strings.Join(failed, "; "))
		}
		return nil
	}
	scopes := []cloudScope{{provider: agentproto.CloudCloudflareEdge, scope: f.Name, read: read}}
	if f.OriginCA {
		scopes = append(scopes, cloudScope{provider: agentproto.CloudCloudflareOrigin, scope: f.Name,
			read: func(ctx context.Context, emit func(agentproto.CloudObject) bool) error {
				zones, err := c.zones(ctx, f.Zones)
				if err != nil {
					return err
				}
				for _, z := range zones {
					if err := c.readOriginCA(ctx, z, emit); err != nil {
						return fmt.Errorf("%s: %w", z.Name, err)
					}
				}
				return nil
			}})
	}
	return scopes, nil
}

func (c *cfClient) zones(ctx context.Context, names []string) ([]cfZone, error) {
	if len(names) == 0 {
		return cfList[cfZone](ctx, c, "/zones", nil)
	}
	var out []cfZone
	for _, n := range names {
		z, err := cfList[cfZone](ctx, c, "/zones", url.Values{"name": {n}})
		if err != nil {
			return nil, err
		}
		if len(z) == 0 {
			return nil, fmt.Errorf("zone %s not found or not visible to the token", n)
		}
		out = append(out, z...)
	}
	return out, nil
}

type cfPack struct {
	ID                 string   `json:"id"`
	Type               string   `json:"type"`
	Hosts              []string `json:"hosts"`
	Status             string   `json:"status"`
	PrimaryCertificate any      `json:"primary_certificate"` // id; a number on some pack types
	Certificates       []struct {
		ID        any    `json:"id"`
		Status    string `json:"status"`
		ExpiresOn string `json:"expires_on"`
	} `json:"certificates"`
}

func (c *cfClient) readPacks(ctx context.Context, z cfZone, emit func(agentproto.CloudObject) bool) error {
	packs, err := cfList[cfPack](ctx, c, "/zones/"+url.PathEscape(z.ID)+"/ssl/certificate_packs", url.Values{"status": {"all"}})
	if err != nil {
		return err
	}
	for _, p := range packs {
		if !emit(cfPackObject(z, p)) {
			return nil
		}
	}
	return nil
}

// cfPackObject describes a pack from its metadata: the API does not return
// edge certificates themselves.
func cfPackObject(z cfZone, p cfPack) agentproto.CloudObject {
	o := agentproto.CloudObject{ID: z.Name + "/" + p.ID, Name: p.Type + " " + z.Name, DNSNames: sortedUnique(p.Hosts),
		Status: p.Status, Managed: !strings.Contains(p.Type, "custom")}
	// The primary certificate's expiry, else the earliest in the pack.
	earliest := ""
	for _, cert := range p.Certificates {
		exp := normTime(cert.ExpiresOn)
		if exp == "" {
			continue
		}
		if p.PrimaryCertificate != nil && fmt.Sprint(cert.ID) == fmt.Sprint(p.PrimaryCertificate) {
			o.NotAfter = exp
		}
		if earliest == "" || exp < earliest {
			earliest = exp
		}
	}
	if o.NotAfter == "" {
		o.NotAfter = earliest
	}
	switch {
	case strings.HasSuffix(p.Status, "_timed_out"):
		o.Renewal, o.RenewalReason = agentproto.RenewalFailed, p.Status
	case strings.HasPrefix(p.Status, "pending_") && p.Status != "pending_deletion", p.Status == "initializing":
		o.Renewal = agentproto.RenewalPending
	}
	return o
}

type cfOriginCert struct {
	ID          string   `json:"id"`
	Certificate string   `json:"certificate"`
	Hostnames   []string `json:"hostnames"`
	ExpiresOn   string   `json:"expires_on"`
	RequestType string   `json:"request_type"`
}

func (c *cfClient) readOriginCA(ctx context.Context, z cfZone, emit func(agentproto.CloudObject) bool) error {
	certs, err := cfList[cfOriginCert](ctx, c, "/certificates", url.Values{"zone_id": {z.ID}})
	if err != nil {
		return err
	}
	for _, oc := range certs {
		o := agentproto.CloudObject{ID: z.Name + "/" + oc.ID, Name: "origin " + z.Name, DNSNames: sortedUnique(oc.Hostnames),
			NotAfter: normTime(oc.ExpiresOn), ChainPEM: oc.Certificate, NotPubliclyTrusted: true}
		if !emit(o) {
			return nil
		}
	}
	return nil
}

// cfList pages through a Cloudflare v4 list endpoint.
func cfList[T any](ctx context.Context, c *cfClient, p string, q url.Values) ([]T, error) {
	var out []T
	for page := 1; ; page++ {
		v := url.Values{}
		for k, vs := range q {
			v[k] = vs
		}
		v.Set("page", strconv.Itoa(page))
		v.Set("per_page", strconv.Itoa(cloudflarePerPage))
		var env struct {
			Success bool `json:"success"`
			Errors  []struct {
				Code    int    `json:"code"`
				Message string `json:"message"`
			} `json:"errors"`
			Result     []T `json:"result"`
			ResultInfo struct {
				TotalPages int `json:"total_pages"`
			} `json:"result_info"`
		}
		status, err := c.get(ctx, p+"?"+v.Encode(), &env)
		if err != nil {
			return out, err
		}
		if !env.Success || status != http.StatusOK {
			var msgs []string
			for _, e := range env.Errors {
				msgs = append(msgs, fmt.Sprintf("%d %s", e.Code, e.Message))
			}
			return out, fmt.Errorf("GET %s: HTTP %d %s", p, status, strings.Join(msgs, "; "))
		}
		out = append(out, env.Result...)
		if page >= env.ResultInfo.TotalPages || len(env.Result) == 0 || len(out) >= cloudMaxObjects {
			return out, nil
		}
	}
}

func (c *cfClient) get(ctx context.Context, p string, v any) (int, error) {
	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+p, nil)
		if err != nil {
			return 0, err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")
		resp, err := c.hc.Do(req)
		if err != nil {
			return 0, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
		_ = resp.Body.Close()
		if err != nil {
			return 0, err
		}
		if (resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500) && attempt < 4 {
			if err := sleepCtx(ctx, retryAfter(resp, attempt)); err != nil {
				return 0, err
			}
			continue
		}
		if err := json.Unmarshal(body, v); err != nil {
			return resp.StatusCode, fmt.Errorf("GET %s: HTTP %d, unreadable body", p, resp.StatusCode)
		}
		return resp.StatusCode, nil
	}
}
