package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
)

// Configuration objects: teams, probe scopes, endpoints, notification
// channels and ACME issuers. Lookups accept an id or a name unless noted.
// Patch types use nil pointers for "leave unchanged".

// Team owns lineages and endpoints.
type Team struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Contact   string    `json:"contact,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// TeamPatch changes a team.
type TeamPatch struct {
	Name    *string `json:"name,omitempty"`
	Contact *string `json:"contact,omitempty"`
}

// ListTeams lists teams.
func (c *Client) ListTeams(ctx context.Context) ([]Team, error) {
	return getList[Team](ctx, c, "/api/v1/teams")
}

// CreateTeam creates a team.
func (c *Client) CreateTeam(ctx context.Context, name, contact string) (*Team, error) {
	var t Team
	_, err := c.do(ctx, request{method: http.MethodPost, path: "/api/v1/teams", body: map[string]string{"name": name, "contact": contact}}, &t)
	return &t, err
}

// GetTeam returns a team.
func (c *Client) GetTeam(ctx context.Context, idOrName string) (*Team, error) {
	var t Team
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/api/v1/teams/" + ref(idOrName)}, &t)
	return &t, err
}

// UpdateTeam changes a team.
func (c *Client) UpdateTeam(ctx context.Context, idOrName string, p TeamPatch) (*Team, error) {
	var t Team
	_, err := c.do(ctx, request{method: http.MethodPatch, path: "/api/v1/teams/" + ref(idOrName), body: p}, &t)
	return &t, err
}

// DeleteTeam deletes a team that owns nothing.
func (c *Client) DeleteTeam(ctx context.Context, idOrName string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: "/api/v1/teams/" + ref(idOrName)}, nil)
	return err
}

// ScopeConfig limits what the prober may connect to. Loopback, private and
// link-local addresses are refused unless allowed explicitly.
type ScopeConfig struct {
	AllowCIDRs     []string `json:"allow_cidrs,omitempty"`
	AllowHosts     []string `json:"allow_hosts,omitempty"`
	AllowLoopback  bool     `json:"allow_loopback,omitempty"`
	AllowPrivate   bool     `json:"allow_private,omitempty"`
	AllowLinkLocal bool     `json:"allow_link_local,omitempty"`
	Ports          []int    `json:"ports,omitempty"`
}

// Scope is a named probe scope.
type Scope struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Config    ScopeConfig `json:"config"`
	Enabled   bool        `json:"enabled"`
	CreatedAt time.Time   `json:"created_at"`
}

// ScopePatch changes a scope. Config replaces the whole config.
type ScopePatch struct {
	Name   *string      `json:"name,omitempty"`
	Config *ScopeConfig `json:"config,omitempty"`
}

// ListScopes lists scopes.
func (c *Client) ListScopes(ctx context.Context) ([]Scope, error) {
	return getList[Scope](ctx, c, "/api/v1/scopes")
}

// CreateScope creates a scope.
func (c *Client) CreateScope(ctx context.Context, name string, cfg ScopeConfig) (*Scope, error) {
	var s Scope
	_, err := c.do(ctx, request{method: http.MethodPost, path: "/api/v1/scopes", body: map[string]any{"name": name, "config": cfg}}, &s)
	return &s, err
}

// GetScope returns a scope.
func (c *Client) GetScope(ctx context.Context, idOrName string) (*Scope, error) {
	var s Scope
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/api/v1/scopes/" + ref(idOrName)}, &s)
	return &s, err
}

// UpdateScope changes a scope.
func (c *Client) UpdateScope(ctx context.Context, idOrName string, p ScopePatch) (*Scope, error) {
	var s Scope
	_, err := c.do(ctx, request{method: http.MethodPatch, path: "/api/v1/scopes/" + ref(idOrName), body: p}, &s)
	return &s, err
}

// DeleteScope deletes a scope no endpoint uses.
func (c *Client) DeleteScope(ctx context.Context, idOrName string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: "/api/v1/scopes/" + ref(idOrName)}, nil)
	return err
}

// Endpoint is a TLS endpoint certloom probes. Host, Port and SNI identify it
// and cannot change.
type Endpoint struct {
	ID              string     `json:"id"`
	Host            string     `json:"host"`
	Port            int        `json:"port"`
	SNI             string     `json:"sni,omitempty"`
	ScopeID         string     `json:"scope_id"`
	LineageID       *string    `json:"lineage_id,omitempty"`
	TeamID          *string    `json:"team_id,omitempty"`
	IntervalSeconds int        `json:"interval_seconds"`
	Enabled         bool       `json:"enabled"`
	LastObservedAt  *time.Time `json:"last_observed_at,omitempty"`
	Version         int64      `json:"version"`
	CreatedAt       time.Time  `json:"created_at"`
}

// EndpointInput creates an endpoint. Scope, Team and Lineage take an id or
// name. Port defaults to 443 and IntervalSeconds to six hours.
type EndpointInput struct {
	Host            string `json:"host"`
	Port            int    `json:"port,omitempty"`
	SNI             string `json:"sni,omitempty"`
	Scope           string `json:"scope"`
	Team            string `json:"team,omitempty"`
	Lineage         string `json:"lineage,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
}

// EndpointPatch changes an endpoint. An empty Team or Lineage clears it.
type EndpointPatch struct {
	Scope           *string `json:"scope,omitempty"`
	Team            *string `json:"team,omitempty"`
	Lineage         *string `json:"lineage,omitempty"`
	IntervalSeconds *int    `json:"interval_seconds,omitempty"`
	Enabled         *bool   `json:"enabled,omitempty"`
}

// ListEndpoints lists endpoints.
func (c *Client) ListEndpoints(ctx context.Context) ([]Endpoint, error) {
	return getList[Endpoint](ctx, c, "/api/v1/endpoints")
}

// CreateEndpoint registers an endpoint. The host must be allowed by the scope.
func (c *Client) CreateEndpoint(ctx context.Context, in EndpointInput) (*Endpoint, error) {
	var e Endpoint
	_, err := c.do(ctx, request{method: http.MethodPost, path: "/api/v1/endpoints", body: in}, &e)
	return &e, err
}

// GetEndpoint returns an endpoint by id.
func (c *Client) GetEndpoint(ctx context.Context, id string) (*Endpoint, error) {
	var e Endpoint
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/api/v1/endpoints/" + ref(id)}, &e)
	return &e, err
}

// UpdateEndpoint changes an endpoint. If ifVersion is non-zero the update
// fails with a precondition error when the endpoint changed since then.
func (c *Client) UpdateEndpoint(ctx context.Context, id string, p EndpointPatch, ifVersion int64) (*Endpoint, error) {
	var e Endpoint
	_, err := c.do(ctx, request{method: http.MethodPatch, path: "/api/v1/endpoints/" + ref(id), body: p, ifMatch: ifVersion}, &e)
	return &e, err
}

// DeleteEndpoint deletes an endpoint no deployment uses for verification.
func (c *Client) DeleteEndpoint(ctx context.Context, id string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: "/api/v1/endpoints/" + ref(id)}, nil)
	return err
}

// Channel is a notification channel. It never holds a secret: CredentialRef
// names where the server finds one, such as env:CERTLOOM_WEBHOOK_SECRET.
type Channel struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Kind          string          `json:"kind"` // webhook, email
	Config        json.RawMessage `json:"config"`
	CredentialRef string          `json:"credential_ref,omitempty"`
	MinSeverity   string          `json:"min_severity"`
	Enabled       bool            `json:"enabled"`
	CreatedAt     time.Time       `json:"created_at"`
}

// ChannelInput creates a channel.
type ChannelInput struct {
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`
	Config        json.RawMessage `json:"config"`
	CredentialRef string          `json:"credential_ref,omitempty"`
	MinSeverity   string          `json:"min_severity,omitempty"`
}

// ChannelPatch changes a channel. Config replaces the whole config; the kind
// is fixed.
type ChannelPatch struct {
	Name          *string         `json:"name,omitempty"`
	Config        json.RawMessage `json:"config,omitempty"`
	CredentialRef *string         `json:"credential_ref,omitempty"`
	MinSeverity   *string         `json:"min_severity,omitempty"`
	Enabled       *bool           `json:"enabled,omitempty"`
}

// ListChannels lists channels.
func (c *Client) ListChannels(ctx context.Context) ([]Channel, error) {
	return getList[Channel](ctx, c, "/api/v1/channels")
}

// CreateChannel creates a channel. New channels are enabled.
func (c *Client) CreateChannel(ctx context.Context, in ChannelInput) (*Channel, error) {
	var ch Channel
	_, err := c.do(ctx, request{method: http.MethodPost, path: "/api/v1/channels", body: in}, &ch)
	return &ch, err
}

// GetChannel returns a channel by id.
func (c *Client) GetChannel(ctx context.Context, id string) (*Channel, error) {
	var ch Channel
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/api/v1/channels/" + ref(id)}, &ch)
	return &ch, err
}

// UpdateChannel changes a channel. A channel named in the active policy
// cannot be renamed.
func (c *Client) UpdateChannel(ctx context.Context, id string, p ChannelPatch) (*Channel, error) {
	var ch Channel
	_, err := c.do(ctx, request{method: http.MethodPatch, path: "/api/v1/channels/" + ref(id), body: p}, &ch)
	return &ch, err
}

// DeleteChannel deletes a channel the active policy does not name.
func (c *Client) DeleteChannel(ctx context.Context, id string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: "/api/v1/channels/" + ref(id)}, nil)
	return err
}

// Issuer is an ACME CA account configuration.
type Issuer struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	Kind         string     `json:"kind"`
	DirectoryURL string     `json:"directory_url"`
	Email        string     `json:"email,omitempty"`
	AgreeTOS     bool       `json:"agree_tos"`
	Profile      string     `json:"profile,omitempty"`
	EABMode      string     `json:"eab_mode"`
	EABKID       string     `json:"eab_kid,omitempty"`
	HasEABHMAC   bool       `json:"has_eab_hmac,omitempty"`
	EABUpdatedAt *time.Time `json:"eab_updated_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// IssuerInput creates an issuer. AgreeTOS must be true: it records that you
// accept the CA's terms of service.
type IssuerInput struct {
	Name         string `json:"name"`
	DirectoryURL string `json:"directory_url"`
	Email        string `json:"email,omitempty"`
	AgreeTOS     bool   `json:"agree_tos"`
	Profile      string `json:"profile,omitempty"`
}

// IssuerPatch changes an issuer. The directory URL is fixed.
type IssuerPatch struct {
	Name    *string `json:"name,omitempty"`
	Email   *string `json:"email,omitempty"`
	Profile *string `json:"profile,omitempty"`
}

// ListIssuers lists issuers.
func (c *Client) ListIssuers(ctx context.Context) ([]Issuer, error) {
	return getList[Issuer](ctx, c, "/api/v1/issuers")
}

// CreateIssuer creates an issuer.
func (c *Client) CreateIssuer(ctx context.Context, in IssuerInput) (*Issuer, error) {
	var i Issuer
	_, err := c.do(ctx, request{method: http.MethodPost, path: "/api/v1/issuers", body: in}, &i)
	return &i, err
}

// GetIssuer returns an issuer.
func (c *Client) GetIssuer(ctx context.Context, idOrName string) (*Issuer, error) {
	var i Issuer
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/api/v1/issuers/" + ref(idOrName)}, &i)
	return &i, err
}

// UpdateIssuer changes an issuer.
func (c *Client) UpdateIssuer(ctx context.Context, idOrName string, p IssuerPatch) (*Issuer, error) {
	var i Issuer
	_, err := c.do(ctx, request{method: http.MethodPatch, path: "/api/v1/issuers/" + ref(idOrName), body: p}, &i)
	return &i, err
}

// DeleteIssuer deletes an issuer no deployment or EAB key uses.
func (c *Client) DeleteIssuer(ctx context.Context, idOrName string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: "/api/v1/issuers/" + ref(idOrName)}, nil)
	return err
}

// dryRunQuery returns the query for plan-only document requests.
func dryRunQuery(on bool) url.Values {
	if on {
		return url.Values{"dry_run": {"true"}}
	}
	return nil
}
