package client

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Policy and certificate templates are versioned YAML (or JSON) documents.
// Applying one returns a plan of what changes; with dryRun nothing is stored.

// Policy is the active monitoring policy. Version 0 means the built-in
// defaults are in effect.
type Policy struct {
	Version   int             `json:"version"`
	Document  json.RawMessage `json:"document"`
	Source    string          `json:"source,omitempty"`
	CreatedBy string          `json:"created_by,omitempty"`
	CreatedAt *time.Time      `json:"created_at,omitempty"`
}

// PolicyPlan reports the effect of a policy document.
type PolicyPlan struct {
	Applied        bool            `json:"applied"`
	Version        int             `json:"version,omitempty"`
	CurrentVersion int             `json:"current_version"`
	Evaluated      int             `json:"certificates_evaluated"`
	Changes        json.RawMessage `json:"changes"`
	Document       json.RawMessage `json:"document"`
}

// GetPolicy returns the active policy.
func (c *Client) GetPolicy(ctx context.Context) (*Policy, error) {
	var p Policy
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/api/v1/policy"}, &p)
	return &p, err
}

// ApplyPolicy validates src and, unless dryRun, stores it as a new version.
func (c *Client) ApplyPolicy(ctx context.Context, src []byte, dryRun bool) (*PolicyPlan, error) {
	var p PolicyPlan
	_, err := c.do(ctx, request{method: http.MethodPut, path: "/api/v1/policy", query: dryRunQuery(dryRun),
		raw: src, contentType: "application/yaml"}, &p)
	return &p, err
}

// Template is a certificate template at its current version.
type Template struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Version     int             `json:"version"`
	Document    json.RawMessage `json:"document"`
	Source      string          `json:"source"`
	UpdatedBy   string          `json:"updated_by"`
	UpdatedAt   time.Time       `json:"updated_at"`
	CreatedAt   time.Time       `json:"created_at"`
	Deployments int             `json:"deployments"`
}

// TemplatePlan reports the effect of a template document on the
// deployments that use it. A template with violations is not applied.
type TemplatePlan struct {
	Applied        bool            `json:"applied"`
	Name           string          `json:"name"`
	Version        int             `json:"version,omitempty"`
	CurrentVersion int             `json:"current_version"`
	Changes        json.RawMessage `json:"changes"`
	Violations     json.RawMessage `json:"violations"`
	Document       json.RawMessage `json:"document"`
}

// ListTemplates lists templates.
func (c *Client) ListTemplates(ctx context.Context) ([]Template, error) {
	return getList[Template](ctx, c, "/api/v1/templates")
}

// GetTemplate returns a template.
func (c *Client) GetTemplate(ctx context.Context, idOrName string) (*Template, error) {
	var t Template
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/api/v1/templates/" + ref(idOrName)}, &t)
	return &t, err
}

// ApplyTemplate creates or updates the template named in src.
func (c *Client) ApplyTemplate(ctx context.Context, src []byte, dryRun bool) (*TemplatePlan, error) {
	var p TemplatePlan
	_, err := c.do(ctx, request{method: http.MethodPut, path: "/api/v1/templates", query: dryRunQuery(dryRun),
		raw: src, contentType: "application/yaml"}, &p)
	return &p, err
}

// DeleteTemplate deletes a template no deployment uses.
func (c *Client) DeleteTemplate(ctx context.Context, idOrName string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: "/api/v1/templates/" + ref(idOrName)}, nil)
	return err
}

// DNSSolver answers ACME DNS-01 challenges for its zones. A stored secret
// is never returned; HasSecret and SecretUpdatedAt show whether one is set.
type DNSSolver struct {
	ID              string         `json:"id"`
	Name            string         `json:"name"`
	Provider        string         `json:"provider"` // rfc2136, cloudflare, plugin
	Plugin          string         `json:"plugin,omitempty"`
	PluginSHA256    string         `json:"plugin_sha256,omitempty"`
	Zones           []string       `json:"zones"`
	Config          map[string]any `json:"config"`
	Credential      string         `json:"credential"` // stored or ambient
	HasSecret       bool           `json:"has_secret"`
	SecretUpdatedAt *time.Time     `json:"secret_updated_at,omitempty"`
	Agents          []string       `json:"agents"`
	Version         int64          `json:"version"`
	CreatedAt       time.Time      `json:"created_at"`
}

// DNSSolverInput creates a DNS solver. Secret is the provider's credential
// object, for example {"api_token": "..."}; it is sealed on the server.
type DNSSolverInput struct {
	Name         string          `json:"name"`
	Provider     string          `json:"provider"`
	Plugin       string          `json:"plugin,omitempty"`
	PluginSHA256 string          `json:"plugin_sha256,omitempty"`
	Zones        []string        `json:"zones"`
	Config       map[string]any  `json:"config,omitempty"`
	Credential   string          `json:"credential,omitempty"`
	Secret       json.RawMessage `json:"secret,omitempty"`
}

// ListDNSSolvers lists DNS solvers.
func (c *Client) ListDNSSolvers(ctx context.Context) ([]DNSSolver, error) {
	return getList[DNSSolver](ctx, c, "/api/v1/dns-solvers")
}

// CreateDNSSolver creates a DNS solver.
func (c *Client) CreateDNSSolver(ctx context.Context, in DNSSolverInput) (*DNSSolver, error) {
	var s DNSSolver
	_, err := c.do(ctx, request{method: http.MethodPost, path: "/api/v1/dns-solvers", body: in}, &s)
	return &s, err
}

// GetDNSSolver returns a DNS solver.
func (c *Client) GetDNSSolver(ctx context.Context, idOrName string) (*DNSSolver, error) {
	var s DNSSolver
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/api/v1/dns-solvers/" + ref(idOrName)}, &s)
	return &s, err
}

// SetDNSSolverSecret replaces the stored secret.
func (c *Client) SetDNSSolverSecret(ctx context.Context, idOrName string, secret json.RawMessage) error {
	_, err := c.do(ctx, request{method: http.MethodPut, path: "/api/v1/dns-solvers/" + ref(idOrName) + "/secret",
		body: map[string]json.RawMessage{"secret": secret}}, nil)
	return err
}

// AssignDNSSolver lets an agent use the solver; UnassignDNSSolver revokes it.
func (c *Client) AssignDNSSolver(ctx context.Context, solver, agent string) error {
	_, err := c.do(ctx, request{method: http.MethodPut, path: "/api/v1/dns-solvers/" + ref(solver) + "/agents/" + ref(agent)}, nil)
	return err
}

// UnassignDNSSolver stops an agent from using the solver.
func (c *Client) UnassignDNSSolver(ctx context.Context, solver, agent string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: "/api/v1/dns-solvers/" + ref(solver) + "/agents/" + ref(agent)}, nil)
	return err
}

// DeleteDNSSolver deletes a DNS solver.
func (c *Client) DeleteDNSSolver(ctx context.Context, idOrName string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: "/api/v1/dns-solvers/" + ref(idOrName)}, nil)
	return err
}
