package client

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// CloudAccount is a cloud account certloomd reads itself, read-only. A
// stored secret is never returned; HasSecret shows whether one is set.
type CloudAccount struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Provider        string          `json:"provider"` // aws, azure, gcp, cloudflare
	Settings        json.RawMessage `json:"settings"`
	Credential      string          `json:"credential"` // ambient or stored
	HasSecret       bool            `json:"has_secret"`
	SecretUpdatedAt *time.Time      `json:"secret_updated_at,omitempty"`
	IntervalSeconds int             `json:"interval_seconds"`
	NextScanAt      time.Time       `json:"next_scan_at"`
	LastScanAt      *time.Time      `json:"last_scan_at,omitempty"`
	Version         int64           `json:"version"`
	CreatedAt       time.Time       `json:"created_at"`
}

// CloudAccountInput creates a cloud account. Settings depend on the
// provider; Secret is the credential object, for example
// {"api_token": "..."}, and requires Credential "stored".
type CloudAccountInput struct {
	Name            string          `json:"name"`
	Provider        string          `json:"provider"`
	Credential      string          `json:"credential,omitempty"`
	Settings        json.RawMessage `json:"settings"`
	IntervalSeconds int             `json:"interval_seconds,omitempty"`
	Secret          json.RawMessage `json:"secret,omitempty"`
}

// CloudAccountPatch replaces an account's settings and interval.
type CloudAccountPatch struct {
	Settings        json.RawMessage `json:"settings"`
	IntervalSeconds int             `json:"interval_seconds,omitempty"`
}

// ListCloudAccounts lists cloud accounts.
func (c *Client) ListCloudAccounts(ctx context.Context) ([]CloudAccount, error) {
	return getList[CloudAccount](ctx, c, "/api/v1/cloud-accounts")
}

// CreateCloudAccount creates a cloud account; its first scan starts at once.
func (c *Client) CreateCloudAccount(ctx context.Context, in CloudAccountInput) (*CloudAccount, error) {
	var a CloudAccount
	_, err := c.do(ctx, request{method: http.MethodPost, path: "/api/v1/cloud-accounts", body: in}, &a)
	return &a, err
}

// GetCloudAccount returns a cloud account.
func (c *Client) GetCloudAccount(ctx context.Context, idOrName string) (*CloudAccount, error) {
	var a CloudAccount
	_, err := c.do(ctx, request{method: http.MethodGet, path: "/api/v1/cloud-accounts/" + ref(idOrName)}, &a)
	return &a, err
}

// UpdateCloudAccount replaces settings and interval. ifVersion, if not 0,
// must be the account's current version.
func (c *Client) UpdateCloudAccount(ctx context.Context, idOrName string, p CloudAccountPatch, ifVersion int64) (*CloudAccount, error) {
	var a CloudAccount
	_, err := c.do(ctx, request{method: http.MethodPatch, path: "/api/v1/cloud-accounts/" + ref(idOrName), body: p, ifMatch: ifVersion}, &a)
	return &a, err
}

// SetCloudAccountSecret replaces the stored secret.
func (c *Client) SetCloudAccountSecret(ctx context.Context, idOrName string, secret json.RawMessage) error {
	_, err := c.do(ctx, request{method: http.MethodPut, path: "/api/v1/cloud-accounts/" + ref(idOrName) + "/secret",
		body: map[string]json.RawMessage{"secret": secret}}, nil)
	return err
}

// ScanCloudAccount queues a scan now.
func (c *Client) ScanCloudAccount(ctx context.Context, idOrName string) error {
	_, err := c.do(ctx, request{method: http.MethodPost, path: "/api/v1/cloud-accounts/" + ref(idOrName) + "/scan"}, nil)
	return err
}

// DeleteCloudAccount deletes a cloud account and its stored secret.
func (c *Client) DeleteCloudAccount(ctx context.Context, idOrName string) error {
	_, err := c.do(ctx, request{method: http.MethodDelete, path: "/api/v1/cloud-accounts/" + ref(idOrName)}, nil)
	return err
}
