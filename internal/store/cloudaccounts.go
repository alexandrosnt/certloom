package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/alexandrosnt/certloom/internal/ids"
)

// CloudAccount is a cloud account certloomd reads itself (ADR-0034). The
// secret ciphertext is never part of the JSON form.
type CloudAccount struct {
	ID              string          `json:"id"`
	Name            string          `json:"name"`
	Provider        string          `json:"provider"` // aws, azure, gcp, cloudflare
	Settings        json.RawMessage `json:"settings"`
	Credential      string          `json:"credential"` // stored or ambient
	HasSecret       bool            `json:"has_secret"`
	SecretUpdatedAt *time.Time      `json:"secret_updated_at,omitempty"`
	IntervalSeconds int             `json:"interval_seconds"`
	NextScanAt      time.Time       `json:"next_scan_at"`
	LastScanAt      *time.Time      `json:"last_scan_at,omitempty"`
	Version         int64           `json:"version"`
	CreatedAt       time.Time       `json:"created_at"`

	SecretCiphertext []byte `json:"-"`
}

// NewCloudAccountID returns an id for an account about to be created; the
// secret is encrypted with the id as associated data before the row exists.
func NewCloudAccountID() string { return ids.New("cla") }

const cloudAccountCols = `id, name, provider, settings, credential, secret_ciphertext, secret_updated_at,
	interval_seconds, next_scan_at, last_scan_at, version, created_at`

func scanCloudAccount(r pgx.Row) (*CloudAccount, error) {
	a := &CloudAccount{}
	err := r.Scan(&a.ID, &a.Name, &a.Provider, &a.Settings, &a.Credential, &a.SecretCiphertext, &a.SecretUpdatedAt,
		&a.IntervalSeconds, &a.NextScanAt, &a.LastScanAt, &a.Version, &a.CreatedAt)
	a.HasSecret = len(a.SecretCiphertext) > 0
	return a, notFound(err)
}

// CreateCloudAccount inserts an account whose ID is already set. It is due
// for a scan right away.
func (tx *Tx) CreateCloudAccount(ctx context.Context, a *CloudAccount, createdBy string) error {
	var updated *time.Time
	if len(a.SecretCiphertext) > 0 {
		now := time.Now()
		updated = &now
	}
	if a.IntervalSeconds == 0 {
		a.IntervalSeconds = 3600
	}
	return conflict(tx.QueryRow(ctx, `INSERT INTO cloud_accounts (id, org_id, name, provider, settings, credential,
		secret_ciphertext, secret_updated_at, interval_seconds, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING next_scan_at, created_at, version`,
		a.ID, tx.OrgID, a.Name, a.Provider, a.Settings, a.Credential, a.SecretCiphertext, updated, a.IntervalSeconds,
		createdBy).Scan(&a.NextScanAt, &a.CreatedAt, &a.Version))
}

// GetCloudAccount returns an account by id or name, including its ciphertext.
func (tx *Tx) GetCloudAccount(ctx context.Context, ref string) (*CloudAccount, error) {
	return scanCloudAccount(tx.QueryRow(ctx, `SELECT `+cloudAccountCols+` FROM cloud_accounts WHERE id = $1 OR name = $1`, ref))
}

// ListCloudAccounts lists the accounts by name.
func (tx *Tx) ListCloudAccounts(ctx context.Context) ([]*CloudAccount, error) {
	return tx.queryCloudAccounts(ctx, `SELECT `+cloudAccountCols+` FROM cloud_accounts ORDER BY name`)
}

// CloudAccountsDue lists the accounts whose next scan is due.
func (tx *Tx) CloudAccountsDue(ctx context.Context, now time.Time) ([]*CloudAccount, error) {
	return tx.queryCloudAccounts(ctx, `SELECT `+cloudAccountCols+` FROM cloud_accounts WHERE next_scan_at <= $1 ORDER BY next_scan_at`, now)
}

func (tx *Tx) queryCloudAccounts(ctx context.Context, sql string, args ...any) ([]*CloudAccount, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*CloudAccount
	for rows.Next() {
		a, err := scanCloudAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// UpdateCloudAccount replaces settings and interval. ifVersion, if non-nil,
// must equal the current version (If-Match).
func (tx *Tx) UpdateCloudAccount(ctx context.Context, a *CloudAccount, ifVersion *int64) error {
	err := tx.versioned(ctx, "cloud_accounts", a.ID, `UPDATE cloud_accounts SET settings = $2, interval_seconds = $3,
		next_scan_at = now(), version = version + 1 WHERE id = $1 AND ($4::bigint IS NULL OR version = $4)`,
		a.ID, a.Settings, a.IntervalSeconds, ifVersion)
	if err != nil {
		return err
	}
	b, err := tx.GetCloudAccount(ctx, a.ID)
	if err == nil {
		a.Version, a.NextScanAt = b.Version, b.NextScanAt
	}
	return err
}

// SetCloudAccountSecret replaces a stored secret and makes the account due.
func (tx *Tx) SetCloudAccountSecret(ctx context.Context, id string, ciphertext []byte) error {
	tag, err := tx.Exec(ctx, `UPDATE cloud_accounts SET secret_ciphertext = $2, secret_updated_at = now(), next_scan_at = now(),
		version = version + 1 WHERE id = $1 AND credential = 'stored'`, id, ciphertext)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// ScheduleCloudScan sets when an account is scanned next.
func (tx *Tx) ScheduleCloudScan(ctx context.Context, id string, at time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE cloud_accounts SET next_scan_at = $2 WHERE id = $1`, id, at)
	return err
}

// SaveCloudScan records a finished scan: its inventory (without PEMs) and
// the next due time.
func (tx *Tx) SaveCloudScan(ctx context.Context, id string, inventory any, at, next time.Time) error {
	b, err := json.Marshal(inventory)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE cloud_accounts SET last_inventory = $2, last_scan_at = $3, next_scan_at = $4 WHERE id = $1`,
		id, b, at, next)
	return err
}

// CloudAccountInventory returns the last stored inventory; nil if none yet.
func (tx *Tx) CloudAccountInventory(ctx context.Context, id string) (json.RawMessage, error) {
	var data json.RawMessage
	err := tx.QueryRow(ctx, `SELECT last_inventory FROM cloud_accounts WHERE id = $1`, id).Scan(&data)
	return data, notFound(err)
}

// DeleteCloudAccount deletes an account and its stored secret.
func (tx *Tx) DeleteCloudAccount(ctx context.Context, id string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM cloud_accounts WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}
