package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/alexandrosnt/certloom/internal/webhook"
	"github.com/jackc/pgx/v5"
)

// WebhookEndpoint receives events it subscribes to (ADR-0021). Secrets are
// never part of the JSON form.
type WebhookEndpoint struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	URL            string     `json:"url"`
	EventTypes     []string   `json:"event_types"`
	AllowPrivate   bool       `json:"allow_private"`
	Enabled        bool       `json:"enabled"`
	DisabledReason string     `json:"disabled_reason,omitempty"`
	FailingSince   *time.Time `json:"failing_since,omitempty"`
	PrevValidUntil *time.Time `json:"previous_secret_valid_until,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`

	SecretCiphertext     []byte `json:"-"`
	PrevSecretCiphertext []byte `json:"-"`
}

const webhookEndpointCols = `id, name, url, event_types, allow_private, enabled, disabled_reason, failing_since, prev_secret_until, created_at,
	secret_ciphertext, prev_secret_ciphertext`

func scanWebhookEndpoint(r pgx.Row) (*WebhookEndpoint, error) {
	e := &WebhookEndpoint{}
	err := r.Scan(&e.ID, &e.Name, &e.URL, &e.EventTypes, &e.AllowPrivate, &e.Enabled, &e.DisabledReason, &e.FailingSince,
		&e.PrevValidUntil, &e.CreatedAt, &e.SecretCiphertext, &e.PrevSecretCiphertext)
	return e, err
}

// NewWebhookEndpointID returns an id for an endpoint about to be created; the
// secret is encrypted with the id as associated data before the row exists.
func NewWebhookEndpointID() string { return ids.New("whe") }

// CreateWebhookEndpoint inserts an endpoint whose ID is already set.
func (tx *Tx) CreateWebhookEndpoint(ctx context.Context, e *WebhookEndpoint, createdBy string) error {
	e.Enabled = true
	return conflict(tx.QueryRow(ctx, `INSERT INTO webhook_endpoints (id, org_id, name, url, event_types, secret_ciphertext, allow_private, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`, e.ID, tx.OrgID, e.Name, e.URL, e.EventTypes, e.SecretCiphertext,
		e.AllowPrivate, createdBy).Scan(&e.CreatedAt))
}

// GetWebhookEndpoint returns an endpoint by id or name.
func (tx *Tx) GetWebhookEndpoint(ctx context.Context, ref string) (*WebhookEndpoint, error) {
	e, err := scanWebhookEndpoint(tx.QueryRow(ctx, `SELECT `+webhookEndpointCols+` FROM webhook_endpoints WHERE id = $1 OR name = $1`, ref))
	return e, notFound(err)
}

// ListWebhookEndpoints lists endpoints.
func (tx *Tx) ListWebhookEndpoints(ctx context.Context) ([]*WebhookEndpoint, error) {
	rows, err := tx.Query(ctx, `SELECT `+webhookEndpointCols+` FROM webhook_endpoints ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*WebhookEndpoint, error) { return scanWebhookEndpoint(r) })
}

// SetWebhookEndpointEnabled enables or disables an endpoint. Enabling clears
// the failure streak.
func (tx *Tx) SetWebhookEndpointEnabled(ctx context.Context, id string, enabled bool, reason string) error {
	tag, err := tx.Exec(ctx, `UPDATE webhook_endpoints SET enabled = $2, disabled_reason = $3,
		failing_since = CASE WHEN $2 THEN NULL ELSE failing_since END WHERE id = $1`, id, enabled, reason)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// RotateWebhookSecret installs a new secret and keeps the old one valid until.
func (tx *Tx) RotateWebhookSecret(ctx context.Context, id string, ciphertext []byte, until time.Time) error {
	tag, err := tx.Exec(ctx, `UPDATE webhook_endpoints SET prev_secret_ciphertext = secret_ciphertext, prev_secret_until = $3,
		secret_ciphertext = $2 WHERE id = $1`, id, ciphertext, until)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// DeleteWebhookEndpoint removes an endpoint and its deliveries.
func (tx *Tx) DeleteWebhookEndpoint(ctx context.Context, id string) error {
	tag, err := tx.Exec(ctx, `DELETE FROM webhook_endpoints WHERE id = $1`, id)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// Event is one occurrence delivered to webhook endpoints.
type Event struct {
	ID         string          `json:"id"`
	Type       string          `json:"type"`
	OccurredAt time.Time       `json:"timestamp"`
	Data       json.RawMessage `json:"data"`
}

// EmitEvent records an event and queues it for every enabled endpoint that
// subscribes to its type. Nothing is written when no endpoint wants it.
// dedupe makes emitting idempotent within the organization.
func (tx *Tx) EmitEvent(ctx context.Context, typ, dedupe string, at time.Time, data any) error {
	if at.IsZero() {
		at = time.Now()
	}
	rows, err := tx.Query(ctx, `SELECT id, event_types FROM webhook_endpoints WHERE enabled`)
	if err != nil {
		return err
	}
	type ep struct {
		id    string
		types []string
	}
	eps, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (ep, error) {
		var e ep
		err := r.Scan(&e.id, &e.types)
		return e, err
	})
	if err != nil {
		return err
	}
	var want []string
	for _, e := range eps {
		if webhook.Matches(e.types, typ) {
			want = append(want, e.id)
		}
	}
	if len(want) == 0 {
		return nil
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	var id string
	err = tx.QueryRow(ctx, `INSERT INTO events (id, org_id, type, dedupe_key, occurred_at, data) VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT (org_id, dedupe_key) DO NOTHING RETURNING id`, ids.New("evt"), tx.OrgID, typ, typ+":"+dedupe, at.UTC(), b).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // already emitted
	}
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `INSERT INTO webhook_deliveries (org_id, endpoint_id, event_id)
		SELECT $1, unnest($2::text[]), $3`, tx.OrgID, want, id)
	return err
}

// WebhookDelivery is one event for one endpoint.
type WebhookDelivery struct {
	ID            int64      `json:"id"`
	OrgID         string     `json:"-"`
	EndpointID    string     `json:"endpoint_id"`
	EventID       string     `json:"event_id"`
	EventType     string     `json:"event_type"`
	State         string     `json:"state"`
	Attempts      int        `json:"attempts"`
	NextAttemptAt time.Time  `json:"next_attempt_at"`
	LastStatus    *int       `json:"last_status,omitempty"`
	LastError     string     `json:"last_error,omitempty"`
	LastAttemptAt *time.Time `json:"last_attempt_at,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
}

const deliveryCols = `d.id, d.org_id, d.endpoint_id, d.event_id, e.type, d.state, d.attempts, d.next_attempt_at, d.last_status,
	d.last_error, d.last_attempt_at, d.created_at`

func scanDelivery(r pgx.Row) (*WebhookDelivery, error) {
	d := &WebhookDelivery{}
	err := r.Scan(&d.ID, &d.OrgID, &d.EndpointID, &d.EventID, &d.EventType, &d.State, &d.Attempts, &d.NextAttemptAt, &d.LastStatus,
		&d.LastError, &d.LastAttemptAt, &d.CreatedAt)
	return d, err
}

// ClaimWebhookDeliveries locks up to n due deliveries across organizations.
// The caller finishes them within the transaction.
func ClaimWebhookDeliveries(ctx context.Context, tx pgx.Tx, n int) ([]*WebhookDelivery, error) {
	rows, err := tx.Query(ctx, `SELECT d.id, d.org_id, d.endpoint_id, d.event_id, '', d.state, d.attempts, d.next_attempt_at, d.last_status,
		d.last_error, d.last_attempt_at, d.created_at FROM webhook_deliveries d
		WHERE d.state = 'pending' AND d.next_attempt_at <= now() ORDER BY d.next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED`, n)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*WebhookDelivery, error) { return scanDelivery(r) })
}

// MarkWebhookDelivery records an attempt: delivered, retried at retryAt, or
// failed for good when retryAt is nil and errMsg is set.
func MarkWebhookDelivery(ctx context.Context, tx pgx.Tx, id int64, status *int, errMsg string, retryAt *time.Time) error {
	state, next := "delivered", time.Now()
	switch {
	case errMsg != "" && retryAt != nil:
		state, next = "pending", *retryAt
	case errMsg != "":
		state = "failed"
	}
	_, err := tx.Exec(ctx, `UPDATE webhook_deliveries SET state = $2, attempts = attempts + 1, last_status = $3, last_error = $4,
		last_attempt_at = now(), next_attempt_at = $5 WHERE id = $1`, id, state, status, errMsg, next)
	return err
}

// MarkEndpointHealth tracks how long an endpoint has failed every delivery.
func MarkEndpointHealth(ctx context.Context, tx pgx.Tx, endpointID string, ok bool) error {
	q := `UPDATE webhook_endpoints SET failing_since = NULL WHERE id = $1 AND failing_since IS NOT NULL`
	if !ok {
		q = `UPDATE webhook_endpoints SET failing_since = now() WHERE id = $1 AND failing_since IS NULL`
	}
	_, err := tx.Exec(ctx, q, endpointID)
	return err
}

// GetEvent returns an event.
func (tx *Tx) GetEvent(ctx context.Context, id string) (*Event, error) {
	e := &Event{}
	err := tx.QueryRow(ctx, `SELECT id, type, occurred_at, data FROM events WHERE id = $1`, id).Scan(&e.ID, &e.Type, &e.OccurredAt, &e.Data)
	return e, notFound(err)
}

// ListWebhookDeliveries lists an endpoint's deliveries, newest first.
func (tx *Tx) ListWebhookDeliveries(ctx context.Context, endpointID string, limit int) ([]*WebhookDelivery, error) {
	rows, err := tx.Query(ctx, `SELECT `+deliveryCols+` FROM webhook_deliveries d JOIN events e ON e.id = d.event_id
		WHERE d.endpoint_id = $1 ORDER BY d.id DESC LIMIT $2`, endpointID, limit)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*WebhookDelivery, error) { return scanDelivery(r) })
}

// RedeliverWebhook queues a delivery again, keeping its event id so
// receivers can dedupe.
func (tx *Tx) RedeliverWebhook(ctx context.Context, endpointID string, id int64) error {
	tag, err := tx.Exec(ctx, `UPDATE webhook_deliveries SET state = 'pending', next_attempt_at = now(), last_error = ''
		WHERE id = $1 AND endpoint_id = $2 AND org_id = $3`, id, endpointID, tx.OrgID)
	if err == nil && tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return err
}

// FailingEndpoints returns enabled endpoints that have failed since before t.
func (tx *Tx) FailingEndpoints(ctx context.Context, before time.Time) ([]*WebhookEndpoint, error) {
	rows, err := tx.Query(ctx, `SELECT `+webhookEndpointCols+` FROM webhook_endpoints WHERE enabled AND failing_since < $1`, before)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (*WebhookEndpoint, error) { return scanWebhookEndpoint(r) })
}

// PruneWebhookEvents deletes events (and their deliveries) older than t.
func (tx *Tx) PruneWebhookEvents(ctx context.Context, before time.Time) (int64, error) {
	tag, err := tx.Exec(ctx, `DELETE FROM events WHERE occurred_at < $1`, before)
	return tag.RowsAffected(), err
}
