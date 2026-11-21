package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/jackc/pgx/v5"
)

// Channel is a notification destination. Config holds non-secret settings;
// secrets are referenced via CredentialRef.
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

// CreateChannel inserts a notification channel.
func (tx *Tx) CreateChannel(ctx context.Context, c *Channel) error {
	c.ID, c.Enabled = ids.New(ids.Channel), true
	if c.MinSeverity == "" {
		c.MinSeverity = string(checks.Warning)
	}
	return conflict(tx.QueryRow(ctx, `INSERT INTO notification_channels (id, org_id, name, kind, config, credential_ref, min_severity)
		VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING created_at`, c.ID, tx.OrgID, c.Name, c.Kind, []byte(c.Config), c.CredentialRef, c.MinSeverity).
		Scan(&c.CreatedAt))
}

const channelCols = `id, name, kind, config, credential_ref, min_severity, enabled, created_at`

func scanChannel(r pgx.CollectableRow) (Channel, error) {
	var c Channel
	var cfg []byte
	err := r.Scan(&c.ID, &c.Name, &c.Kind, &cfg, &c.CredentialRef, &c.MinSeverity, &c.Enabled, &c.CreatedAt)
	c.Config = cfg
	return c, err
}

// ListChannels returns all channels.
func (tx *Tx) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := tx.Query(ctx, `SELECT `+channelCols+` FROM notification_channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, scanChannel)
}

// GetChannel returns a channel by id.
func (tx *Tx) GetChannel(ctx context.Context, id string) (*Channel, error) {
	rows, err := tx.Query(ctx, `SELECT `+channelCols+` FROM notification_channels WHERE id = $1`, id)
	if err != nil {
		return nil, err
	}
	c, err := pgx.CollectExactlyOneRow(rows, scanChannel)
	return &c, notFound(err)
}

// Notification is the payload delivered to channels. It contains no secrets.
type Notification struct {
	Event       string    `json:"event"` // finding.opened, finding.escalated, finding.resolved, test
	OrgID       string    `json:"org_id"`
	FindingID   string    `json:"finding_id,omitempty"`
	SubjectType string    `json:"subject_type,omitempty"`
	SubjectID   string    `json:"subject_id,omitempty"`
	Subject     string    `json:"subject,omitempty"` // human label, e.g. host:port
	Check       string    `json:"check,omitempty"`
	Severity    string    `json:"severity,omitempty"`
	Message     string    `json:"message"`
	Remediation string    `json:"remediation,omitempty"`
	At          time.Time `json:"at"`
}

// EnqueueNotification writes n to the outbox for every enabled channel whose
// minimum severity it meets. dedupe makes enqueueing idempotent.
func (tx *Tx) EnqueueNotification(ctx context.Context, n Notification, dedupe string) error {
	return tx.EnqueueNotificationTo(ctx, n, dedupe, nil)
}

// EnqueueNotificationTo is EnqueueNotification restricted to the named
// channels (all enabled channels when names is empty).
func (tx *Tx) EnqueueNotificationTo(ctx context.Context, n Notification, dedupe string, names []string) error {
	// Every notification is also an event for webhook endpoints (ADR-0021),
	// whatever channels it is routed to.
	if n.Event != "test" {
		if err := tx.EmitEvent(ctx, n.Event, dedupe, n.At, n); err != nil {
			return err
		}
	}
	chs, err := tx.ListChannels(ctx)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(n)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, nm := range names {
		want[nm] = true
	}
	for _, c := range chs {
		if !c.Enabled || (len(want) > 0 && !want[c.Name]) {
			continue
		}
		if n.Event != "test" && n.Event != "finding.resolved" &&
			checks.Severity(n.Severity).Rank() < checks.Severity(c.MinSeverity).Rank() {
			continue
		}
		if _, err := tx.Exec(ctx, `INSERT INTO outbox (org_id, channel_id, dedupe_key, payload) VALUES ($1,$2,$3,$4)
			ON CONFLICT (dedupe_key) DO NOTHING`, tx.OrgID, c.ID, c.ID+":"+dedupe, payload); err != nil {
			return err
		}
	}
	return nil
}

// OutboxItem is a pending delivery.
type OutboxItem struct {
	ID        int64
	OrgID     string
	ChannelID string
	Payload   json.RawMessage
	Attempts  int
}

// ClaimOutbox locks up to n due outbox rows for delivery. The caller must
// finish within the returned transaction (rows stay locked until commit).
func ClaimOutbox(ctx context.Context, tx pgx.Tx, n int) ([]OutboxItem, error) {
	rows, err := tx.Query(ctx, `SELECT id, org_id, channel_id, payload, attempts FROM outbox
		WHERE delivered_at IS NULL AND failed_at IS NULL AND next_attempt_at <= now()
		ORDER BY next_attempt_at LIMIT $1 FOR UPDATE SKIP LOCKED`, n)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (OutboxItem, error) {
		var o OutboxItem
		var p []byte
		err := r.Scan(&o.ID, &o.OrgID, &o.ChannelID, &p, &o.Attempts)
		o.Payload = p
		return o, err
	})
}

// MarkOutbox records a delivery attempt. retryAt nil with err != "" means permanently failed.
func MarkOutbox(ctx context.Context, tx pgx.Tx, id int64, errMsg string, retryAt *time.Time) error {
	switch {
	case errMsg == "":
		_, err := tx.Exec(ctx, `UPDATE outbox SET delivered_at = now(), attempts = attempts + 1, last_error = '' WHERE id = $1`, id)
		return err
	case retryAt != nil:
		_, err := tx.Exec(ctx, `UPDATE outbox SET attempts = attempts + 1, last_error = $2, next_attempt_at = $3 WHERE id = $1`, id, errMsg, *retryAt)
		return err
	default:
		_, err := tx.Exec(ctx, `UPDATE outbox SET attempts = attempts + 1, last_error = $2, failed_at = now() WHERE id = $1`, id, errMsg)
		return err
	}
}
