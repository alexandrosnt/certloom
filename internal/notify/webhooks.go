package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/webhook"
	"github.com/jackc/pgx/v5"
)

// SecretOpener decrypts stored webhook secrets (the KEK).
type SecretOpener interface {
	Open(ciphertext []byte, aad string) ([]byte, error)
}

// WebhookSecretAAD binds a stored endpoint secret to its endpoint.
func WebhookSecretAAD(endpointID string) string { return "webhook_endpoint:" + endpointID }

// webhookRetries are the waits between attempts, about 23 hours in total.
var webhookRetries = []time.Duration{30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute,
	time.Hour, 3 * time.Hour, 6 * time.Hour, 12 * time.Hour}

// WebhookDeliverer sends queued events to webhook endpoints (ADR-0021).
type WebhookDeliverer struct {
	DB       *store.DB
	KEK      SecretOpener
	Log      *slog.Logger
	Resolver probe.Resolver
	now      func() time.Time
}

func (d *WebhookDeliverer) clock() time.Time {
	if d.now != nil {
		return d.now()
	}
	return time.Now()
}

// RunOnce delivers up to n due deliveries. Like the outbox, a crash after
// sending and before commit may send one again; receivers dedupe on
// webhook-id, which is the event id.
func (d *WebhookDeliverer) RunOnce(ctx context.Context, n int) (int, error) {
	sent := 0
	err := d.DB.WithoutOrg(ctx, func(tx pgx.Tx) error {
		items, err := store.ClaimWebhookDeliveries(ctx, tx, n)
		if err != nil {
			return err
		}
		for _, it := range items {
			status, derr := d.deliver(ctx, it)
			var retry *time.Time
			msg := ""
			if derr != nil {
				msg = derr.Error()
				if it.Attempts < len(webhookRetries) && !errors.Is(derr, errPermanent) {
					t := d.clock().Add(webhookRetries[it.Attempts])
					retry = &t
				}
				d.Log.Warn("webhook delivery failed", "delivery", it.ID, "endpoint", it.EndpointID, "event", it.EventID,
					"attempt", it.Attempts+1, "error", msg)
			} else {
				sent++
			}
			if err := store.MarkWebhookDelivery(ctx, tx, it.ID, status, msg, retry); err != nil {
				return err
			}
			if !errors.Is(derr, errEndpointGone) {
				if err := store.MarkEndpointHealth(ctx, tx, it.EndpointID, derr == nil); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return sent, err
}

var errEndpointGone = fmt.Errorf("%w: endpoint disabled or deleted", errPermanent)

// webhookBody is the Standard Webhooks payload.
type webhookBody struct {
	Type      string          `json:"type"`
	Timestamp time.Time       `json:"timestamp"`
	Data      json.RawMessage `json:"data"`
}

func (d *WebhookDeliverer) deliver(ctx context.Context, it *store.WebhookDelivery) (*int, error) {
	var ep *store.WebhookEndpoint
	var ev *store.Event
	err := d.DB.WithOrg(ctx, it.OrgID, func(tx *store.Tx) (err error) {
		if ep, err = tx.GetWebhookEndpoint(ctx, it.EndpointID); err != nil {
			return err
		}
		ev, err = tx.GetEvent(ctx, it.EventID)
		return err
	})
	if errors.Is(err, store.ErrNotFound) || (err == nil && !ep.Enabled) {
		return nil, errEndpointGone
	}
	if err != nil {
		return nil, err
	}
	secrets, err := d.secrets(ep)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errPermanent, err)
	}
	body, err := json.Marshal(webhookBody{Type: ev.Type, Timestamp: ev.OccurredAt.UTC(), Data: ev.Data})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errPermanent, err)
	}
	h, err := webhook.Headers(secrets, ev.ID, d.clock(), body)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errPermanent, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.URL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errPermanent, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certloom-webhooks")
	for k, v := range h {
		req.Header.Set(k, v)
	}
	resp, err := guardedClient(d.Resolver, ep.AllowPrivate).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	code := resp.StatusCode
	switch {
	case code >= 200 && code < 300:
		return &code, nil
	case code >= 300 && code < 400:
		return &code, fmt.Errorf("%w: endpoint returned redirect %d (redirects are not followed)", errPermanent, code)
	case code >= 400 && code < 500 && code != 408 && code != 429:
		return &code, fmt.Errorf("%w: endpoint returned %d", errPermanent, code)
	}
	return &code, fmt.Errorf("endpoint returned %d", code)
}

// secrets returns the current secret and, during a rotation, the previous one.
func (d *WebhookDeliverer) secrets(ep *store.WebhookEndpoint) ([]string, error) {
	cur, err := d.KEK.Open(ep.SecretCiphertext, WebhookSecretAAD(ep.ID))
	if err != nil {
		return nil, errors.New("stored webhook secret cannot be decrypted")
	}
	out := []string{string(cur)}
	if len(ep.PrevSecretCiphertext) > 0 && ep.PrevValidUntil != nil && d.clock().Before(*ep.PrevValidUntil) {
		prev, err := d.KEK.Open(ep.PrevSecretCiphertext, WebhookSecretAAD(ep.ID))
		if err == nil {
			out = append(out, string(prev))
		}
	}
	return out, nil
}
