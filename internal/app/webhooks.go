package app

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/notify"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/webhook"
)

// Event webhooks (ADR-0021).

const (
	// webhookRotationOverlap is how long the previous secret keeps signing.
	webhookRotationOverlap = 24 * time.Hour
	// webhookDisableAfter disables an endpoint that failed every delivery this long.
	webhookDisableAfter = 72 * time.Hour
	// webhookEventRetention is how long events and their delivery logs are kept.
	webhookEventRetention = 30 * 24 * time.Hour
)

// WebhookEndpointInput describes a new endpoint.
type WebhookEndpointInput struct {
	Name, URL    string
	EventTypes   []string
	AllowPrivate bool
}

// CreatedWebhookEndpoint carries the secret, shown only once.
type CreatedWebhookEndpoint struct {
	*store.WebhookEndpoint
	Secret string `json:"secret"`
}

func checkWebhookInput(in *WebhookEndpointInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return invalid("name is required")
	}
	u, err := url.Parse(in.URL)
	if err != nil || u.Host == "" || (u.Scheme != "https" && (u.Scheme != "http" || !in.AllowPrivate)) {
		return invalid("url must be https (http only for allow_private internal receivers)")
	}
	if u.User != nil {
		return invalid("url must not contain credentials")
	}
	if len(in.EventTypes) == 0 {
		return invalid("subscribe to at least one event type (e.g. renewal.* or certificate.issued)")
	}
	for _, t := range in.EventTypes {
		if !webhook.ValidFilter(t) {
			return invalid("unknown event type %q (see docs/events.md)", t)
		}
	}
	return nil
}

// CreateWebhookEndpoint registers an endpoint and returns its new secret.
func (s *Service) CreateWebhookEndpoint(ctx context.Context, p authz.Principal, in WebhookEndpointInput) (*CreatedWebhookEndpoint, error) {
	if s.PKI == nil {
		return nil, ErrAgentsDisabled
	}
	if err := checkWebhookInput(&in); err != nil {
		return nil, err
	}
	sec := webhook.NewSecret()
	e := &store.WebhookEndpoint{ID: store.NewWebhookEndpointID(), Name: in.Name, URL: in.URL, EventTypes: in.EventTypes, AllowPrivate: in.AllowPrivate}
	err := s.tx(ctx, p, authz.ManageWebhooks, func(tx *store.Tx) (err error) {
		if e.SecretCiphertext, err = s.PKI.KEK.Seal([]byte(sec), notify.WebhookSecretAAD(e.ID)); err != nil {
			return err
		}
		if err := tx.CreateWebhookEndpoint(ctx, e, p.Actor); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "webhooks.create", "webhook_endpoint", e.ID, map[string]any{"name": e.Name, "url": e.URL,
			"event_types": e.EventTypes, "allow_private": e.AllowPrivate})
	})
	if err != nil {
		return nil, err
	}
	return &CreatedWebhookEndpoint{WebhookEndpoint: e, Secret: sec}, nil
}

// ListWebhookEndpoints lists endpoints without secrets.
func (s *Service) ListWebhookEndpoints(ctx context.Context, p authz.Principal) (out []*store.WebhookEndpoint, err error) {
	err = s.tx(ctx, p, authz.ManageWebhooks, func(tx *store.Tx) error { out, err = tx.ListWebhookEndpoints(ctx); return err })
	return out, err
}

// GetWebhookEndpoint returns one endpoint without secrets.
func (s *Service) GetWebhookEndpoint(ctx context.Context, p authz.Principal, ref string) (e *store.WebhookEndpoint, err error) {
	err = s.tx(ctx, p, authz.ManageWebhooks, func(tx *store.Tx) error { e, err = tx.GetWebhookEndpoint(ctx, ref); return err })
	return e, err
}

// SetWebhookEndpointEnabled enables or disables an endpoint.
func (s *Service) SetWebhookEndpointEnabled(ctx context.Context, p authz.Principal, ref string, enabled bool) error {
	return s.tx(ctx, p, authz.ManageWebhooks, func(tx *store.Tx) error {
		e, err := tx.GetWebhookEndpoint(ctx, ref)
		if err != nil {
			return err
		}
		reason := ""
		if !enabled {
			reason = "disabled by " + p.Actor
		}
		if err := tx.SetWebhookEndpointEnabled(ctx, e.ID, enabled, reason); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "webhooks.set_enabled", "webhook_endpoint", e.ID, map[string]any{"name": e.Name, "enabled": enabled})
	})
}

// RotateWebhookSecret issues a new secret; the old one keeps signing for a day
// so receivers can switch without dropping deliveries.
func (s *Service) RotateWebhookSecret(ctx context.Context, p authz.Principal, ref string) (string, error) {
	if s.PKI == nil {
		return "", ErrAgentsDisabled
	}
	sec := webhook.NewSecret()
	err := s.tx(ctx, p, authz.ManageWebhooks, func(tx *store.Tx) error {
		e, err := tx.GetWebhookEndpoint(ctx, ref)
		if err != nil {
			return err
		}
		ct, err := s.PKI.KEK.Seal([]byte(sec), notify.WebhookSecretAAD(e.ID))
		if err != nil {
			return err
		}
		until := s.now().Add(webhookRotationOverlap)
		if err := tx.RotateWebhookSecret(ctx, e.ID, ct, until); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "webhooks.rotate_secret", "webhook_endpoint", e.ID, map[string]any{"name": e.Name, "previous_valid_until": until})
	})
	if err != nil {
		return "", err
	}
	return sec, nil
}

// DeleteWebhookEndpoint removes an endpoint and its delivery log.
func (s *Service) DeleteWebhookEndpoint(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ManageWebhooks, func(tx *store.Tx) error {
		e, err := tx.GetWebhookEndpoint(ctx, ref)
		if err != nil {
			return err
		}
		if err := tx.DeleteWebhookEndpoint(ctx, e.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "webhooks.delete", "webhook_endpoint", e.ID, map[string]any{"name": e.Name})
	})
}

// ListWebhookDeliveries shows the recent deliveries to an endpoint.
func (s *Service) ListWebhookDeliveries(ctx context.Context, p authz.Principal, ref string, limit int) (out []*store.WebhookDelivery, err error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	err = s.tx(ctx, p, authz.ManageWebhooks, func(tx *store.Tx) error {
		e, err := tx.GetWebhookEndpoint(ctx, ref)
		if err != nil {
			return err
		}
		out, err = tx.ListWebhookDeliveries(ctx, e.ID, limit)
		return err
	})
	return out, err
}

// RedeliverWebhook queues a delivery again with the same event id.
func (s *Service) RedeliverWebhook(ctx context.Context, p authz.Principal, ref string, deliveryID int64) error {
	return s.tx(ctx, p, authz.ManageWebhooks, func(tx *store.Tx) error {
		e, err := tx.GetWebhookEndpoint(ctx, ref)
		if err != nil {
			return err
		}
		if err := tx.RedeliverWebhook(ctx, e.ID, deliveryID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "webhooks.redeliver", "webhook_endpoint", e.ID, map[string]any{"delivery": deliveryID})
	})
}

// SweepWebhooks disables endpoints that failed every delivery for too long
// and prunes old events with their delivery logs.
func (s *Service) SweepWebhooks(ctx context.Context) error {
	orgs, err := s.orgIDs(ctx)
	if err != nil {
		return err
	}
	var errs []error
	for _, org := range orgs {
		err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
			now := s.now()
			if _, err := tx.PruneWebhookEvents(ctx, now.Add(-webhookEventRetention)); err != nil {
				return err
			}
			failing, err := tx.FailingEndpoints(ctx, now.Add(-webhookDisableAfter))
			if err != nil || len(failing) == 0 {
				return err
			}
			pv, err := tx.ActivePolicy(ctx)
			if err != nil {
				return err
			}
			for _, e := range failing {
				reason := "every delivery failed since " + e.FailingSince.UTC().Format(time.RFC3339)
				if err := tx.SetWebhookEndpointEnabled(ctx, e.ID, false, reason); err != nil {
					return err
				}
				n := store.Notification{Event: "webhook.disabled", OrgID: org, SubjectType: "webhook_endpoint", SubjectID: e.ID,
					Subject: "webhook " + e.Name, Severity: "warning", At: now.UTC(),
					Message: fmt.Sprintf("webhook endpoint %s was disabled: %s; fix the receiver, then run: certloom webhook enable %s", e.Name, reason, e.Name)}
				if err := tx.EnqueueNotificationTo(ctx, n, e.ID+":disabled:"+now.Format(time.RFC3339), pv.Document.Spec.Approvals.Channels); err != nil {
					return err
				}
				if err := s.systemAudit(ctx, tx, workflowActor, "webhooks.auto_disable", "webhook_endpoint", e.ID, map[string]any{"reason": reason}); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("org %s: %w", org, err))
		}
	}
	return errors.Join(errs...)
}

// emit records a lifecycle event that has no notification of its own.
func (s *Service) emit(ctx context.Context, tx *store.Tx, typ, dedupe string, data map[string]any) error {
	return tx.EmitEvent(ctx, typ, dedupe, s.now(), data)
}
