// Package notify delivers outbox notifications to webhook and email channels
// with at-least-once semantics. Payloads never contain secrets.
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"net/netip"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/jackc/pgx/v5"
)

// WebhookConfig is the non-secret configuration of a webhook channel.
// The HMAC signing secret comes from the channel's credential reference.
type WebhookConfig struct {
	URL string `json:"url"`
	// AllowPrivate permits private/loopback destinations (internal receivers).
	AllowPrivate bool `json:"allow_private,omitempty"`
}

// EmailConfig is the non-secret configuration of an email channel. The SMTP
// password comes from the channel's credential reference.
type EmailConfig struct {
	Host     string   `json:"host"`
	Port     int      `json:"port"`
	Username string   `json:"username,omitempty"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	// TLS: "starttls" (default) or "implicit". Plaintext SMTP is not supported.
	TLS string `json:"tls,omitempty"`
}

// Validate checks a channel's configuration without contacting it.
func Validate(c *store.Channel) error {
	if strings.TrimSpace(c.Name) == "" {
		return errors.New("channel name is required")
	}
	if c.CredentialRef != "" && !secret.ValidRef(c.CredentialRef) {
		return fmt.Errorf("invalid credential reference %q", c.CredentialRef)
	}
	switch c.MinSeverity {
	case "", "info", "warning", "critical":
	default:
		return fmt.Errorf("invalid min_severity %q", c.MinSeverity)
	}
	switch c.Kind {
	case "webhook":
		var w WebhookConfig
		if err := json.Unmarshal(c.Config, &w); err != nil {
			return err
		}
		u, err := url.Parse(w.URL)
		if err != nil || u.Host == "" {
			return fmt.Errorf("invalid webhook url")
		}
		if u.Scheme != "https" && (u.Scheme != "http" || !w.AllowPrivate) {
			return errors.New("webhook url must be https (http only allowed with allow_private for internal receivers)")
		}
		if u.User != nil {
			return errors.New("webhook url must not embed credentials; use credential_ref")
		}
	case "email":
		var e EmailConfig
		if err := json.Unmarshal(c.Config, &e); err != nil {
			return err
		}
		if e.Host == "" || e.Port == 0 || len(e.To) == 0 {
			return errors.New("email channel needs host, port and at least one recipient")
		}
		for _, a := range append([]string{e.From}, e.To...) {
			if _, err := mail.ParseAddress(a); err != nil {
				return fmt.Errorf("invalid address %q", a)
			}
		}
		if e.TLS != "" && e.TLS != "starttls" && e.TLS != "implicit" {
			return errors.New(`tls must be "starttls" or "implicit"`)
		}
	default:
		return fmt.Errorf("unknown channel kind %q", c.Kind)
	}
	return nil
}

// Deliverer drains the outbox.
type Deliverer struct {
	DB          *store.DB
	Log         *slog.Logger
	MaxAttempts int // default 8
	// Resolver is used for webhook SSRF checks; nil = system resolver.
	Resolver probe.Resolver
}

// RunOnce delivers up to n due notifications. Each item is delivered while
// its outbox row is locked, so concurrent deliverers never send it twice
// concurrently; a crash after sending but before commit may resend
// (at-least-once; receivers should dedupe on the X-Certloom-Delivery header).
func (d *Deliverer) RunOnce(ctx context.Context, n int) (int, error) {
	sent := 0
	err := d.DB.WithoutOrg(ctx, func(tx pgx.Tx) error {
		items, err := store.ClaimOutbox(ctx, tx, n)
		if err != nil {
			return err
		}
		for _, it := range items {
			derr := d.deliver(ctx, it)
			var retry *time.Time
			msg := ""
			if derr != nil {
				msg = derr.Error()
				max := d.MaxAttempts
				if max == 0 {
					max = 8
				}
				if it.Attempts+1 < max && !errors.Is(derr, errPermanent) {
					t := time.Now().Add(backoff(it.Attempts + 1))
					retry = &t
				}
				d.Log.Warn("notification delivery failed", "outbox_id", it.ID, "channel", it.ChannelID, "attempt", it.Attempts+1, "error", msg)
			} else {
				sent++
			}
			if err := store.MarkOutbox(ctx, tx, it.ID, msg, retry); err != nil {
				return err
			}
		}
		return nil
	})
	return sent, err
}

var errPermanent = errors.New("permanent")

func backoff(attempt int) time.Duration {
	d := 30 * time.Second
	for i := 1; i < attempt && d < time.Hour; i++ {
		d *= 2
	}
	return min(d, time.Hour)
}

func (d *Deliverer) deliver(ctx context.Context, it store.OutboxItem) error {
	var ch *store.Channel
	err := d.DB.WithOrg(ctx, it.OrgID, func(tx *store.Tx) (err error) {
		ch, err = tx.GetChannel(ctx, it.ChannelID)
		return err
	})
	if err != nil {
		return fmt.Errorf("%w: load channel: %w", errPermanent, err)
	}
	if !ch.Enabled {
		return fmt.Errorf("%w: channel disabled", errPermanent)
	}
	var cred secret.Value
	if ch.CredentialRef != "" {
		if cred, err = secret.Resolve(ch.CredentialRef); err != nil {
			return err // may be fixed by the operator; retry
		}
	}
	deliveryID := it.ChannelID + "-" + strconv.FormatInt(it.ID, 10)
	switch ch.Kind {
	case "webhook":
		var cfg WebhookConfig
		if err := json.Unmarshal(ch.Config, &cfg); err != nil {
			return fmt.Errorf("%w: %w", errPermanent, err)
		}
		return d.webhook(ctx, cfg, cred, deliveryID, it.Payload)
	case "email":
		var cfg EmailConfig
		if err := json.Unmarshal(ch.Config, &cfg); err != nil {
			return fmt.Errorf("%w: %w", errPermanent, err)
		}
		return sendEmail(ctx, cfg, cred, deliveryID, it.Payload)
	}
	return fmt.Errorf("%w: unknown kind %q", errPermanent, ch.Kind)
}

// Sign returns the hex HMAC-SHA256 of body under key, as sent in X-Certloom-Signature.
func Sign(key, body []byte) string {
	m := hmac.New(sha256.New, key)
	m.Write(body)
	return "sha256=" + hex.EncodeToString(m.Sum(nil))
}

func (d *Deliverer) webhook(ctx context.Context, cfg WebhookConfig, key secret.Value, deliveryID string, body []byte) error {
	scope := &probe.Scope{AllowLoopback: cfg.AllowPrivate, AllowPrivate: cfg.AllowPrivate}
	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		Proxy: nil, // never route through an env proxy: the guard below must see the real destination
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			var addrs []netip.Addr
			if a, err := netip.ParseAddr(host); err == nil {
				addrs = []netip.Addr{a}
			} else if addrs, err = resolver.LookupNetIP(ctx, "ip", host); err != nil {
				return nil, err
			}
			for _, a := range addrs {
				if err := scope.CheckAddr(a); err != nil {
					continue
				}
				return dialer.DialContext(ctx, network, net.JoinHostPort(a.Unmap().String(), port))
			}
			return nil, fmt.Errorf("%w: webhook destination %s is not allowed (private/loopback/metadata; set allow_private for internal receivers)", errPermanent, host)
		},
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout: 10 * time.Second,
	}
	client := &http.Client{Transport: tr, Timeout: 15 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, cfg.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("%w: %w", errPermanent, err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certloom-notifier")
	req.Header.Set("X-Certloom-Delivery", deliveryID)
	if !key.IsEmpty() {
		req.Header.Set("X-Certloom-Signature", Sign(key.Reveal(), body))
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		return fmt.Errorf("%w: webhook returned redirect %d (redirects are not followed)", errPermanent, resp.StatusCode)
	case resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != 408 && resp.StatusCode != 429:
		return fmt.Errorf("%w: webhook returned %d", errPermanent, resp.StatusCode)
	}
	return fmt.Errorf("webhook returned %d", resp.StatusCode)
}

func sendEmail(ctx context.Context, cfg EmailConfig, password secret.Value, deliveryID string, payload []byte) error {
	var n store.Notification
	if err := json.Unmarshal(payload, &n); err != nil {
		return fmt.Errorf("%w: %w", errPermanent, err)
	}
	subject := fmt.Sprintf("[certloom] %s %s: %s", strings.ToUpper(n.Severity), n.Check, n.Subject)
	switch n.Event {
	case "test":
		subject = "[certloom] test notification"
	case "finding.resolved":
		subject = fmt.Sprintf("[certloom] RESOLVED %s: %s", n.Check, n.Subject)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "From: %s\r\nTo: %s\r\nSubject: %s\r\nX-Certloom-Delivery: %s\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n",
		cfg.From, strings.Join(cfg.To, ", "), strings.NewReplacer("\r", "", "\n", "").Replace(subject), deliveryID)
	fmt.Fprintf(&b, "%s\r\n\r\nSubject: %s\r\nCheck: %s\r\nSeverity: %s\r\nAt: %s\r\n", n.Message, n.Subject, n.Check, n.Severity, n.At.Format(time.RFC3339))
	if n.Remediation != "" {
		fmt.Fprintf(&b, "\r\nWhat to do: %s\r\n", n.Remediation)
	}
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	tlsCfg := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}
	var c *smtp.Client
	if cfg.TLS == "implicit" {
		d := &tls.Dialer{NetDialer: &net.Dialer{Timeout: 15 * time.Second}, Config: tlsCfg}
		conn, err := d.DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		if c, err = smtp.NewClient(conn, cfg.Host); err != nil {
			return err
		}
	} else {
		conn, err := (&net.Dialer{Timeout: 15 * time.Second}).DialContext(ctx, "tcp", addr)
		if err != nil {
			return err
		}
		if c, err = smtp.NewClient(conn, cfg.Host); err != nil {
			return err
		}
		if ok, _ := c.Extension("STARTTLS"); !ok {
			_ = c.Close()
			return fmt.Errorf("%w: SMTP server does not offer STARTTLS; refusing plaintext", errPermanent)
		}
		if err := c.StartTLS(tlsCfg); err != nil {
			_ = c.Close()
			return err
		}
	}
	defer c.Close()
	if cfg.Username != "" {
		if err := c.Auth(smtp.PlainAuth("", cfg.Username, password.RevealString(), cfg.Host)); err != nil {
			return err
		}
	}
	if err := c.Mail(cfg.From); err != nil {
		return err
	}
	for _, to := range cfg.To {
		if err := c.Rcpt(to); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
