// Package ari implements the client side of ACME Renewal Information
// (RFC 9773) for the control plane. ARI requests are unauthenticated GETs, so
// no ACME account key is needed here.
package ari

import (
	"context"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"math/rand/v2"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrNotSupported means the directory does not advertise renewalInfo.
var ErrNotSupported = errors.New("ACME server does not advertise ARI (renewalInfo)")

// Window is a suggested renewal window.
type Window struct {
	Start, End     time.Time
	ExplanationURL string
	RetryAfter     time.Duration
}

// Client fetches renewal information.
type Client struct {
	HTTP *http.Client
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

// CertID returns the RFC 9773 identifier: base64url(AKI keyIdentifier) "."
// base64url(DER-encoded serial number INTEGER contents).
func CertID(cert *x509.Certificate) (string, error) {
	if len(cert.AuthorityKeyId) == 0 {
		return "", errors.New("certificate has no Authority Key Identifier; ARI not possible")
	}
	der, err := asn1.Marshal(cert.SerialNumber)
	if err != nil {
		return "", err
	}
	// Strip the INTEGER tag and length; ARI uses the value bytes.
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(der, &raw); err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(cert.AuthorityKeyId) + "." + enc.EncodeToString(raw.Bytes), nil
}

// RenewalInfoURL discovers the renewalInfo base URL from the directory.
func (c *Client) RenewalInfoURL(ctx context.Context, directoryURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, directoryURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("directory returned %d", resp.StatusCode)
	}
	var dir struct {
		RenewalInfo string `json:"renewalInfo"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&dir); err != nil {
		return "", err
	}
	if dir.RenewalInfo == "" {
		return "", ErrNotSupported
	}
	return dir.RenewalInfo, nil
}

// Fetch retrieves the suggested window for cert.
func (c *Client) Fetch(ctx context.Context, renewalInfoURL string, cert *x509.Certificate) (*Window, error) {
	id, err := CertID(cert)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(renewalInfoURL, "/")+"/"+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("renewalInfo returned %d", resp.StatusCode)
	}
	var body struct {
		SuggestedWindow struct {
			Start time.Time `json:"start"`
			End   time.Time `json:"end"`
		} `json:"suggestedWindow"`
		ExplanationURL string `json:"explanationURL"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); err != nil {
		return nil, fmt.Errorf("invalid renewalInfo response: %w", err)
	}
	w := &Window{Start: body.SuggestedWindow.Start, End: body.SuggestedWindow.End, ExplanationURL: body.ExplanationURL,
		RetryAfter: parseRetryAfter(resp.Header.Get("Retry-After"))}
	if w.Start.IsZero() || w.End.IsZero() || !w.End.After(w.Start) {
		return nil, errors.New("invalid renewalInfo: suggestedWindow end must be after start")
	}
	return w, nil
}

func parseRetryAfter(v string) time.Duration {
	if v == "" {
		return 0
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t)
	}
	return 0
}

// ClampRetry bounds the next poll interval.
func ClampRetry(d time.Duration) time.Duration {
	switch {
	case d <= 0:
		return 6 * time.Hour
	case d < time.Hour:
		return time.Hour
	case d > 24*time.Hour:
		return 24 * time.Hour
	}
	return d
}

// ChooseTime picks a uniformly random time within the window, as RFC 9773
// section 4.2 recommends; if the window has passed, renew now.
func ChooseTime(w *Window, now time.Time, r *rand.Rand) time.Time {
	if !w.End.After(now) {
		return now
	}
	start := w.Start
	if start.Before(now) {
		start = now
	}
	span := w.End.Sub(start)
	if span <= 0 {
		return start
	}
	var n int64
	if r != nil {
		n = r.Int64N(int64(span))
	} else {
		n = rand.Int64N(int64(span)) //nolint:gosec // spreading renewal times, not a secret
	}
	return start.Add(time.Duration(n))
}

// MinLead is how long before NotAfter a certificate must be replaced at the
// latest: 7 days, scaled down to a fifth of the lifetime for short-lived ones.
func MinLead(cert *x509.Certificate) time.Duration {
	return min(7*24*time.Hour, cert.NotAfter.Sub(cert.NotBefore)/5)
}

// Fallback computes a renewal time without ARI: NotBefore + p-lifetime, but
// no later than NotAfter - minLead (p = 2/3).
func Fallback(cert *x509.Certificate) time.Time {
	life := cert.NotAfter.Sub(cert.NotBefore)
	at := cert.NotBefore.Add(life * 2 / 3)
	if latest := cert.NotAfter.Add(-MinLead(cert)); at.After(latest) {
		at = latest
	}
	return at
}

// serialFromID is used in tests to cross-check CertID.
func serialFromID(id string) *big.Int {
	_, s, _ := strings.Cut(id, ".")
	b, _ := base64.RawURLEncoding.DecodeString(s)
	return new(big.Int).SetBytes(b)
}
