// Package webhook signs and matches event webhooks (ADR-0021) following the
// Standard Webhooks specification.
package webhook

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"slices"
	"strconv"
	"strings"
	"time"
)

// SecretPrefix marks a signing secret, as in Standard Webhooks.
const SecretPrefix = "whsec_"

// NewSecret returns a fresh signing secret: the prefix and 32 random bytes in
// standard base64.
func NewSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return SecretPrefix + base64.StdEncoding.EncodeToString(b)
}

// secretKey decodes the HMAC key from a secret.
func secretKey(secret string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(secret, SecretPrefix))
	if err != nil || len(k) < 24 {
		return nil, errors.New("webhook secret must be whsec_ followed by at least 24 base64 bytes")
	}
	return k, nil
}

// Sign returns the "v1,<base64>" signature of a message.
func Sign(secret, msgID string, ts time.Time, body []byte) (string, error) {
	k, err := secretKey(secret)
	if err != nil {
		return "", err
	}
	m := hmac.New(sha256.New, k)
	m.Write([]byte(msgID + "." + strconv.FormatInt(ts.Unix(), 10) + "."))
	m.Write(body)
	return "v1," + base64.StdEncoding.EncodeToString(m.Sum(nil)), nil
}

// Headers returns the Standard Webhooks headers for a message, signed with
// every given secret (more than one while a rotated secret is still valid).
func Headers(secrets []string, msgID string, ts time.Time, body []byte) (map[string]string, error) {
	var sigs []string
	for _, s := range secrets {
		sig, err := Sign(s, msgID, ts, body)
		if err != nil {
			return nil, err
		}
		sigs = append(sigs, sig)
	}
	return map[string]string{
		"webhook-id":        msgID,
		"webhook-timestamp": strconv.FormatInt(ts.Unix(), 10),
		"webhook-signature": strings.Join(sigs, " "),
	}, nil
}

// Verify checks headers against a secret within tolerance of now; it is what
// a receiver does, used here by tests and `certloom webhook` tooling.
func Verify(secret string, h map[string]string, body []byte, now time.Time, tolerance time.Duration) error {
	sec, err := strconv.ParseInt(h["webhook-timestamp"], 10, 64)
	if err != nil {
		return errors.New("bad webhook-timestamp")
	}
	ts := time.Unix(sec, 0)
	if now.Sub(ts) > tolerance || ts.Sub(now) > tolerance {
		return errors.New("webhook-timestamp outside tolerance")
	}
	want, err := Sign(secret, h["webhook-id"], ts, body)
	if err != nil {
		return err
	}
	for _, s := range strings.Fields(h["webhook-signature"]) {
		if hmac.Equal([]byte(s), []byte(want)) {
			return nil
		}
	}
	return errors.New("no matching signature")
}

// Types is the event catalog (docs/events.md). Types are never renamed; a
// breaking change to a type's data gets a new name with a .v2 suffix.
var Types = []string{
	"certificate.issued",
	"deployment.created",
	"template.applied",
	"agent.enrolled", "agent.revoked",
	"renewal.verified", "renewal.failed", "renewal.rolled_back", "renewal.cancelled", "renewal.rolling_back",
	"renewal.blocked", "renewal.rate_limited", "renewal.window_override",
	"approval.requested", "approval.approved", "approval.denied", "approval.revoked", "approval.expired", "approval.blocking_renewal",
	"exception.requested", "exception.approved", "exception.denied", "exception.expiring", "exception.expired", "exception.revoked",
	"finding.opened", "finding.escalated", "finding.reopened", "finding.resolved",
	"alert.escalated", "alert.ack_expired",
}

// ValidFilter reports whether f is a known type or "prefix.*" of one.
func ValidFilter(f string) bool {
	if p, ok := strings.CutSuffix(f, ".*"); ok {
		return slices.ContainsFunc(Types, func(t string) bool { return strings.HasPrefix(t, p+".") })
	}
	return slices.Contains(Types, f)
}

// Matches reports whether an endpoint with these filters wants eventType.
func Matches(filters []string, eventType string) bool {
	for _, f := range filters {
		if f == eventType {
			return true
		}
		if p, ok := strings.CutSuffix(f, ".*"); ok && strings.HasPrefix(eventType, p+".") {
			return true
		}
	}
	return false
}
