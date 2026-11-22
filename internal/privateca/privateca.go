// Package privateca signs CSRs with private CAs that have their own API:
// HashiCorp Vault PKI and Smallstep step-ca (ADR-0028). The private key never
// reaches this package; it only relays a CSR the agent made.
package privateca

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Signer turns a CSR into a PEM chain, leaf first, without the root.
type Signer interface {
	Sign(ctx context.Context, csrPEM string, sans []string) (string, error)
}

// Error is a failed signing call. Permanent errors (authentication, a role or
// provisioner refusing the request) fail the run; others are retried.
type Error struct {
	Status     int
	Permanent  bool
	RetryAfter time.Duration
	Msg        string
}

func (e *Error) Error() string {
	if e.Status != 0 {
		return fmt.Sprintf("CA returned %d: %s", e.Status, e.Msg)
	}
	return e.Msg
}

// maxResponse bounds what is read from a CA; a chain is a few KiB.
const maxResponse = 1 << 20

// HTTPClient trusts only the roots in caBundle, follows no redirects and
// times out, because the CA URL is configuration, not something a CA can
// move us away from.
func HTTPClient(caBundle string) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(caBundle)) {
		return nil, errors.New("ca_bundle has no PEM certificates")
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = nil
	tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, nil
}

// postJSON sends body and decodes a 2xx reply into out. Non-2xx replies come
// back as *Error, with msg pulling the CA's own message out of the body.
func postJSON(ctx context.Context, c *http.Client, url string, hdr http.Header, body, out any, msg func([]byte) string) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	for k, v := range hdr {
		req.Header[k] = v
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return &Error{Msg: err.Error()}
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return &Error{Msg: "reading response: " + err.Error()}
	}
	if len(data) > maxResponse {
		return &Error{Status: resp.StatusCode, Permanent: true, Msg: "response larger than 1 MiB"}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return statusError(resp, msg(data))
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return &Error{Status: resp.StatusCode, Permanent: true, Msg: "malformed response: " + err.Error()}
	}
	return nil
}

func statusError(resp *http.Response, msg string) *Error {
	e := &Error{Status: resp.StatusCode, Msg: msg}
	if e.Msg == "" {
		e.Msg = http.StatusText(resp.StatusCode)
	}
	switch {
	case resp.StatusCode == http.StatusTooManyRequests:
		if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && s > 0 {
			e.RetryAfter = time.Duration(s) * time.Second
		}
	case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode >= 500:
	default:
		// Redirects (never followed), bad request, unauthorized, forbidden:
		// the same request fails again.
		e.Permanent = true
	}
	return e
}

// chain joins PEM certificates into a leaf-first chain and drops
// self-signed roots, which are never served.
func chain(pems ...string) (string, error) {
	var out strings.Builder
	seen := map[string]bool{}
	for _, p := range pems {
		rest := []byte(p)
		for {
			var blk *pem.Block
			blk, rest = pem.Decode(rest)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" || seen[string(blk.Bytes)] {
				continue
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				return "", fmt.Errorf("CA returned an unparsable certificate: %w", err)
			}
			seen[string(blk.Bytes)] = true
			if out.Len() > 0 && c.IsCA && bytes.Equal(c.RawIssuer, c.RawSubject) && c.CheckSignatureFrom(c) == nil {
				continue
			}
			_ = pem.Encode(&out, blk)
		}
	}
	if out.Len() == 0 {
		return "", &Error{Permanent: true, Msg: "CA returned no certificate"}
	}
	return out.String(), nil
}
