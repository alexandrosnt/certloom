// Package client is a Go client for the certloom REST API (/api/v1).
//
// It depends only on the standard library so that tools such as the
// Terraform provider can use it without pulling in the server.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Client talks to one certloom server with one API token.
type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
	userAgent  string
	maxRetries int
	maxWait    time.Duration
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPClient sets the HTTP client, for example one that trusts a private CA.
func WithHTTPClient(h *http.Client) Option { return func(c *Client) { c.httpClient = h } }

// WithUserAgent sets the User-Agent header.
func WithUserAgent(ua string) Option { return func(c *Client) { c.userAgent = ua } }

// WithRetries sets how often a request answered with 429 or 503 is retried,
// and the longest wait between attempts. The default is 3 retries, 30s.
func WithRetries(n int, maxWait time.Duration) Option {
	return func(c *Client) { c.maxRetries, c.maxWait = n, maxWait }
}

// New returns a client for the server at endpoint (for example
// https://certloom.example.com) authenticating with an API token.
func New(endpoint, token string, opts ...Option) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(endpoint, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("certloom: invalid endpoint %q", endpoint)
	}
	if token == "" {
		return nil, errors.New("certloom: API token is required")
	}
	c := &Client{baseURL: u, token: token, httpClient: &http.Client{Timeout: 60 * time.Second},
		userAgent: "certloom-go-client", maxRetries: 3, maxWait: 30 * time.Second}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// Error is a problem response (RFC 9457) from the server.
type Error struct {
	StatusCode  int    `json:"status"`
	Type        string `json:"type"`
	Title       string `json:"title"`
	Detail      string `json:"detail"`
	Remediation string `json:"remediation,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
}

func (e *Error) Error() string {
	msg := e.Detail
	if msg == "" {
		msg = e.Title
	}
	if e.RequestID != "" {
		return fmt.Sprintf("certloom: %d %s (request %s)", e.StatusCode, msg, e.RequestID)
	}
	return fmt.Sprintf("certloom: %d %s", e.StatusCode, msg)
}

// Code is the last segment of the problem type, such as "not-found",
// "conflict" or "in-use".
func (e *Error) Code() string { return e.Type[strings.LastIndexByte(e.Type, '/')+1:] }

// IsNotFound reports whether err is a 404 from the server.
func IsNotFound(err error) bool { return statusIs(err, http.StatusNotFound) }

// IsConflict reports whether err is a 409 from the server: a name already
// taken, or an object still in use.
func IsConflict(err error) bool { return statusIs(err, http.StatusConflict) }

// IsPreconditionFailed reports whether an If-Match version was stale.
func IsPreconditionFailed(err error) bool { return statusIs(err, http.StatusPreconditionFailed) }

func statusIs(err error, status int) bool {
	var e *Error
	return errors.As(err, &e) && e.StatusCode == status
}

// request describes one API call.
type request struct {
	method      string
	path        string
	query       url.Values
	body        any    // marshalled as JSON unless raw is set
	raw         []byte // sent as is with contentType
	contentType string
	ifMatch     int64 // endpoint version; 0 sends no If-Match
}

// do sends req and decodes a JSON response into out (if non-nil). It returns
// the response headers for callers that need the ETag.
func (c *Client) do(ctx context.Context, req request, out any) (http.Header, error) {
	var body []byte
	ct := req.contentType
	switch {
	case req.raw != nil:
		body = req.raw
	case req.body != nil:
		b, err := json.Marshal(req.body)
		if err != nil {
			return nil, err
		}
		body, ct = b, "application/json"
	}
	// req.path is already escaped segment by segment (see ref), so it is
	// joined as text; setting url.URL.Path would escape it a second time.
	target := c.baseURL.String() + req.path
	if len(req.query) > 0 {
		target += "?" + req.query.Encode()
	}

	// POST is retried only with an Idempotency-Key, so a create the server
	// already finished is replayed instead of repeated.
	var idemKey string
	if req.method == http.MethodPost {
		idemKey = newKey()
	}
	for attempt := 0; ; attempt++ {
		hr, err := http.NewRequestWithContext(ctx, req.method, target, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		hr.Header.Set("Authorization", "Bearer "+c.token)
		hr.Header.Set("Accept", "application/json")
		hr.Header.Set("User-Agent", c.userAgent)
		if ct != "" {
			hr.Header.Set("Content-Type", ct)
		}
		if idemKey != "" {
			hr.Header.Set("Idempotency-Key", idemKey)
		}
		if req.ifMatch > 0 {
			hr.Header.Set("If-Match", fmt.Sprintf(`"v%d"`, req.ifMatch))
		}
		resp, err := c.httpClient.Do(hr)
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode < 300 {
			if out != nil && len(data) > 0 {
				if err := json.Unmarshal(data, out); err != nil {
					return nil, fmt.Errorf("certloom: decoding %s %s: %w", req.method, req.path, err)
				}
			}
			return resp.Header, nil
		}
		if wait, ok := c.retryAfter(resp, attempt); ok {
			t := time.NewTimer(wait)
			select {
			case <-ctx.Done():
				t.Stop()
				return nil, ctx.Err()
			case <-t.C:
			}
			continue
		}
		e := &Error{StatusCode: resp.StatusCode}
		if json.Unmarshal(data, e) != nil || e.StatusCode == 0 {
			e.StatusCode, e.Title = resp.StatusCode, http.StatusText(resp.StatusCode)
		}
		return nil, e
	}
}

// retryAfter decides whether to retry a 429 or 503 and how long to wait.
func (c *Client) retryAfter(resp *http.Response, attempt int) (time.Duration, bool) {
	if attempt >= c.maxRetries || (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable) {
		return 0, false
	}
	wait := time.Duration(1<<attempt) * time.Second
	if s := resp.Header.Get("Retry-After"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n >= 0 {
			wait = time.Duration(n) * time.Second
		} else if t, err := http.ParseTime(s); err == nil {
			wait = time.Until(t)
		}
	}
	if wait > c.maxWait {
		return 0, false
	}
	return max(wait, 0), true
}

func newKey() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// ref escapes an id or name for use as a path segment.
func ref(s string) string { return url.PathEscape(s) }

type list[T any] struct {
	Items []T `json:"items"`
}

func getList[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var l list[T]
	if _, err := c.do(ctx, request{method: http.MethodGet, path: path}, &l); err != nil {
		return nil, err
	}
	return l.Items, nil
}
