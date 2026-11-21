package api

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/alexandrosnt/certloom/internal/store"
	"golang.org/x/time/rate"
)

// ---------- rate limiting ----------

// Limiter is a set of per-key token buckets (per principal, per client IP).
// Limits are per process: with N replicas the effective limit is Nx higher.
type Limiter struct {
	Rate  rate.Limit
	Burst int
	mu    sync.Mutex
	m     map[string]*entry
}

type entry struct {
	l    *rate.Limiter
	seen time.Time
}

// NewLimiter returns a limiter allowing perSecond sustained with burst.
func NewLimiter(perSecond float64, burst int) *Limiter {
	return &Limiter{Rate: rate.Limit(perSecond), Burst: burst, m: map[string]*entry{}}
}

// Allow reports whether key may proceed, and the remaining tokens.
func (l *Limiter) Allow(key string) (bool, int, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	e, ok := l.m[key]
	if !ok {
		if len(l.m) > 10000 { // evict idle entries to bound memory
			for k, v := range l.m {
				if now.Sub(v.seen) > 10*time.Minute {
					delete(l.m, k)
				}
			}
		}
		e = &entry{l: rate.NewLimiter(l.Rate, l.Burst)}
		l.m[key] = e
	}
	e.seen = now
	r := e.l.ReserveN(now, 1)
	if d := r.DelayFrom(now); d > 0 {
		r.CancelAt(now)
		return false, 0, d
	}
	return true, int(math.Max(0, math.Floor(e.l.TokensAt(now)))), 0
}

func clientIP(r *http.Request) string {
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return h
}

func tooMany(w http.ResponseWriter, r *http.Request, retry time.Duration, what string) {
	secs := int(math.Ceil(retry.Seconds()))
	w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
	problem(w, r, 429, "rate-limited", what, "Slow down and retry after the Retry-After interval.")
}

// ---------- idempotency ----------

// idempotencyExempt lists POST routes whose responses must never be stored
// because they contain secrets.
var idempotencyExempt = map[string]bool{"POST /api/v1/tokens": true, "POST /api/v1/webhooks": true,
	"POST /api/v1/webhooks/{id}/rotate-secret": true}

type recorder struct {
	http.ResponseWriter
	status int
	buf    bytes.Buffer
}

func (r *recorder) WriteHeader(s int) { r.status = s; r.ResponseWriter.WriteHeader(s) }
func (r *recorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = 200
	}
	r.buf.Write(b)
	return r.ResponseWriter.Write(b)
}

// idempotent wraps a POST handler with Idempotency-Key support:
// the first request runs and its response is stored; retries with the same
// key and identical request replay it; a different request with the same key
// gets 422; a concurrent duplicate gets 409. Server errors release the key.
func (s *Server) idempotent(pattern string, fn handlerFunc) handlerFunc {
	if !strings.HasPrefix(pattern, "POST ") {
		return fn
	}
	return func(w http.ResponseWriter, r *http.Request) error {
		key := r.Header.Get("Idempotency-Key")
		if key == "" {
			return fn(w, r)
		}
		if idempotencyExempt[pattern] {
			return errors.Join(errBadRequest, errors.New("Idempotency-Key is not supported on this endpoint (its response contains a secret)"))
		}
		if len(key) > 255 || strings.ContainsFunc(key, func(c rune) bool { return c < 0x21 || c > 0x7e }) {
			return errors.Join(errBadRequest, errors.New("Idempotency-Key must be 1-255 printable ASCII characters"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return err
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		h := sha256.New()
		fmt.Fprintf(h, "%s\n%s\n", r.Method, r.URL.RequestURI())
		h.Write(body)
		p := PrincipalFrom(r.Context())
		prev, err := s.Svc.DB.BeginIdempotent(r.Context(), p.OrgID, key, p.Actor, h.Sum(nil))
		if err != nil {
			return err
		}
		if prev != nil {
			w.Header().Set("Content-Type", prev.ContentType)
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(prev.Status)
			_, _ = w.Write(prev.Body) //nolint:gosec // replays our own stored JSON response
			return nil
		}
		rec := &recorder{ResponseWriter: w}
		herr := fn(rec, r)
		if herr != nil {
			s.writeError(rec, r, herr)
		}
		if rec.status >= 500 || rec.status == 0 {
			_ = s.Svc.DB.AbortIdempotent(r.Context(), p.OrgID, key)
			return nil
		}
		if err := s.Svc.DB.FinishIdempotent(r.Context(), p.OrgID, key, store.IdempotentResponse{
			Status: rec.status, Body: rec.buf.Bytes(), ContentType: rec.Header().Get("Content-Type")}); err != nil {
			s.Log.Error("store idempotent response", "error", err)
		}
		return nil
	}
}

// ---------- ETag / If-Match ----------

func etag(version int64) string { return fmt.Sprintf(`"v%d"`, version) }

// ifMatch parses If-Match. It returns nil when absent or "*".
func ifMatch(r *http.Request) (*int64, error) {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	if v == "" || v == "*" {
		return nil, nil
	}
	v = strings.TrimPrefix(v, "W/")
	n, err := strconv.ParseInt(strings.TrimSuffix(strings.TrimPrefix(v, `"v`), `"`), 10, 64)
	if err != nil || !strings.HasPrefix(v, `"v`) {
		return nil, store.ErrPrecondition
	}
	return &n, nil
}
