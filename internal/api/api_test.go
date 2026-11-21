package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

var bg = context.Background()

type harness struct {
	t     *testing.T
	db    *storetest.DB
	svc   *app.Service
	srv   *httptest.Server
	org   string
	owner string
}

func newHarness(t *testing.T, configure func(*Server)) *harness {
	db := storetest.New(t)
	o, err := db.CreateOrg(bg, "api-test")
	if err != nil {
		t.Fatal(err)
	}
	var tok string
	_ = db.WithOrg(bg, o.ID, func(tx *store.Tx) error {
		_, v, err := tx.CreateToken(bg, "owner", store.RoleOwner, "test", time.Hour)
		tok = v.RevealString()
		return err
	})
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &app.Service{DB: db.DB, Prober: probe.New(), Log: log}
	s := &Server{Svc: svc, Log: log}
	if configure != nil {
		configure(s)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return &harness{t: t, db: db, svc: svc, srv: srv, org: o.ID, owner: tok}
}

func (h *harness) req(method, path, token string, body any, hdr map[string]string) (*http.Response, string) {
	h.t.Helper()
	var rd io.Reader
	switch b := body.(type) {
	case nil:
	case string:
		rd = strings.NewReader(b)
	default:
		j, _ := json.Marshal(b)
		rd = bytes.NewReader(j)
	}
	r, _ := http.NewRequest(method, h.srv.URL+path, rd)
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(r)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp, string(out)
}

func TestIdempotencyKeys(t *testing.T) {
	h := newHarness(t, nil)
	key := map[string]string{"Idempotency-Key": "create-team-1"}
	r1, b1 := h.req("POST", "/api/v1/teams", h.owner, map[string]string{"name": "sre"}, key)
	r2, b2 := h.req("POST", "/api/v1/teams", h.owner, map[string]string{"name": "sre"}, key)
	if r1.StatusCode != 201 || r2.StatusCode != 201 || b1 != b2 || r2.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("replay: %d %d replayed=%q\n%s\n%s", r1.StatusCode, r2.StatusCode, r2.Header.Get("Idempotent-Replayed"), b1, b2)
	}
	_, list := h.req("GET", "/api/v1/teams", h.owner, nil, nil)
	if strings.Count(list, `"name":"sre"`) != 1 {
		t.Fatalf("replayed request executed twice: %s", list)
	}
	if r, _ := h.req("POST", "/api/v1/teams", h.owner, map[string]string{"name": "other"}, key); r.StatusCode != 422 {
		t.Fatalf("same key, different body: want 422, got %d", r.StatusCode)
	}
	// A 4xx response is stored and replayed too (deterministic outcome).
	k2 := map[string]string{"Idempotency-Key": "dup-team"}
	h.req("POST", "/api/v1/teams", h.owner, map[string]string{"name": "dup"}, nil)
	ra, _ := h.req("POST", "/api/v1/teams", h.owner, map[string]string{"name": "dup"}, k2)
	rb, _ := h.req("POST", "/api/v1/teams", h.owner, map[string]string{"name": "dup"}, k2)
	if ra.StatusCode != 409 || rb.StatusCode != 409 || rb.Header.Get("Idempotent-Replayed") != "true" {
		t.Fatalf("conflict replay: %d %d", ra.StatusCode, rb.StatusCode)
	}
	// Token creation must never store its (secret) response.
	if r, body := h.req("POST", "/api/v1/tokens", h.owner, map[string]string{"name": "x", "role": "viewer"},
		map[string]string{"Idempotency-Key": "tok"}); r.StatusCode != 400 || !strings.Contains(body, "secret") {
		t.Fatalf("token endpoint should reject Idempotency-Key: %d %s", r.StatusCode, body)
	}
	var n int
	_ = h.db.Owner.QueryRow(bg, `SELECT count(*) FROM idempotency_keys WHERE key = 'tok'`).Scan(&n)
	if n != 0 {
		t.Fatal("token request stored an idempotency record")
	}
}

func TestETagIfMatch(t *testing.T) {
	h := newHarness(t, nil)
	h.req("POST", "/api/v1/teams", h.owner, map[string]string{"name": "a"}, nil)
	h.req("POST", "/api/v1/teams", h.owner, map[string]string{"name": "b"}, nil)
	h.req("POST", "/api/v1/lineages", h.owner, map[string]string{"name": "www"}, nil)

	r, _ := h.req("GET", "/api/v1/lineages/www", h.owner, nil, nil)
	tag := r.Header.Get("ETag")
	if tag != `"v1"` {
		t.Fatalf("ETag = %q", tag)
	}
	if r, _ := h.req("PUT", "/api/v1/lineages/www/owner", h.owner, map[string]string{"team": "a"}, map[string]string{"If-Match": tag}); r.StatusCode != 204 {
		t.Fatalf("first conditional update: %d", r.StatusCode)
	}
	// A second writer still holding v1 loses.
	if r, body := h.req("PUT", "/api/v1/lineages/www/owner", h.owner, map[string]string{"team": "b"}, map[string]string{"If-Match": tag}); r.StatusCode != 412 {
		t.Fatalf("stale If-Match: want 412, got %d %s", r.StatusCode, body)
	}
	r, _ = h.req("GET", "/api/v1/lineages/www", h.owner, nil, nil)
	if r.Header.Get("ETag") != `"v2"` {
		t.Fatalf("ETag after update = %q", r.Header.Get("ETag"))
	}
	if r, _ := h.req("PUT", "/api/v1/lineages/www/owner", h.owner, map[string]string{"team": "b"}, map[string]string{"If-Match": "garbage"}); r.StatusCode != 412 {
		t.Fatalf("malformed If-Match: want 412, got %d", r.StatusCode)
	}
	if r, _ := h.req("PUT", "/api/v1/lineages/nope/owner", h.owner, map[string]string{"team": "b"}, nil); r.StatusCode != 404 {
		t.Fatalf("missing lineage: want 404, got %d", r.StatusCode)
	}
	// Without If-Match, last write wins (backwards compatible).
	if r, _ := h.req("PUT", "/api/v1/lineages/www/owner", h.owner, map[string]string{"team": "b"}, nil); r.StatusCode != 204 {
		t.Fatalf("unconditional update: %d", r.StatusCode)
	}
}

func TestRateLimits(t *testing.T) {
	h := newHarness(t, func(s *Server) {
		s.UserLimit = NewLimiter(0.001, 3)
		s.IPFailLimit = NewLimiter(0.001, 2)
	})
	codes := []int{}
	for range 4 {
		r, _ := h.req("GET", "/api/v1/whoami", h.owner, nil, nil)
		codes = append(codes, r.StatusCode)
		if r.StatusCode == 429 && r.Header.Get("Retry-After") == "" {
			t.Fatal("429 without Retry-After")
		}
	}
	if codes[2] != 200 || codes[3] != 429 {
		t.Fatalf("principal limit: %v", codes)
	}
	bad := []int{}
	for range 3 {
		r, _ := h.req("GET", "/api/v1/whoami", "certloom_org_x.invalid", nil, nil)
		bad = append(bad, r.StatusCode)
	}
	if bad[0] != 401 || bad[2] != 429 {
		t.Fatalf("failed-auth limit: %v", bad)
	}
}

func importCert(t *testing.T, h *harness, c *testpki.Cert) {
	t.Helper()
	pc, _ := certparse.FromX509(c.Cert)
	if err := h.db.WithOrg(bg, h.org, func(tx *store.Tx) error {
		_, err := tx.UpsertCertificate(bg, pc, "import")
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPolicyPlanApply(t *testing.T) {
	h := newHarness(t, nil)
	// Expires in 60 days: no finding under defaults (warn at 30d), warning under 90d.
	importCert(t, h, testpki.Issue(t, nil, testpki.Options{CommonName: "x", NotBefore: time.Now().Add(-300 * 24 * time.Hour), NotAfter: time.Now().Add(60 * 24 * time.Hour)}))
	src := "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec:\n  expiry: {warning: 90d, critical: 14d}\n"

	r, body := h.req("PUT", "/api/v1/policy?dry_run=true", h.owner, src, map[string]string{"Content-Type": "application/yaml"})
	var plan app.PolicyPlan
	_ = json.Unmarshal([]byte(body), &plan)
	if r.StatusCode != 200 || plan.Applied || plan.Evaluated != 1 || len(plan.Changes) != 1 ||
		plan.Changes[0].Check != "expiry" || plan.Changes[0].From != "" || plan.Changes[0].To != "warning" {
		t.Fatalf("dry run: %d %s", r.StatusCode, body)
	}
	_, got := h.req("GET", "/api/v1/policy", h.owner, nil, nil)
	if !strings.Contains(got, `"version":0`) {
		t.Fatalf("dry run must not apply: %s", got)
	}
	r, body = h.req("PUT", "/api/v1/policy", h.owner, src, nil)
	if r.StatusCode != 200 || !strings.Contains(body, `"applied":true`) || !strings.Contains(body, `"version":1`) {
		t.Fatalf("apply: %d %s", r.StatusCode, body)
	}
	if r, _ := h.req("PUT", "/api/v1/policy", h.owner, "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {keys: {minRSABits: 1024}}", nil); r.StatusCode != 400 {
		t.Fatalf("weakening policy: want 400, got %d", r.StatusCode)
	}
	// Viewers can read but not apply.
	var viewer string
	_ = h.db.WithOrg(bg, h.org, func(tx *store.Tx) error {
		_, v, err := tx.CreateToken(bg, "v", store.RoleViewer, "test", time.Hour)
		viewer = v.RevealString()
		return err
	})
	if r, _ := h.req("PUT", "/api/v1/policy", viewer, src, nil); r.StatusCode != 403 {
		t.Fatalf("viewer apply: want 403, got %d", r.StatusCode)
	}
}

func TestEscalationAndPruning(t *testing.T) {
	h := newHarness(t, nil)
	h.req("PUT", "/api/v1/policy", h.owner, "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec:\n  escalation: {after: 15m, channels: [oncall]}\n  retention: {observations: 1d}\n", nil)
	h.req("POST", "/api/v1/channels", h.owner, map[string]any{"name": "oncall", "kind": "webhook", "config": map[string]any{"url": "https://hooks.example.test/x"}}, nil)
	h.req("POST", "/api/v1/channels", h.owner, map[string]any{"name": "other", "kind": "webhook", "config": map[string]any{"url": "https://hooks.example.test/y"}}, nil)

	// An alert that has been open for an hour.
	importCert(t, h, testpki.Issue(t, nil, testpki.Options{CommonName: "soon", NotBefore: time.Now().Add(-80 * 24 * time.Hour), NotAfter: time.Now().Add(2 * 24 * time.Hour)}))
	if err := h.svc.ScheduleCertSweeps(bg); err != nil {
		t.Fatal(err)
	}
	if err := runSweep(h); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Owner.Exec(bg, `UPDATE alerts SET created_at = now() - interval '1 hour'`); err != nil {
		t.Fatal(err)
	}
	n, err := h.svc.EscalateAlerts(bg)
	if err != nil || n != 1 {
		t.Fatalf("escalate: n=%d err=%v", n, err)
	}
	if n, _ := h.svc.EscalateAlerts(bg); n != 0 {
		t.Fatalf("escalated again within the interval: %d", n)
	}
	var toOncall, toOther int
	_ = h.db.Owner.QueryRow(bg, `SELECT count(*) FILTER (WHERE c.name='oncall'), count(*) FILTER (WHERE c.name='other')
		FROM outbox o JOIN notification_channels c ON c.id = o.channel_id WHERE o.payload->>'event' = 'alert.escalated'`).Scan(&toOncall, &toOther)
	if toOncall != 1 || toOther != 0 {
		t.Fatalf("escalation routing: oncall=%d other=%d", toOncall, toOther)
	}

	// Pruning keeps the newest observation per endpoint.
	_ = h.db.WithOrg(bg, h.org, func(tx *store.Tx) error {
		s, err := tx.CreateScope(bg, "s", store.ScopeConfig{})
		if err != nil {
			return err
		}
		e := &store.Endpoint{Host: "old.example.test", Port: 443, ScopeID: s.ID}
		if err := tx.CreateEndpoint(bg, e); err != nil {
			return err
		}
		for _, age := range []string{"10 days", "5 days", "3 days"} {
			if _, err := tx.Exec(bg, `INSERT INTO observations (org_id, endpoint_id, observed_at, error_class) VALUES ($1,$2, now() - $3::interval, 'timeout')`,
				h.org, e.ID, age); err != nil {
				return err
			}
		}
		return nil
	})
	res, err := h.svc.Prune(bg)
	if err != nil || res.Observations != 2 {
		t.Fatalf("prune: %+v %v", res, err)
	}
}

// runSweep claims the queued certificate sweep and runs it inline.
func runSweep(h *harness) error {
	q := &jobs.Queue{Pool: h.db.Pool, WorkerID: "test"}
	js, err := q.Claim(bg, []string{app.JobKindCertSweep}, 1)
	if err != nil {
		return err
	}
	if len(js) != 1 {
		return fmt.Errorf("expected 1 sweep job, got %d", len(js))
	}
	return h.svc.RunCertSweep(bg, js[0])
}
