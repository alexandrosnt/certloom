package workflow

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/notify"
	"github.com/alexandrosnt/certloom/internal/store"
	wh "github.com/alexandrosnt/certloom/internal/webhook"
)

type received struct {
	headers map[string]string
	body    []byte
}

// receiver records webhook requests and answers with status.
type receiver struct {
	mu     sync.Mutex
	got    []received
	status atomic.Int32
}

func (rc *receiver) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	h := map[string]string{}
	for _, k := range []string{"webhook-id", "webhook-timestamp", "webhook-signature"} {
		h[k] = r.Header.Get(k)
	}
	rc.mu.Lock()
	rc.got = append(rc.got, received{h, b})
	rc.mu.Unlock()
	w.WriteHeader(int(rc.status.Load()))
}

func (rc *receiver) take() []received {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	out := rc.got
	rc.got = nil
	return out
}

func TestEventWebhooks(t *testing.T) {
	e := newEnv(t)
	rc := &receiver{}
	rc.status.Store(200)
	srv := httptest.NewServer(rc)
	t.Cleanup(srv.Close)
	d := &notify.WebhookDeliverer{DB: e.db.DB, KEK: e.svc.PKI.KEK, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	deliver := func() int {
		t.Helper()
		n, err := d.RunOnce(ctx, 50)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	for name, in := range map[string]app.WebhookEndpointInput{
		"unknown type":   {Name: "x", URL: srv.URL, EventTypes: []string{"renewal.exploded"}, AllowPrivate: true},
		"no types":       {Name: "x", URL: srv.URL, AllowPrivate: true},
		"http public":    {Name: "x", URL: "http://hooks.example.com/x", EventTypes: []string{"renewal.*"}},
		"credentials":    {Name: "x", URL: "https://u:p@hooks.example.com/x", EventTypes: []string{"renewal.*"}},
		"everything (*)": {Name: "x", URL: srv.URL, EventTypes: []string{"*"}, AllowPrivate: true},
	} {
		if _, err := e.svc.CreateWebhookEndpoint(ctx, e.owner, in); !errors.Is(err, app.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}
	operator := e.principal("user:op", store.RoleOperator)
	if _, err := e.svc.CreateWebhookEndpoint(ctx, operator, app.WebhookEndpointInput{Name: "x", URL: srv.URL,
		EventTypes: []string{"renewal.*"}, AllowPrivate: true}); err == nil {
		t.Fatal("operator created a webhook")
	}
	ep, err := e.svc.CreateWebhookEndpoint(ctx, e.owner, app.WebhookEndpointInput{Name: "ops", URL: srv.URL,
		EventTypes: []string{"renewal.*", "certificate.issued"}, AllowPrivate: true})
	if err != nil || !strings.HasPrefix(ep.Secret, wh.SecretPrefix) {
		t.Fatalf("%+v %v", ep, err)
	}
	secret := ep.Secret
	list, _ := e.svc.ListWebhookEndpoints(ctx, e.owner)
	if b, _ := json.Marshal(list); strings.Contains(string(b), secret) || strings.Contains(string(b), "ciphertext") {
		t.Fatalf("list exposes the secret: %s", b)
	}

	// A renewal produces certificate.issued and renewal.verified, signed.
	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified {
		t.Fatalf("renewal %s %q", r.State, r.Error)
	}
	if n := deliver(); n != 2 {
		t.Fatalf("delivered %d", n)
	}
	types := map[string]string{}
	for _, m := range rc.take() {
		if err := wh.Verify(secret, m.headers, m.body, time.Now(), 5*time.Minute); err != nil {
			t.Fatalf("signature: %v", err)
		}
		var body struct {
			Type      string
			Timestamp time.Time
			Data      map[string]any
		}
		if err := json.Unmarshal(m.body, &body); err != nil || body.Timestamp.IsZero() {
			t.Fatalf("body %s", m.body)
		}
		types[body.Type] = m.headers["webhook-id"]
		if body.Type == "certificate.issued" && body.Data["deployment_id"] != e.dep.ID {
			t.Fatalf("certificate.issued data %v", body.Data)
		}
	}
	if types["certificate.issued"] == "" || types["renewal.verified"] == "" {
		t.Fatalf("types %v", types)
	}
	// Unsubscribed types are not even stored.
	var stored int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM events WHERE type NOT IN ('certificate.issued','renewal.verified')`).Scan(&stored)
	if stored != 0 {
		t.Fatalf("%d unsubscribed events stored", stored)
	}

	// 5xx is retried later; 4xx fails for good; redelivery keeps the id.
	rc.status.Store(503)
	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified {
		t.Fatal(r.State)
	}
	deliver()
	rc.take()
	ds, _ := e.svc.ListWebhookDeliveries(ctx, e.owner, "ops", 10)
	if ds[0].State != "pending" || ds[0].Attempts != 1 || ds[0].LastStatus == nil || *ds[0].LastStatus != 503 ||
		!ds[0].NextAttemptAt.After(time.Now()) {
		t.Fatalf("after 503: %+v", ds[0])
	}
	if deliver() != 0 {
		t.Fatal("retried before its time")
	}
	rc.status.Store(400)
	_, _ = e.db.Owner.Exec(ctx, `UPDATE webhook_deliveries SET next_attempt_at = now() WHERE state = 'pending'`)
	deliver()
	rc.take()
	ds, _ = e.svc.ListWebhookDeliveries(ctx, e.owner, "ops", 10)
	if ds[0].State != "failed" || ds[0].Attempts != 2 {
		t.Fatalf("after 400: %+v", ds[0])
	}
	rc.status.Store(200)
	if err := e.svc.RedeliverWebhook(ctx, e.owner, "ops", ds[0].ID); err != nil {
		t.Fatal(err)
	}
	if deliver() != 1 {
		t.Fatal("redelivery not sent")
	}
	if m := rc.take(); len(m) != 1 || m[0].headers["webhook-id"] != ds[0].EventID {
		t.Fatalf("redelivery %+v", m)
	}

	// Rotation: both secrets sign for a while.
	newSecret, err := e.svc.RotateWebhookSecret(ctx, e.owner, "ops")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.svc.RedeliverWebhook(ctx, e.owner, "ops", ds[0].ID); err != nil {
		t.Fatal(err)
	}
	deliver()
	m := rc.take()
	if len(m) != 1 || len(strings.Fields(m[0].headers["webhook-signature"])) != 2 {
		t.Fatalf("rotation %+v", m)
	}
	for _, s := range []string{secret, newSecret} {
		if err := wh.Verify(s, m[0].headers, m[0].body, time.Now(), 5*time.Minute); err != nil {
			t.Fatal(err)
		}
	}

	// Secrets are in no event, audit record or delivery log.
	for _, q := range []string{`SELECT count(*) FROM events WHERE data::text LIKE '%' || $1 || '%'`,
		`SELECT count(*) FROM audit_events WHERE detail::text LIKE '%' || $1 || '%'`,
		`SELECT count(*) FROM idempotency_keys WHERE position(convert_to($1, 'UTF8') in response) > 0`} {
		for _, s := range []string{secret, newSecret} {
			var n int
			if err := e.db.Owner.QueryRow(ctx, q, s).Scan(&n); err != nil || n != 0 {
				t.Fatalf("%s: %d %v", q, n, err)
			}
		}
	}

	// An endpoint failing for three days is disabled.
	_, _ = e.db.Owner.Exec(ctx, `UPDATE webhook_endpoints SET failing_since = now() - interval '4 days'`)
	if err := e.svc.SweepWebhooks(ctx); err != nil {
		t.Fatal(err)
	}
	got, _ := e.svc.GetWebhookEndpoint(ctx, e.owner, "ops")
	if got.Enabled || !strings.Contains(got.DisabledReason, "every delivery failed") {
		t.Fatalf("not disabled: %+v", got)
	}
	if err := e.svc.SetWebhookEndpointEnabled(ctx, e.owner, "ops", true); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.svc.GetWebhookEndpoint(ctx, e.owner, "ops"); !got.Enabled || got.FailingSince != nil {
		t.Fatalf("re-enabled: %+v", got)
	}
}
