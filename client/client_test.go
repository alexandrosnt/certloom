package client

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type seen struct {
	method, path, query, body string
	header                    http.Header
}

// fake answers with the given handlers in turn and records each request.
func fake(t *testing.T, replies ...func(http.ResponseWriter)) (*Client, func() []seen) {
	t.Helper()
	var mu sync.Mutex
	var got []seen
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		n := len(got)
		got = append(got, seen{r.Method, r.URL.Path, r.URL.RawQuery, string(b), r.Header.Clone()})
		mu.Unlock()
		if n >= len(replies) {
			t.Errorf("unexpected request %d: %s %s", n+1, r.Method, r.URL.Path)
			w.WriteHeader(500)
			return
		}
		replies[n](w)
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL+"/", "tok-1", WithRetries(3, 2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return c, func() []seen { mu.Lock(); defer mu.Unlock(); return got }
}

func reply(status int, body string, hdr ...string) func(http.ResponseWriter) {
	return func(w http.ResponseWriter) {
		for i := 0; i+1 < len(hdr); i += 2 {
			w.Header().Set(hdr[i], hdr[i+1])
		}
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}
}

func TestNewValidates(t *testing.T) {
	for _, ep := range []string{"", "certloom.example.com", "ftp://x", "https://"} {
		if _, err := New(ep, "t"); err == nil {
			t.Errorf("endpoint %q accepted", ep)
		}
	}
	if _, err := New("https://certloom.example.com", ""); err == nil {
		t.Error("empty token accepted")
	}
}

func TestRequestShapeAndDecoding(t *testing.T) {
	c, got := fake(t, reply(201, `{"id":"team_1","name":"sre"}`), reply(200, `{"items":[{"id":"team_1","name":"sre"}]}`))
	tm, err := c.CreateTeam(context.Background(), "sre", "")
	if err != nil || tm.ID != "team_1" {
		t.Fatalf("create: %+v %v", tm, err)
	}
	ts, err := c.ListTeams(context.Background())
	if err != nil || len(ts) != 1 || ts[0].Name != "sre" {
		t.Fatalf("list: %+v %v", ts, err)
	}
	r := got()[0]
	if r.method != "POST" || r.path != "/api/v1/teams" || r.header.Get("Authorization") != "Bearer tok-1" ||
		r.header.Get("Content-Type") != "application/json" || len(r.header.Get("Idempotency-Key")) != 32 {
		t.Fatalf("request: %+v", r)
	}
	if got()[1].header.Get("Idempotency-Key") != "" {
		t.Fatal("GET sent an Idempotency-Key")
	}
}

func TestPathSegmentsAreEscaped(t *testing.T) {
	c, got := fake(t, reply(204, ""))
	if err := c.DeleteTeam(context.Background(), "a/b c"); err != nil {
		t.Fatal(err)
	}
	if p := got()[0].path; p != "/api/v1/teams/a/b c" { // as the server decodes it
		t.Fatalf("path %q", p)
	}
}

func TestProblemErrors(t *testing.T) {
	c, _ := fake(t,
		reply(404, `{"type":"https://certloom.invalid/problems/not-found","title":"Not Found","status":404,"detail":"resource not found","request_id":"req_1"}`),
		reply(409, `{"type":"https://certloom.invalid/problems/in-use","title":"Conflict","status":409,"detail":"in use: still referenced by endpoints"}`),
		reply(502, `<html>bad gateway</html>`))
	_, err := c.GetTeam(context.Background(), "x")
	if !IsNotFound(err) || !strings.Contains(err.Error(), "req_1") {
		t.Fatalf("404: %v", err)
	}
	err = c.DeleteScope(context.Background(), "lab")
	var e *Error
	if !IsConflict(err) || !errors.As(err, &e) || e.Code() != "in-use" {
		t.Fatalf("409: %v", err)
	}
	if _, err = c.GetScope(context.Background(), "x"); !statusIs(err, 502) {
		t.Fatalf("non-problem body: %v", err)
	}
}

func TestRetriesKeepIdempotencyKey(t *testing.T) {
	c, got := fake(t, reply(429, "", "Retry-After", "0"), reply(503, ""), reply(201, `{"id":"scp_1"}`))
	if _, err := c.CreateScope(context.Background(), "lab", ScopeConfig{}); err != nil {
		t.Fatal(err)
	}
	g := got()
	if len(g) != 3 {
		t.Fatalf("attempts %d", len(g))
	}
	k := g[0].header.Get("Idempotency-Key")
	for _, r := range g {
		if r.header.Get("Idempotency-Key") != k || r.body != g[0].body {
			t.Fatal("retry changed the key or body")
		}
	}
}

func TestNoRetryWhenWaitTooLong(t *testing.T) {
	c, got := fake(t, reply(429, `{"status":429,"title":"Too Many Requests"}`, "Retry-After", "3600"))
	if _, err := c.ListTeams(context.Background()); !statusIs(err, 429) || len(got()) != 1 {
		t.Fatalf("err %v after %d attempts", err, len(got()))
	}
}

func TestPatchAndIfMatch(t *testing.T) {
	c, got := fake(t, reply(200, `{"id":"ep_1","version":4,"enabled":false}`))
	off := false
	e, err := c.UpdateEndpoint(context.Background(), "ep_1", EndpointPatch{Enabled: &off, Team: ptr("")}, 3)
	if err != nil || e.Version != 4 {
		t.Fatalf("%+v %v", e, err)
	}
	r := got()[0]
	if r.method != "PATCH" || r.header.Get("If-Match") != `"v3"` {
		t.Fatalf("request: %+v", r)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(r.body), &body)
	if len(body) != 2 || body["enabled"] != false || body["team"] != "" {
		t.Fatalf("patch body %s", r.body)
	}
}

func TestDocumentsSendRawYAML(t *testing.T) {
	c, got := fake(t, reply(200, `{"applied":false,"current_version":2}`))
	src := []byte("apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {}\n")
	p, err := c.ApplyPolicy(context.Background(), src, true)
	if err != nil || p.Applied {
		t.Fatalf("%+v %v", p, err)
	}
	r := got()[0]
	if r.method != "PUT" || r.query != "dry_run=true" || r.body != string(src) || r.header.Get("Content-Type") != "application/yaml" {
		t.Fatalf("request: %+v", r)
	}
}

func TestContextCancelStopsRetry(t *testing.T) {
	c, _ := fake(t, reply(503, "", "Retry-After", "1"))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := c.ListTeams(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err %v", err)
	}
}

func ptr[T any](v T) *T { return &v }

func TestIssuerEABAndAgents(t *testing.T) {
	c, got := fake(t, reply(200, `{"id":"iss_1","eab_mode":"reusable","eab_kid":"kid","has_eab_hmac":true}`),
		reply(200, `{"items":[{"id":"agt_1","name":"web-01","state":"active","health":"healthy"}]}`))
	i, err := c.SetIssuerEAB(context.Background(), "zerossl", EABReusable, "kid", "aG1hYw")
	if err != nil || !i.HasEABHMAC {
		t.Fatalf("%+v %v", i, err)
	}
	if r := got()[0]; r.method != "PUT" || r.path != "/api/v1/issuers/zerossl/eab" || !strings.Contains(r.body, `"hmac":"aG1hYw"`) {
		t.Fatalf("request: %+v", r)
	}
	as, err := c.ListAgents(context.Background())
	if err != nil || len(as) != 1 || as[0].Health != "healthy" {
		t.Fatalf("%+v %v", as, err)
	}
}
