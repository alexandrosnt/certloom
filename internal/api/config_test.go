package api

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestConfigLifecycle covers get, patch and delete for the configuration
// objects the Terraform provider manages, including deletes refused while
// something still references the object.
func TestConfigLifecycle(t *testing.T) {
	h := newHarness(t, nil)
	want := func(status int, method, path string, body any, hdr map[string]string) string {
		t.Helper()
		r, b := h.req(method, path, h.owner, body, hdr)
		if r.StatusCode != status {
			t.Fatalf("%s %s: want %d, got %d %s", method, path, status, r.StatusCode, b)
		}
		return b
	}
	id := func(body string) string {
		t.Helper()
		var v struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil || v.ID == "" {
			t.Fatalf("no id in %s", body)
		}
		return v.ID
	}

	// Teams.
	team := id(want(201, "POST", "/api/v1/teams", map[string]string{"name": "sre"}, nil))
	b := want(200, "PATCH", "/api/v1/teams/"+team, map[string]string{"contact": "sre@example.test"}, nil)
	if !strings.Contains(b, `"name":"sre"`) || !strings.Contains(b, "sre@example.test") {
		t.Fatalf("patch kept name and set contact: %s", b)
	}
	want(200, "PATCH", "/api/v1/teams/sre", map[string]string{"name": "platform"}, nil)
	want(200, "GET", "/api/v1/teams/platform", nil, nil)
	want(404, "GET", "/api/v1/teams/sre", nil, nil)
	want(400, "PATCH", "/api/v1/teams/platform", map[string]string{"name": " "}, nil)
	want(400, "PATCH", "/api/v1/teams/platform", map[string]any{"unknown": 1}, nil)
	want(201, "POST", "/api/v1/teams", map[string]string{"name": "other"}, nil)
	want(409, "PATCH", "/api/v1/teams/platform", map[string]string{"name": "other"}, nil)

	// Scopes and endpoints.
	loop := map[string]any{"name": "lab", "config": map[string]any{"allow_cidrs": []string{"127.0.0.0/8"}, "allow_loopback": true, "ports": []int{8443}}}
	scope := id(want(201, "POST", "/api/v1/scopes", loop, nil))
	want(201, "POST", "/api/v1/scopes", map[string]any{"name": "public", "config": map[string]any{"allow_hosts": []string{"*.example.test"}}}, nil)
	ep := id(want(201, "POST", "/api/v1/endpoints", map[string]any{"host": "127.0.0.1", "port": 8443, "scope": "lab", "team": "platform"}, nil))

	want(409, "DELETE", "/api/v1/teams/platform", nil, nil)
	want(409, "DELETE", "/api/v1/scopes/"+scope, nil, nil)

	r, _ := h.req("GET", "/api/v1/endpoints/"+ep, h.owner, nil, nil)
	tag := r.Header.Get("ETag")
	b = want(200, "PATCH", "/api/v1/endpoints/"+ep, map[string]any{"interval_seconds": 600, "enabled": false, "team": ""},
		map[string]string{"If-Match": tag})
	if !strings.Contains(b, `"interval_seconds":600`) || !strings.Contains(b, `"enabled":false`) || strings.Contains(b, "team_id") {
		t.Fatalf("endpoint patch: %s", b)
	}
	want(412, "PATCH", "/api/v1/endpoints/"+ep, map[string]any{"enabled": true}, map[string]string{"If-Match": tag})
	want(400, "PATCH", "/api/v1/endpoints/"+ep, map[string]any{"interval_seconds": 5}, nil)
	// The new scope must still allow the endpoint's host.
	want(400, "PATCH", "/api/v1/endpoints/"+ep, map[string]any{"scope": "public"}, nil)

	// Widening is allowed and narrowing a scope by patch replaces the config.
	b = want(200, "PATCH", "/api/v1/scopes/lab", map[string]any{"config": map[string]any{"allow_cidrs": []string{"127.0.0.1/32"}, "allow_loopback": true, "ports": []int{8443}}}, nil)
	if !strings.Contains(b, `"ports":[8443]`) {
		t.Fatalf("scope patch: %s", b)
	}
	want(400, "PATCH", "/api/v1/scopes/lab", map[string]any{"config": map[string]any{"allow_cidrs": []string{"not-a-cidr"}}}, nil)

	want(204, "DELETE", "/api/v1/endpoints/"+ep, nil, nil)
	want(404, "GET", "/api/v1/endpoints/"+ep, nil, nil)
	want(404, "DELETE", "/api/v1/endpoints/"+ep, nil, nil)
	want(204, "DELETE", "/api/v1/scopes/lab", nil, nil)
	want(204, "DELETE", "/api/v1/teams/platform", nil, nil)

	// Channels: the active policy pins channel names.
	ch := id(want(201, "POST", "/api/v1/channels", map[string]any{"name": "oncall", "kind": "webhook",
		"config": map[string]string{"url": "https://hooks.example.test/oncall"}}, nil))
	b = want(200, "PATCH", "/api/v1/channels/"+ch, map[string]any{"min_severity": "critical", "enabled": false}, nil)
	if !strings.Contains(b, `"min_severity":"critical"`) || !strings.Contains(b, `"kind":"webhook"`) {
		t.Fatalf("channel patch: %s", b)
	}
	want(400, "PATCH", "/api/v1/channels/"+ch, map[string]any{"min_severity": "loud"}, nil)
	want(200, "PUT", "/api/v1/policy", "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec:\n  escalation: {after: 15m, channels: [oncall]}\n", nil)
	want(409, "PATCH", "/api/v1/channels/"+ch, map[string]any{"name": "pager"}, nil)
	want(409, "DELETE", "/api/v1/channels/"+ch, nil, nil)
	want(200, "PUT", "/api/v1/policy", "apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {}\n", nil)
	want(204, "DELETE", "/api/v1/channels/"+ch, nil, nil)

	// Issuers: the CA and the terms-of-service decision are fixed.
	iss := id(want(201, "POST", "/api/v1/issuers", map[string]any{"name": "le", "directory_url": "https://acme.example.test/dir", "agree_tos": true}, nil))
	b = want(200, "PATCH", "/api/v1/issuers/le", map[string]any{"email": "pki@example.test", "profile": "shortlived"}, nil)
	if !strings.Contains(b, "pki@example.test") || !strings.Contains(b, "acme.example.test") {
		t.Fatalf("issuer patch: %s", b)
	}
	want(400, "PATCH", "/api/v1/issuers/le", map[string]any{"directory_url": "https://other.example.test/dir"}, nil)
	want(204, "DELETE", "/api/v1/issuers/"+iss, nil, nil)
	want(404, "GET", "/api/v1/issuers/le", nil, nil)

	// Every change is audited.
	var n int
	_ = h.db.Owner.QueryRow(bg, `SELECT count(*) FROM audit_events WHERE action IN ('teams.update','teams.delete','scopes.update',
		'scopes.delete','endpoints.update','endpoints.delete','channels.update','channels.delete','issuers.update','issuers.delete')`).Scan(&n)
	if n < 10 {
		t.Fatalf("audit events: %d", n)
	}
}
