package api

import (
	"encoding/json"
	"testing"

	"github.com/alexandrosnt/certloom/client"
)

// TestGoClient runs the public Go client against the real server, so the
// client's types and paths stay in step with the API.
func TestGoClient(t *testing.T) {
	h := newHarness(t, nil)
	c, err := client.New(h.srv.URL, h.owner)
	if err != nil {
		t.Fatal(err)
	}

	team, err := c.CreateTeam(bg, "sre", "sre@example.test")
	if err != nil || team.ID == "" {
		t.Fatalf("create team: %+v %v", team, err)
	}
	if _, err := c.CreateTeam(bg, "sre", ""); !client.IsConflict(err) {
		t.Fatalf("duplicate team: %v", err)
	}
	name := "platform"
	if team, err = c.UpdateTeam(bg, team.ID, client.TeamPatch{Name: &name}); err != nil || team.Name != "platform" || team.Contact != "sre@example.test" {
		t.Fatalf("update team: %+v %v", team, err)
	}

	sc, err := c.CreateScope(bg, "lab", client.ScopeConfig{AllowCIDRs: []string{"127.0.0.0/8"}, AllowLoopback: true, Ports: []int{8443}})
	if err != nil {
		t.Fatal(err)
	}
	ep, err := c.CreateEndpoint(bg, client.EndpointInput{Host: "127.0.0.1", Port: 8443, Scope: "lab", Team: "platform"})
	if err != nil || ep.TeamID == nil || *ep.TeamID != team.ID || ep.Version != 1 {
		t.Fatalf("create endpoint: %+v %v", ep, err)
	}
	if err := c.DeleteScope(bg, sc.ID); !client.IsConflict(err) {
		t.Fatalf("delete used scope: %v", err)
	}
	iv := 900
	if ep, err = c.UpdateEndpoint(bg, ep.ID, client.EndpointPatch{IntervalSeconds: &iv}, ep.Version); err != nil || ep.Version != 2 || ep.IntervalSeconds != 900 {
		t.Fatalf("update endpoint: %+v %v", ep, err)
	}
	if _, err := c.UpdateEndpoint(bg, ep.ID, client.EndpointPatch{IntervalSeconds: &iv}, 1); !client.IsPreconditionFailed(err) {
		t.Fatalf("stale version: %v", err)
	}
	if got, err := c.GetEndpoint(bg, ep.ID); err != nil || got.Host != "127.0.0.1" || got.Version != 2 {
		t.Fatalf("get endpoint: %+v %v", got, err)
	}
	if err := c.DeleteEndpoint(bg, ep.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := c.GetEndpoint(bg, ep.ID); !client.IsNotFound(err) {
		t.Fatalf("deleted endpoint: %v", err)
	}
	if err := c.DeleteScope(bg, "lab"); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteTeam(bg, "platform"); err != nil {
		t.Fatal(err)
	}

	ch, err := c.CreateChannel(bg, client.ChannelInput{Name: "oncall", Kind: "webhook",
		Config: json.RawMessage(`{"url":"https://hooks.example.test/oncall"}`), MinSeverity: "critical"})
	if err != nil || !ch.Enabled {
		t.Fatalf("create channel: %+v %v", ch, err)
	}
	if _, err := c.ApplyPolicy(bg, []byte("apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec:\n  escalation: {after: 1h, channels: [oncall]}\n"), false); err != nil {
		t.Fatal(err)
	}
	pol, err := c.GetPolicy(bg)
	if err != nil || pol.Version != 1 || pol.Source == "" {
		t.Fatalf("policy: %+v %v", pol, err)
	}
	if err := c.DeleteChannel(bg, ch.ID); !client.IsConflict(err) {
		t.Fatalf("delete channel named by policy: %v", err)
	}
	plan, err := c.ApplyPolicy(bg, []byte("apiVersion: certloom/v1\nkind: MonitoringPolicy\nspec: {}\n"), true)
	if err != nil || plan.Applied {
		t.Fatalf("dry run: %+v %v", plan, err)
	}

	iss, err := c.CreateIssuer(bg, client.IssuerInput{Name: "le", DirectoryURL: "https://acme.example.test/dir", AgreeTOS: true})
	if err != nil || iss.EABMode == "" {
		t.Fatalf("create issuer: %+v %v", iss, err)
	}
	email := "pki@example.test"
	if iss, err = c.UpdateIssuer(bg, "le", client.IssuerPatch{Email: &email}); err != nil || iss.Email != email {
		t.Fatalf("update issuer: %+v %v", iss, err)
	}
	if err := c.DeleteIssuer(bg, iss.ID); err != nil {
		t.Fatal(err)
	}
	if list, err := c.ListIssuers(bg); err != nil || len(list) != 0 {
		t.Fatalf("issuers after delete: %+v %v", list, err)
	}
}
