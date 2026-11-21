package workflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

// withWildTarget adds a target without a webroot and no local dns solvers.
func withWildTarget(c *agent.Config) {
	wild := c.Targets[0]
	wild.Name, wild.LiveLink, wild.Webroot = "wild", filepath.Join(c.StateDir, "live", "wild"), ""
	c.Targets = append(c.Targets, wild)
}

const forbidCentralDNS = `apiVersion: certloom/v1
kind: MonitoringPolicy
spec:
  dns:
    centralCredentials: forbidden
`

func TestCentralDNSSolverIsSealedToTheAgent(t *testing.T) {
	e := newEnvWith(t, testpki.Options{}, withWildTarget)
	// Derived from plain text so the secret scanner does not flag it; the test
	// looks for this exact string anywhere it must not be.
	tsig := base64.StdEncoding.EncodeToString([]byte("central tsig secret for the test"))
	sec := secret.FromString(`{"tsig_key":"key \"wf\" { algorithm hmac-sha256; secret \"` + tsig + `\"; };"}`)
	in := app.DNSSolverInput{Name: "bind", Provider: "rfc2136", Zones: []string{"WF.test."},
		Config: map[string]any{"nameserver": "127.0.0.1:53"}, Secret: sec}

	operator := authz.Principal{OrgID: e.owner.OrgID, Actor: "user:op", Role: store.RoleOperator}
	if _, err := e.svc.CreateDNSSolver(ctx, operator, in); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator created a solver: %v", err)
	}
	if _, err := e.svc.CreateDNSSolver(ctx, e.owner, app.DNSSolverInput{Name: "x", Provider: "cloudflare", Zones: []string{"wf.test"},
		Secret: secret.FromString(`{"wrong":"key"}`)}); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("cloudflare without api_token: %v", err)
	}
	d, err := e.svc.CreateDNSSolver(ctx, e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Zones[0] != "wf.test" || !d.HasSecret {
		t.Fatalf("solver: %+v", d)
	}
	list, _ := e.svc.ListDNSSolvers(ctx, e.owner)
	if b, _ := json.Marshal(list); strings.Contains(string(b), tsig) || strings.Contains(string(b), "secret_ciphertext") {
		t.Fatalf("list exposes the secret: %s", b)
	}

	dep := app.DeploymentInput{Lineage: "wild", Agent: "web-01", Target: "wild", Issuer: "fake", SANs: []string{"*.wf.test"},
		Challenge: agentproto.ChallengeDNS01}
	if _, err := e.svc.CreateLineage(ctx, e.owner, "wild", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateDeployment(ctx, e.owner, dep); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("dns-01 before the solver is assigned: %v", err)
	}
	if err := e.svc.AssignDNSSolver(ctx, e.owner, "bind", "web-01", true); err != nil {
		t.Fatal(err)
	}
	dd, err := e.svc.CreateDeployment(ctx, e.owner, dep)
	if err != nil {
		t.Fatal(err)
	}

	var got agentproto.IssuePayload
	var taskID string
	e.agent.SetHandler(agentproto.TaskIssue, func(c context.Context, task *agentproto.Task) (any, error) {
		got, taskID = agentproto.IssuePayload{}, task.ID
		_ = json.Unmarshal(task.Payload, &got)
		return e.fakeIssue(c, task)
	})
	renew := func() {
		t.Helper()
		run, err := e.svc.RequestRenewal(ctx, e.owner, dd.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r := e.pump(run.ID); r.State != store.RunVerified {
			t.Fatalf("state %s err %q", r.State, r.Error)
		}
	}
	renew()
	if len(got.DNSSolvers) != 1 || got.DNSSolvers[0].Name != "bind" || len(got.DNSSolvers[0].Sealed) == 0 ||
		got.DNSSolvers[0].Config["nameserver"] != "127.0.0.1:53" {
		t.Fatalf("issue task solvers: %+v", got.DNSSolvers)
	}

	// The secret is in no stored task, audit event or log of the delivery.
	for _, q := range []string{`SELECT count(*) FROM agent_tasks WHERE envelope::text LIKE '%' || $1 || '%'`,
		`SELECT count(*) FROM audit_events WHERE detail::text LIKE '%' || $1 || '%'`,
		`SELECT count(*) FROM dns_solvers WHERE position(convert_to($1, 'UTF8') in secret_ciphertext) > 0`} {
		var n int
		if err := e.db.Owner.QueryRow(ctx, q, tsig).Scan(&n); err != nil || n != 0 {
			t.Fatalf("%s: %d %v", q, n, err)
		}
	}
	var delivered int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM audit_events WHERE action = 'dns_solvers.secret_delivered'
		AND detail->>'task' = $1`, taskID).Scan(&delivered)
	if delivered != 1 {
		t.Fatalf("delivery audited %d times", delivered)
	}

	// Rotation reaches the next issuance; forbidding central credentials stops delivery.
	if err := e.svc.SetDNSSolverSecret(ctx, e.owner, "bind", sec); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.ApplyPolicy(ctx, e.owner, []byte(forbidCentralDNS), false); err != nil {
		t.Fatal(err)
	}
	renew()
	if len(got.DNSSolvers) != 0 {
		t.Fatalf("solvers sent although policy forbids them: %+v", got.DNSSolvers)
	}
	if err := e.svc.SetDNSSolverSecret(ctx, e.owner, "bind", sec); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("secret stored although policy forbids it: %v", err)
	}
}

func TestAmbientSolverOnlyForPlugins(t *testing.T) {
	e := newEnv(t)
	_, err := e.svc.CreateDNSSolver(ctx, e.owner, app.DNSSolverInput{Name: "cf", Provider: "cloudflare", Zones: []string{"wf.test"},
		Credential: "ambient"})
	if !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("ambient cloudflare: %v", err)
	}
	d, err := e.svc.CreateDNSSolver(ctx, e.owner, app.DNSSolverInput{Name: "r53", Provider: "plugin", Plugin: "/usr/libexec/certloom/dns/route53",
		PluginSHA256: strings.Repeat("ab", 32), Zones: []string{"wf.test"}, Credential: "ambient"})
	if err != nil || d.HasSecret {
		t.Fatalf("%+v %v", d, err)
	}
	if err := e.svc.SetDNSSolverSecret(ctx, e.owner, "r53", secret.FromString(`{"a":"b"}`)); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("secret on an ambient solver: %v", err)
	}
}
