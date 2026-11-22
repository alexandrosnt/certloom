package workflow

import (
	"errors"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

func webTemplate(issuer, allowed string) []byte {
	return []byte(`apiVersion: certloom/v1
kind: CertificateTemplate
metadata: {name: web}
spec:
  issuer: ` + issuer + `
  sans: {allowed: [` + allowed + `], maxNames: 2}
`)
}

const templatesRequired = `apiVersion: certloom/v1
kind: MonitoringPolicy
spec:
  templates: {required: true}
`

const templatesAndApprovalsRequired = `apiVersion: certloom/v1
kind: MonitoringPolicy
spec:
  templates: {required: true}
  approvals: {deployments: required}
`

func TestTemplates(t *testing.T) {
	e := newEnvWith(t, testpki.Options{}, withWildTarget)
	operator := e.principal("user:op", store.RoleOperator)
	if _, err := e.svc.ApplyTemplate(ctx, operator, webTemplate("fake", `"*.wf.test"`), false); !errors.Is(err, authz.ErrForbidden) {
		t.Fatalf("operator applied a template: %v", err)
	}
	if _, err := e.svc.ApplyTemplate(ctx, e.owner, webTemplate("missing", `"*.wf.test"`), false); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("unknown issuer: %v", err)
	}
	plan, err := e.svc.ApplyTemplate(ctx, e.owner, webTemplate("fake", `"*.wf.test"`), false)
	if err != nil || !plan.Applied || plan.Version != 1 || plan.CurrentVersion != 0 {
		t.Fatalf("%+v %v", plan, err)
	}

	if _, err := e.svc.CreateLineage(ctx, e.owner, "wild", "", ""); err != nil {
		t.Fatal(err)
	}
	in := app.DeploymentInput{Lineage: "wild", Agent: "web-01", Target: "wild", Template: "web", SANs: []string{"www.wf.test"}}
	for name, bad := range map[string]func(*app.DeploymentInput){
		"name outside template": func(i *app.DeploymentInput) { i.SANs = []string{"www.other.test"} },
		"too many names":        func(i *app.DeploymentInput) { i.SANs = []string{"a.wf.test", "b.wf.test", "c.wf.test"} },
		"other issuer":          func(i *app.DeploymentInput) { i.Issuer = "someone-else" },
		"other challenge":       func(i *app.DeploymentInput) { i.Challenge = "dns-01" },
		"unknown template":      func(i *app.DeploymentInput) { i.Template = "nope" },
	} {
		bi := in
		bad(&bi)
		if _, err := e.svc.CreateDeployment(ctx, e.owner, bi); !errors.Is(err, app.ErrInvalid) {
			t.Errorf("%s: %v", name, err)
		}
	}

	// Policy can require templates.
	if _, err := e.svc.ApplyPolicy(ctx, e.owner, []byte(templatesRequired), false); err != nil {
		t.Fatal(err)
	}
	noTpl := in
	noTpl.Template, noTpl.Issuer = "", "fake"
	if _, err := e.svc.CreateDeployment(ctx, e.owner, noTpl); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("deployment without a template under templates.required: %v", err)
	}
	d, err := e.svc.CreateDeployment(ctx, e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if d.TemplateID == nil || d.Approval != store.ApprovalApproved {
		t.Fatalf("deployment %+v", d)
	}
	fake := d.IssuerID

	// A new issuer in the template moves the deployment; with optional
	// approvals and an owner applying, the new spec is approved at once.
	if err := e.svc.CreateIssuer(ctx, e.owner, &store.Issuer{Name: "fake2", DirectoryURL: "https://acme2.invalid/dir", AgreeTOS: true}, secret.Value{}); err != nil {
		t.Fatal(err)
	}
	dry, err := e.svc.ApplyTemplate(ctx, e.owner, webTemplate("fake2", `"*.wf.test"`), true)
	if err != nil || dry.Applied || len(dry.Changes) != 1 || dry.Changes[0].Deployment != d.ID ||
		strings.Join(dry.Changes[0].Changed, ",") != "issuer" || dry.Changes[0].NeedsApproval {
		t.Fatalf("dry run %+v %v", dry, err)
	}
	if got := e.deployment(d.ID); got.IssuerID != fake {
		t.Fatal("dry run changed the deployment")
	}
	if _, err := e.svc.ApplyTemplate(ctx, e.owner, webTemplate("fake2", `"*.wf.test"`), false); err != nil {
		t.Fatal(err)
	}
	got := e.deployment(d.ID)
	if got.IssuerID == fake || got.Approval != store.ApprovalApproved {
		t.Fatalf("after apply: %+v", got)
	}
	if r := e.renewOnce(d.ID); r.State != store.RunVerified {
		t.Fatalf("renewal after template change: %s %q", r.State, r.Error)
	}

	// Narrowing the names would break the deployment: plan shows it, apply refuses.
	narrow := webTemplate("fake2", `"api-*.wf.test"`)
	if p, err := e.svc.ApplyTemplate(ctx, e.owner, narrow, true); err != nil || len(p.Violations) != 1 {
		t.Fatalf("plan %+v %v", p, err)
	}
	if _, err := e.svc.ApplyTemplate(ctx, e.owner, narrow, false); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("breaking apply: %v", err)
	}
	if tpl, _ := e.svc.GetTemplate(ctx, e.owner, "web"); tpl.Version != 2 || tpl.Deployments != 1 {
		t.Fatalf("template %+v", tpl)
	}

	// With approvals required, an issuer admin's change waits for someone else.
	if _, err := e.svc.ApplyPolicy(ctx, e.owner, []byte(templatesAndApprovalsRequired), false); err != nil {
		t.Fatal(err)
	}
	admin := e.principal("user:pki", "issuer_admin")
	p, err := e.svc.ApplyTemplate(ctx, admin, webTemplate("fake", `"*.wf.test"`), false)
	if err != nil || len(p.Changes) != 1 || !p.Changes[0].NeedsApproval {
		t.Fatalf("admin apply %+v %v", p, err)
	}
	if got := e.deployment(d.ID); got.Approval != "pending" || got.IssuerID != fake {
		t.Fatalf("after admin apply: %+v", got)
	}
	if _, err := e.svc.RequestRenewal(ctx, e.owner, d.ID); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("renewal of an unapproved spec: %v", err)
	}
	reqs, _ := e.svc.ListApprovals(ctx, e.owner, store.ApprovalRequested)
	if len(reqs) != 1 || reqs[0].ResourceID != d.ID {
		t.Fatalf("approval requests %+v", reqs)
	}

	if err := e.svc.DeleteTemplate(ctx, e.owner, "web"); !errors.Is(err, store.ErrConflict) {
		t.Fatalf("delete of a used template: %v", err)
	}
}

func (e *env) deployment(id string) *store.Deployment {
	e.t.Helper()
	var d *store.Deployment
	if err := e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) (err error) { d, err = tx.GetDeployment(ctx, id, false); return err }); err != nil {
		e.t.Fatal(err)
	}
	return d
}
