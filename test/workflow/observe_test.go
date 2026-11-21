package workflow

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

type openFinding struct {
	subjectType, subjectID, check, severity string
	resolved                                bool
}

func findings(t *testing.T, e *env) []openFinding {
	t.Helper()
	rows, err := e.db.Owner.Query(ctx, `SELECT subject_type, subject_id, check_id, severity, resolved_at IS NOT NULL
		FROM findings WHERE subject_type IN ('deployment','k8s_object') ORDER BY subject_id, check_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []openFinding
	for rows.Next() {
		var f openFinding
		if err := rows.Scan(&f.subjectType, &f.subjectID, &f.check, &f.severity, &f.resolved); err != nil {
			t.Fatal(err)
		}
		out = append(out, f)
	}
	return out
}

func openOf(fs []openFinding, check string) []openFinding {
	var out []openFinding
	for _, f := range fs {
		if f.check == check && !f.resolved {
			out = append(out, f)
		}
	}
	return out
}

// report makes the agent answer the next inventory task with inv.
func (e *env) report(inv agentproto.InventoryOutput) {
	e.t.Helper()
	e.agent.SetHandler(agentproto.TaskInventoryScan, func(context.Context, *agentproto.Task) (any, error) { return inv, nil })
	if _, err := e.svc.RequestInventoryScan(ctx, e.owner, "web-01"); err != nil {
		e.t.Fatal(err)
	}
	if _, err := e.agent.PollOnce(ctx, 0); err != nil {
		e.t.Fatal(err)
	}
}

func iisEnv(t *testing.T) *env {
	return newEnvWith(t, testpki.Options{}, func(c *agent.Config) {
		c.Targets = []agent.TargetConfig{{Name: "www", Type: "iis", Site: "Shop", Bindings: []string{"*:443:www.wf.test", "10.0.0.5:443:"},
			AllowedSANs: []string{"www.wf.test"}}}
	})
}

func TestIISBindingDrift(t *testing.T) {
	e := iisEnv(t)
	var current string
	_ = e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		l, err := tx.LineageByRef(ctx, "www")
		current = *l.CurrentSHA256
		return err
	})
	bindings := func(sha string) []agentproto.IISBinding {
		return []agentproto.IISBinding{
			{Site: "shop", Binding: "*:443:www.wf.test", SSLFlags: 1, CertHash: "AA", CertStore: "WebHosting", CertSHA256: current},
			{Site: "Shop", Binding: "10.0.0.5:443:", CertHash: "BB", CertStore: "WebHosting", CertSHA256: sha},
			{Site: "Other", Binding: "*:443:other.test", CertHash: "CC", CertSHA256: "ff"},
		}
	}

	e.report(agentproto.InventoryOutput{IIS: bindings(current)})
	if fs := openOf(findings(t, e), "iis_binding_drift"); len(fs) != 0 {
		t.Fatalf("bindings match, want no drift: %+v", fs)
	}

	e.report(agentproto.InventoryOutput{IIS: bindings(strings.Repeat("ab", 32))})
	fs := openOf(findings(t, e), "iis_binding_drift")
	if len(fs) != 1 || fs[0].subjectID != e.dep.ID || fs[0].severity != "warning" {
		t.Fatalf("want a warning drift finding on the deployment, got %+v", fs)
	}

	// The entry disappears from HTTP.sys: escalates.
	b := bindings(current)
	b[1].CertHash, b[1].CertSHA256 = "", ""
	e.report(agentproto.InventoryOutput{IIS: b})
	if fs := openOf(findings(t, e), "iis_binding_drift"); len(fs) != 1 || fs[0].severity != "critical" {
		t.Fatalf("want critical drift, got %+v", fs)
	}

	e.report(agentproto.InventoryOutput{IIS: bindings(current)})
	if fs := openOf(findings(t, e), "iis_binding_drift"); len(fs) != 0 {
		t.Fatalf("drift should resolve: %+v", fs)
	}

	// The observations are kept for the API; certificate PEMs are not.
	inv, err := e.svc.AgentInventory(ctx, e.owner, "web-01")
	if err != nil || inv["reported_at"] == nil || !strings.Contains(string(inv["inventory"].(json.RawMessage)), "10.0.0.5:443:") {
		t.Fatalf("stored inventory: %v %v", inv, err)
	}
}

func TestIISSpecCoversSiteAndBindings(t *testing.T) {
	e := iisEnv(t)
	_ = e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		a, err := tx.GetAgent(ctx, "web-01")
		if err != nil {
			t.Fatal(err)
		}
		iss, err := tx.GetIssuer(ctx, "fake")
		if err != nil {
			t.Fatal(err)
		}
		spec := store.BuildDeploymentSpec(e.dep, iss, a)
		if spec.Target.Type != "iis" || spec.Target.Attributes["site"] != "shop" || spec.Target.Attributes["bindings"] != "*:443:www.wf.test,10.0.0.5:443:" {
			t.Fatalf("spec target %+v", spec.Target)
		}
		before := spec.SHA256()
		a.Capabilities.Targets[0].Bindings = append(a.Capabilities.Targets[0].Bindings, "*:8443:www.wf.test")
		if store.BuildDeploymentSpec(e.dep, iss, a).SHA256() == before {
			t.Fatal("adding a binding must change the approved spec")
		}
		return nil
	})
}

func TestPeriodicInventoryIsQueued(t *testing.T) {
	e := iisEnv(t)
	count := func() int {
		var n int
		if err := e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM agent_tasks WHERE type = 'inventory.scan'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if err := e.svc.RequestDueInventories(ctx); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatalf("IIS agent asked for periodic inventory; tasks=%d", count())
	}
	if err := e.svc.RequestDueInventories(ctx); err != nil {
		t.Fatal(err)
	}
	if count() != 1 {
		t.Fatal("a second task was queued within the interval")
	}
}

func TestKubernetesObservation(t *testing.T) {
	e := newEnv(t)
	leaf := testpki.Issue(t, e.ca, testpki.Options{CommonName: "shop.k8s.test", DNSNames: []string{"shop.k8s.test"}})
	old := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	ready := func(status string) []agentproto.KubeCondition {
		return []agentproto.KubeCondition{{Type: "Ready", Status: status, Reason: "x", LastTransitionTime: old}}
	}
	inv := agentproto.KubeInventory{Cluster: "prod",
		Certificates: []agentproto.KubeCert{
			{Namespace: "web", Name: "shop", IssuerKind: "ClusterIssuer", IssuerName: "le", Conditions: ready("True"), ChainPEM: string(leaf.PEM())},
			{Namespace: "web", Name: "blog", IssuerKind: "Issuer", IssuerName: "local", Conditions: ready("False"),
				RequestName: "blog-2", RequestFailed: "Denied: PolicyDenied"},
		},
		Issuers: []agentproto.KubeIssuer{
			{Name: "le", Type: "acme", Conditions: ready("False")},
			{Namespace: "web", Name: "local", Type: "selfSigned", Conditions: ready("True")},
			{Name: "unused", Type: "ca", Conditions: ready("False")},
		},
		Bundles: []agentproto.KubeBundle{{Name: "trust", Target: "configMap", Conditions: []agentproto.KubeCondition{{Type: "Synced", Status: "False"}}}},
	}
	e.report(agentproto.InventoryOutput{Kubernetes: &inv})
	fs := findings(t, e)
	want := map[string]int{"k8s_certificate_not_ready": 1, "k8s_request_failed": 1, "k8s_issuer_not_ready": 1, "k8s_bundle_not_synced": 1}
	for check, n := range want {
		if got := openOf(fs, check); len(got) != n {
			t.Fatalf("%s: got %+v", check, got)
		}
	}
	if is := openOf(fs, "k8s_issuer_not_ready")[0]; !strings.HasSuffix(is.subjectID, "/ClusterIssuer//le") {
		t.Fatalf("issuer finding subject %s (an unused issuer must not be reported)", is.subjectID)
	}
	var imported int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE source = 'kubernetes'`).Scan(&imported)
	if imported != 1 {
		t.Fatalf("certificate from CertificateRequest status not imported: %d", imported)
	}

	// blog is deleted; bundles could not be listed this time.
	inv.Certificates = inv.Certificates[:1]
	inv.Bundles, inv.Errors = nil, []string{"bundles: not available (HTTP 404)"}
	e.report(agentproto.InventoryOutput{Kubernetes: &inv})
	fs = findings(t, e)
	if len(openOf(fs, "k8s_certificate_not_ready")) != 0 || len(openOf(fs, "k8s_request_failed")) != 0 {
		t.Fatalf("findings of a deleted Certificate must resolve: %+v", fs)
	}
	if len(openOf(fs, "k8s_bundle_not_synced")) != 1 {
		t.Fatal("a bundle that was not listed is not known to be gone; keep its finding")
	}
}
