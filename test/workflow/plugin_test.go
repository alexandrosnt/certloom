package workflow

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

// pluginEnv adds a plugin target "lb" whose plugin is pinned by path, so the
// heartbeat reports it without anything installed on the test host.
func pluginEnv(t *testing.T) (*env, string) {
	path := filepath.Join(t.TempDir(), "certloom-plugin-f5")
	e := newEnvWith(t, testpki.Options{}, func(c *agent.Config) {
		c.Targets = append(c.Targets, agent.TargetConfig{Name: "lb", Type: agentproto.TargetPlugin, Plugin: path,
			SHA256: strings.Repeat("ab", 32), AllowedSANs: []string{"lb.wf.test"}})
	})
	return e, path
}

func (e *env) spec(depID string) store.DeploymentSpec {
	e.t.Helper()
	var spec store.DeploymentSpec
	err := e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		d, err := tx.GetDeployment(ctx, depID, false)
		if err != nil {
			return err
		}
		iss, err := tx.GetIssuer(ctx, d.IssuerID)
		if err != nil {
			return err
		}
		a, err := tx.GetAgent(ctx, d.AgentID)
		if err != nil {
			return err
		}
		spec = store.BuildDeploymentSpec(d, iss, a)
		return nil
	})
	if err != nil {
		e.t.Fatal(err)
	}
	return spec
}

func TestPluginTargetDeployment(t *testing.T) {
	e, path := pluginEnv(t)
	var agentID string
	_ = e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		a, err := tx.GetAgent(ctx, "web-01")
		agentID = a.ID
		if err == nil && !a.Capabilities.HasPlugin(path, agentproto.PluginKindDeployTarget) {
			t.Errorf("heartbeat plugins: %+v", a.Capabilities.Plugins)
		}
		return err
	})

	in := app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "lb", Issuer: "fake", SANs: []string{"lb.wf.test"}}
	d, err := e.svc.CreateDeployment(ctx, e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	spec := e.spec(d.ID)
	if spec.Target.Type != agentproto.TargetPlugin || spec.Target.Attributes["plugin"] != path {
		t.Fatalf("spec target: %+v", spec.Target)
	}

	// Pointing the target at another plugin changes what was approved.
	before := spec.SHA256()
	e.heartbeatAs(agentID, func(hb *agentproto.Heartbeat) {
		for i := range hb.Targets {
			if hb.Targets[i].Name == "lb" {
				hb.Targets[i].Plugin = "other-plugin"
			}
		}
	})
	if e.spec(d.ID).SHA256() == before {
		t.Fatal("plugin change did not change the spec digest")
	}

	// A host that stops reporting the plugin cannot get new deployments for it.
	e.heartbeatAs(agentID, func(hb *agentproto.Heartbeat) { hb.Plugins = nil })
	in.Lineage = "lb2"
	if _, err := e.svc.CreateLineage(ctx, e.owner, "lb2", "", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.CreateDeployment(ctx, e.owner, in); err == nil || !strings.Contains(err.Error(), "does not report as installed") {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyTaskCarriesRunID(t *testing.T) {
	e := newEnv(t)
	var got agentproto.VerifyPayload
	e.agent.SetHandler(agentproto.TaskVerify, func(c context.Context, task *agentproto.Task) (any, error) {
		_ = json.Unmarshal(task.Payload, &got)
		return e.fakeVerify(c, task)
	})
	run := e.renewOnce(e.dep.ID)
	if got.RunID != run.ID {
		t.Fatalf("verify payload run id %q, run %q", got.RunID, run.ID)
	}
}

func TestPluginInventoryImport(t *testing.T) {
	e, _ := pluginEnv(t)
	c := testpki.Issue(t, e.ca, testpki.Options{CommonName: "vip.wf.test", DNSNames: []string{"vip.wf.test"}})
	e.report(agentproto.InventoryOutput{Plugins: []agentproto.PluginInventory{
		{Source: "lb", Kind: agentproto.PluginKindDeployTarget, Plugin: "corp-f5",
			Items: []agentproto.PluginItem{{PEM: string(c.PEM()), Location: "/Common/vip-443", UsedBy: []string{"vs-443"}}}},
		{Source: "keystores", Kind: "discovery", Plugin: "jks", Error: "permission denied"},
	}})
	var source string
	if err := e.db.Owner.QueryRow(ctx, `SELECT source FROM certificates WHERE sha256 = $1`, sha(c)).Scan(&source); err != nil || source != "plugin" {
		t.Fatalf("certificate source %q: %v", source, err)
	}
	var raw []byte
	_ = e.db.WithOrg(ctx, e.owner.OrgID, func(tx *store.Tx) error {
		a, err := tx.GetAgent(ctx, "web-01")
		if err != nil {
			return err
		}
		raw, _, err = tx.AgentInventory(ctx, a.ID)
		return err
	})
	s := string(raw)
	if strings.Contains(s, "BEGIN CERTIFICATE") || !strings.Contains(s, "/Common/vip-443") || !strings.Contains(s, "permission denied") {
		t.Fatalf("stored inventory: %s", s)
	}
}
