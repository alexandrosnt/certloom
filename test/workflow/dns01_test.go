package workflow

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

func withDNSSolver(c *agent.Config) {
	wild := c.Targets[0]
	wild.Name, wild.LiveLink, wild.Webroot = "wild", filepath.Join(c.StateDir, "live", "wild"), ""
	c.Targets = append(c.Targets, wild)
	c.DNSSolvers = []agent.DNSSolverConfig{{Name: "internal", Provider: agent.ProviderRFC2136, Nameserver: "127.0.0.1:53",
		TSIGFile: filepath.Join(c.StateDir, "tsig.key"), Zones: []string{"wf.test"}}}
}

func TestDNS01NeedsSolversAndWildcardsNeedDNS01(t *testing.T) {
	e := newEnv(t)
	in := app.DeploymentInput{Lineage: "www", Agent: "web-01", Target: "www", Issuer: "fake", SANs: []string{"www.wf.test"},
		Challenge: agentproto.ChallengeDNS01}
	if _, err := e.svc.CreateDeployment(ctx, e.owner, in); !errors.Is(err, app.ErrInvalid) || !strings.Contains(err.Error(), "no dns solver") {
		t.Fatalf("dns-01 without solvers: %v", err)
	}
	in.Challenge, in.SANs = "", []string{"*.wf.test"}
	if _, err := e.svc.CreateDeployment(ctx, e.owner, in); !errors.Is(err, app.ErrInvalid) || !strings.Contains(err.Error(), "needs challenge dns-01") {
		t.Fatalf("wildcard over http-01: %v", err)
	}
	in.Challenge = "tls-alpn-01"
	if _, err := e.svc.CreateDeployment(ctx, e.owner, in); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("unknown challenge: %v", err)
	}
}

func TestDNS01WildcardRenewal(t *testing.T) {
	e := newEnvWith(t, testpki.Options{}, withDNSSolver)
	var got agentproto.IssuePayload
	e.agent.SetHandler(agentproto.TaskIssue, func(c context.Context, task *agentproto.Task) (any, error) {
		_ = json.Unmarshal(task.Payload, &got)
		return e.fakeIssue(c, task)
	})
	if _, err := e.svc.CreateLineage(ctx, e.owner, "wild", "", ""); err != nil {
		t.Fatal(err)
	}
	// The wild target has no webroot: dns-01 does not need one.
	in := app.DeploymentInput{Lineage: "wild", Agent: "web-01", Target: "wild", Issuer: "fake", SANs: []string{"*.wf.test", "www.wf.test"},
		Challenge: agentproto.ChallengeDNS01}
	// A plain name in allowed_sans never permits its wildcard.
	in.SANs = []string{"*.www.wf.test"}
	if _, err := e.svc.CreateDeployment(ctx, e.owner, in); !errors.Is(err, app.ErrInvalid) {
		t.Fatalf("unlisted wildcard: %v", err)
	}
	in.SANs = []string{"*.wf.test", "www.wf.test"}
	d, err := e.svc.CreateDeployment(ctx, e.owner, in)
	if err != nil {
		t.Fatal(err)
	}
	if d.Challenge != agentproto.ChallengeDNS01 {
		t.Fatalf("challenge not stored: %+v", d)
	}
	run, err := e.svc.RequestRenewal(ctx, e.owner, d.ID)
	if err != nil {
		t.Fatal(err)
	}
	if r := e.pump(run.ID); r.State != store.RunVerified {
		t.Fatalf("state %s err %q steps %s", r.State, r.Error, steps(r))
	}
	if got.Challenge != agentproto.ChallengeDNS01 || got.SANs[0] != "*.wf.test" {
		t.Fatalf("issue task: %+v", got)
	}
}

// Adding the challenge to the spec must not void approvals of existing
// HTTP-01 deployments: their spec still encodes as version 1.
func TestSpecDigestKeepsHTTP01Encoding(t *testing.T) {
	e := newEnvWith(t, testpki.Options{}, withDNSSolver)
	iss := &store.Issuer{ID: "iss", Kind: "acme", DirectoryURL: "https://acme.invalid/dir"}
	a := &store.Agent{ID: "agt"}
	d := &store.Deployment{LineageID: "lin", Target: "www", SANs: []string{"www.wf.test"}, KeyAlgorithm: agentproto.KeyECDSAP256,
		Challenge: agentproto.ChallengeHTTP01}
	v1, _ := json.Marshal(store.BuildDeploymentSpec(d, iss, a))
	if !strings.HasPrefix(string(v1), `{"v":1,`) || strings.Contains(string(v1), "challenge") {
		t.Fatalf("http-01 spec changed encoding: %s", v1)
	}
	d.Challenge = agentproto.ChallengeDNS01
	v2 := store.BuildDeploymentSpec(d, iss, a)
	if v2.V != store.SpecVersion || v2.Challenge != agentproto.ChallengeDNS01 {
		t.Fatalf("dns-01 spec: %+v", v2)
	}
	d.Challenge = agentproto.ChallengeHTTP01
	if store.BuildDeploymentSpec(d, iss, a).SHA256() == v2.SHA256() {
		t.Fatal("switching the challenge must change the digest")
	}
	// The deployment created before this change is still approved as is.
	if e.dep.ApprovedSpecSHA256 == nil || e.dep.Challenge != agentproto.ChallengeHTTP01 {
		t.Fatalf("existing deployment: %+v", e.dep)
	}
}
