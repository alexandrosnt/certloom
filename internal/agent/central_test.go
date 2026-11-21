package agent

import (
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

func sealFor(t *testing.T, a *Agent, taskID, solverID, secret string) []byte {
	t.Helper()
	b, err := agentproto.SealSecret(a.sealPub, agentproto.SealInfo(a.id.AgentID, taskID, solverID), []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestCentralSolverSecretOpensOnlyForItsTask(t *testing.T) {
	a, _, _ := testAgent(t)
	if err := a.loadSealKey(); err != nil {
		t.Fatal(err)
	}
	tk := &agentproto.Task{ID: "tsk_1"}
	c := agentproto.CentralDNSSolver{ID: "dns_1", Name: "cf", Provider: ProviderCloudflare, Zones: []string{"example.test"},
		Sealed: sealFor(t, a, "tsk_1", "dns_1", `{"api_token":"tok"}`)}
	got, err := a.dnsSolversFor(tk, agentproto.IssuePayload{DNSSolvers: []agentproto.CentralDNSSolver{c}})
	if err != nil || len(got) != 1 || got[0].secret["api_token"] != "tok" || !got[0].central {
		t.Fatalf("%+v %v", got, err)
	}
	// Replayed into another task, or sealed for another solver id: refused.
	if _, err := a.dnsSolversFor(&agentproto.Task{ID: "tsk_2"}, agentproto.IssuePayload{DNSSolvers: []agentproto.CentralDNSSolver{c}}); err == nil {
		t.Fatal("secret opened for another task")
	}
	c.ID = "dns_2"
	if _, err := a.dnsSolversFor(tk, agentproto.IssuePayload{DNSSolvers: []agentproto.CentralDNSSolver{c}}); err == nil {
		t.Fatal("secret opened as another solver")
	}
}

func TestCentralSolverRulesAndOptOut(t *testing.T) {
	a, _, _ := testAgent(t)
	if err := a.loadSealKey(); err != nil {
		t.Fatal(err)
	}
	tk := &agentproto.Task{ID: "tsk_1"}
	a.cfg.DNSSolvers = []DNSSolverConfig{{Name: "local", Provider: ProviderRFC2136, Zones: []string{"example.test"}}}
	central := agentproto.CentralDNSSolver{ID: "dns_1", Name: "central", Provider: ProviderCloudflare, Zones: []string{"example.test"},
		Sealed: sealFor(t, a, "tsk_1", "dns_1", `{"api_token":"tok"}`)}
	got, err := a.dnsSolversFor(tk, agentproto.IssuePayload{DNSSolvers: []agentproto.CentralDNSSolver{central}})
	if err != nil || len(got) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	// Same zone: the host's own solver comes first and wins the tie.
	m := &dnsMux{log: quietLog}
	for i := range got {
		m.solvers = append(m.solvers, &dnsSolver{cfg: &got[i], zones: []string{"example.test."}})
	}
	if s, _, _ := m.pick("_acme-challenge.www.example.test."); s.cfg.Name != "local" {
		t.Fatalf("picked %s", s.cfg.Name)
	}

	for _, bad := range []agentproto.CentralDNSSolver{
		{ID: "x", Name: "amb", Provider: ProviderCloudflare, Ambient: true},
		{ID: "x", Name: "rel", Provider: "plugin", Plugin: "relative", SHA256: strings.Repeat("a", 64), Ambient: true},
		{ID: "x", Name: "nosecret", Provider: ProviderCloudflare},
		{ID: "x", Name: "odd", Provider: "route53"},
	} {
		if _, err := a.centralSolver(tk, bad); err == nil {
			t.Errorf("%s accepted", bad.Name)
		}
	}

	off := false
	a.cfg.CentralDNSSolvers = &off
	got, err = a.dnsSolversFor(tk, agentproto.IssuePayload{DNSSolvers: []agentproto.CentralDNSSolver{central}})
	if err != nil || len(got) != 1 || got[0].Name != "local" {
		t.Fatalf("opt-out: %+v %v", got, err)
	}
}

func TestSealKeyRotationKeepsPrevious(t *testing.T) {
	a, _, _ := testAgent(t)
	if err := a.loadSealKey(); err != nil {
		t.Fatal(err)
	}
	old := sealFor(t, a, "tsk_1", "dns_1", `{"k":"v"}`)
	if err := a.rotateSealKey(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.openSecret(agentproto.SealInfo("agt_1", "tsk_1", "dns_1"), old); err != nil {
		t.Fatalf("task sealed before rotation: %v", err)
	}
	// A restart loads the same keys.
	b := &Agent{cfg: a.cfg, log: a.log}
	if err := b.loadSealKey(); err != nil || string(b.sealPub) != string(a.sealPub) {
		t.Fatalf("reload: %v", err)
	}
}
