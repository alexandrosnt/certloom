package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

func testAgent(t *testing.T, allowed ...string) (*Agent, ed25519.PrivateKey, *[]string) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	st, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ran := &[]string{}
	a := &Agent{cfg: &Config{StateDir: dir, AllowedTasks: allowed, Targets: []TargetConfig{{Name: "www"}}},
		log: slog.New(slog.NewTextHandler(io.Discard, nil)), state: st,
		id: identity{AgentID: "agt_1", OrgID: "org_1", TaskPublicKey: pub}}
	rec := func(name string) func(context.Context, *agentproto.Task) (any, error) {
		return func(context.Context, *agentproto.Task) (any, error) {
			*ran = append(*ran, name)
			return map[string]string{}, nil
		}
	}
	a.handlers = map[string]func(context.Context, *agentproto.Task) (any, error){}
	for _, tt := range agentproto.AllTaskTypes {
		a.handlers[tt] = rec(tt)
	}
	return a, priv, ran
}

func task(id, typ string, seq int64) agentproto.Task {
	return agentproto.Task{ID: id, OrgID: "org_1", AgentID: "agt_1", Type: typ, Target: "www", Seq: seq,
		NotAfter: time.Now().Add(time.Hour), Nonce: "n-" + id, Payload: json.RawMessage(`{}`)}
}

func result(t *testing.T, a *Agent, id string) *agentproto.Result {
	t.Helper()
	r, err := a.state.Result(id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestTaskVerification(t *testing.T) {
	a, key, ran := testAgent(t)
	ctx := context.Background()
	sign := func(tk agentproto.Task, k ed25519.PrivateKey) agentproto.Envelope {
		env, _ := agentproto.Sign(k, tk)
		return env
	}
	_, otherKey, _ := ed25519.GenerateKey(rand.Reader)

	// Forged signature: never executed, no result recorded.
	a.Execute(ctx, sign(task("t1", agentproto.TaskDeploy, 1), otherKey))
	// Tampered payload after signing.
	env := sign(task("t2", agentproto.TaskDeploy, 1), key)
	env.Task = []byte(string(env.Task[:len(env.Task)-2]) + ` }`)
	a.Execute(ctx, env)
	// Addressed to another agent.
	other := task("t3", agentproto.TaskDeploy, 1)
	other.AgentID = "agt_2"
	a.Execute(ctx, sign(other, key))
	if len(*ran) != 0 || result(t, a, "t1") != nil || result(t, a, "t3") != nil {
		t.Fatalf("unauthentic or misaddressed tasks must not run: ran=%v", *ran)
	}
	// Expired but authentic: not run, failure reported so the control plane stops waiting.
	exp := task("t4", agentproto.TaskDeploy, 1)
	exp.NotAfter = time.Now().Add(-time.Minute)
	a.Execute(ctx, sign(exp, key))
	if r := result(t, a, "t4"); r == nil || r.OK || len(*ran) != 0 {
		t.Fatalf("expired: %+v ran=%v", r, *ran)
	}
	// Valid task runs once; redelivery is deduplicated.
	good := sign(task("t5", agentproto.TaskDeploy, 5), key)
	a.Execute(ctx, good)
	a.Execute(ctx, good)
	if len(*ran) != 1 || !result(t, a, "t5").OK {
		t.Fatalf("valid task: ran=%v", *ran)
	}
	// Stale sequence for the same target is refused, and does not lower the fence.
	a.Execute(ctx, sign(task("t6", agentproto.TaskRollback, 4), key))
	if r := result(t, a, "t6"); r == nil || r.OK || len(*ran) != 1 {
		t.Fatalf("stale seq: %+v ran=%v", r, *ran)
	}
	a.Execute(ctx, sign(task("t7", agentproto.TaskRollback, 4), key))
	if r := result(t, a, "t7"); r == nil || r.OK {
		t.Fatal("fence was lowered by recording a rejected task")
	}
	// Same nonce, different id (replay of a captured envelope with new id is impossible
	// without the key, but a duplicate nonce is still refused).
	dup := task("t8", agentproto.TaskDeploy, 9)
	dup.Nonce = "n-t5"
	a.Execute(ctx, sign(dup, key))
	if r := result(t, a, "t8"); r == nil || r.OK {
		t.Fatal("reused nonce accepted")
	}
}

func TestLocalAllowlist(t *testing.T) {
	a, key, ran := testAgent(t, agentproto.TaskInventoryScan, agentproto.TaskVerify)
	env, _ := agentproto.Sign(key, task("d1", agentproto.TaskDeploy, 1))
	a.Execute(context.Background(), env)
	if r := result(t, a, "d1"); r == nil || r.OK || len(*ran) != 0 {
		t.Fatalf("deploy should be refused by local allowlist: %+v", r)
	}
}

func TestSANAllowlist(t *testing.T) {
	for _, c := range []struct {
		san  string
		want bool
	}{{"www.example.com", true}, {"a.example.com", true}, {"a.b.example.com", false}, {"example.com", false}, {"*.example.com", false}, {"evil.com", false}} {
		if got := sanAllowed(c.san, []string{"www.example.com", "*.example.com"}); got != c.want {
			t.Errorf("%s: got %v", c.san, got)
		}
	}
}

func TestCertbotDiscoveryIsReadOnly(t *testing.T) {
	a, _, _ := testAgent(t)
	cb := t.TempDir()
	h := testpki.NewHierarchy(t, "cb.example.test")
	live := filepath.Join(cb, "live", "cb")
	_ = os.MkdirAll(live, 0o755)
	_ = os.MkdirAll(filepath.Join(cb, "renewal"), 0o755)
	_ = os.WriteFile(filepath.Join(live, "cert.pem"), h.Leaf.PEM(), 0o644)
	_ = os.WriteFile(filepath.Join(live, "privkey.pem"), h.Leaf.KeyPEM(t), 0o600)
	conf := "version = 4.2.0\ncert = " + filepath.Join(live, "cert.pem") + "\n[renewalparams]\nauthenticator = webroot\nserver = https://acme-v02.api.letsencrypt.org/directory\n"
	_ = os.WriteFile(filepath.Join(cb, "renewal", "cb.conf"), []byte(conf), 0o644)
	before := snapshot(t, cb)
	a.cfg.CertbotDir = cb
	a.cfg.DiscoveryPaths = []string{filepath.Join(live, "*.pem")}
	out, err := a.handleInventory(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	inv := out.(agentproto.InventoryOutput)
	if len(inv.Certbot) != 1 || !inv.Certbot[0].ARIAware || inv.Certbot[0].Authenticator != "webroot" {
		t.Fatalf("certbot: %+v", inv.Certbot)
	}
	for _, c := range inv.Certificates {
		if contains(c.ChainPEM, "PRIVATE KEY") {
			t.Fatal("inventory must never include private keys")
		}
	}
	if snapshot(t, cb) != before {
		t.Fatal("certbot directory was modified")
	}
}

func snapshot(t *testing.T, dir string) string {
	var s string
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, _ error) error {
		if fi != nil {
			s += p + fi.ModTime().String() + "\n"
		}
		return nil
	})
	return s
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || (len(sub) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// ---- real deploy / rollback on symlinks (POSIX) ----

func TestDeployAndRollbackOnSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink-based activation targets Linux; covered by e2e in a Linux container")
	}
	a, _, _ := testAgent(t)
	dir := a.cfg.StateDir
	marker := filepath.Join(dir, "reloads")
	failTest := filepath.Join(dir, "fail-test")
	a.cfg.Targets = []TargetConfig{{Name: "www", Type: "nginx", LiveLink: filepath.Join(dir, "live", "www"),
		TestCommand:   []string{"sh", "-c", "test ! -e " + failTest},
		ReloadCommand: []string{"sh", "-c", "echo r >> " + marker},
		AllowedSANs:   []string{"www.example.test"}, VerifyAddress: "127.0.0.1:1"}}
	ca := testpki.Issue(t, nil, testpki.Options{CommonName: "ca", IsCA: true})
	deploy := func(run string, wantErr bool) agentproto.DeployOutput {
		t.Helper()
		key, err := loadOrCreateKey(filepath.Join(a.runDir("www", run), "privkey.pem"))
		if err != nil {
			t.Fatal(err)
		}
		leaf := testpki.IssueWithKey(t, ca, key, testpki.Options{CommonName: "www.example.test", DNSNames: []string{"www.example.test"}})
		pl, _ := json.Marshal(agentproto.DeployPayload{RunID: run, ChainPEM: string(leaf.PEM())})
		out, err := a.handleDeploy(context.Background(), &agentproto.Task{Target: "www", Payload: pl})
		if (err != nil) != wantErr {
			t.Fatalf("deploy %s: err=%v", run, err)
		}
		return out.(agentproto.DeployOutput)
	}
	live := a.cfg.Targets[0].LiveLink
	deploy("run1", false)
	if d, _ := os.Readlink(live); filepath.Base(d) != "run1" {
		t.Fatalf("live -> %s", d)
	}
	deploy("run2", false)
	// Rollback of run2 restores run1.
	pl, _ := json.Marshal(agentproto.RollbackPayload{RunID: "run2"})
	if _, err := a.handleRollback(context.Background(), &agentproto.Task{Target: "www", Payload: pl}); err != nil {
		t.Fatal(err)
	}
	if d, _ := os.Readlink(live); filepath.Base(d) != "run1" {
		t.Fatalf("after rollback live -> %s", d)
	}
	// A failing config test restores the previous link automatically.
	_ = os.WriteFile(failTest, nil, 0o644)
	out := deploy("run3", true)
	if !out.RolledBack {
		t.Fatal("expected RolledBack")
	}
	if d, _ := os.Readlink(live); filepath.Base(d) != "run1" {
		t.Fatalf("after failed test live -> %s", d)
	}
	// Re-executing a deploy (crash mid-task) keeps the original rollback target.
	_ = os.Remove(failTest)
	deploy("run4", false)
	deploy("run4", false)
	pl, _ = json.Marshal(agentproto.RollbackPayload{RunID: "run4"})
	if _, err := a.handleRollback(context.Background(), &agentproto.Task{Target: "www", Payload: pl}); err != nil {
		t.Fatal(err)
	}
	if d, _ := os.Readlink(live); filepath.Base(d) != "run1" {
		t.Fatalf("re-executed deploy lost rollback target: live -> %s", d)
	}
	// A deploy whose certificate does not match the run's key is refused before switching.
	key5, _ := loadOrCreateKey(filepath.Join(a.runDir("www", "run5"), "privkey.pem"))
	_ = key5
	wrong := testpki.Issue(t, ca, testpki.Options{CommonName: "www.example.test", DNSNames: []string{"www.example.test"}})
	pl, _ = json.Marshal(agentproto.DeployPayload{RunID: "run5", ChainPEM: string(wrong.PEM())})
	if _, err := a.handleDeploy(context.Background(), &agentproto.Task{Target: "www", Payload: pl}); err == nil {
		t.Fatal("mismatched key accepted")
	}
	if d, _ := os.Readlink(live); filepath.Base(d) != "run1" {
		t.Fatalf("mismatched deploy changed live link -> %s", d)
	}
	// The live path must be a symlink we own.
	_ = os.Remove(live)
	_ = os.MkdirAll(live, 0o755)
	if err := switchLink(live, a.runDir("www", "run1")); err == nil {
		t.Fatal("must refuse to replace a real directory")
	}
}
