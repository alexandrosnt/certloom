package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/pluginstore"
	"github.com/alexandrosnt/certloom/plugin"
)

// With CERTLOOM_TEST_PLUGIN set, the test binary is a deploy_target plugin
// that keeps its "live" certificate in FAKE_TARGET_DIR.
func TestMain(m *testing.M) {
	if os.Getenv("CERTLOOM_TEST_PLUGIN") != "" {
		s := &plugin.Server{Name: "fake-target", Version: "1.0.0", Deploy: dirTarget(os.Getenv("FAKE_TARGET_DIR"))}
		os.Exit(s.Serve(context.Background(), os.Args[1:], os.Stdin, os.Stdout))
	}
	os.Exit(m.Run())
}

type dirTarget string

func (d dirTarget) path(name string) string { return filepath.Join(string(d), name) }

func (d dirTarget) Deploy(_ context.Context, req plugin.Request) error {
	cert, err := os.ReadFile(req.Files.Certificate)
	if err != nil {
		return err
	}
	if _, err := os.ReadFile(req.Files.Key); err != nil {
		return err
	}
	if old, err := os.ReadFile(d.path("live.pem")); err == nil {
		_ = os.WriteFile(d.path("before-"+req.IdempotencyKey), old, 0o600)
	}
	if err := os.WriteFile(d.path("live.pem"), cert, 0o600); err != nil {
		return err
	}
	if os.Getenv("FAKE_FAIL") == "deploy" {
		return &plugin.Classified{Class: plugin.ClassPermanent, Err: errors.New("appliance refused the certificate")}
	}
	return nil
}

func (d dirTarget) Verify(context.Context, plugin.Request) (string, error) {
	b, err := os.ReadFile(d.path("live.pem"))
	return string(b), err
}

func (d dirTarget) Rollback(_ context.Context, req plugin.Request) error {
	old, err := os.ReadFile(d.path("before-" + req.IdempotencyKey))
	if errors.Is(err, os.ErrNotExist) {
		return nil // nothing was replaced
	}
	if err != nil {
		return err
	}
	return os.WriteFile(d.path("live.pem"), old, 0o600)
}

func (d dirTarget) Inventory(context.Context, plugin.Request) ([]plugin.Item, error) {
	b, err := os.ReadFile(d.path("live.pem"))
	if err != nil {
		return nil, nil
	}
	return []plugin.Item{{Certificate: string(b), Location: "live.pem", UsedBy: []string{"vip-443"}}}, nil
}

func fileSHA256(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// pluginAgent returns an agent with one plugin target running this test
// binary, pinned by path, and the directory the fake target writes to.
func pluginAgent(t *testing.T) (*Agent, *TargetConfig, string) {
	t.Helper()
	dir := t.TempDir()
	st, err := OpenState(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	live := t.TempDir()
	t.Setenv("CERTLOOM_TEST_PLUGIN", "1")
	t.Setenv("FAKE_TARGET_DIR", live)
	tgt := TargetConfig{Name: "lb", Type: agentproto.TargetPlugin, Plugin: exe, SHA256: fileSHA256(t, exe),
		AllowedSANs: []string{"app.example.test"}, Env: []string{"CERTLOOM_TEST_PLUGIN", "FAKE_TARGET_DIR", "FAKE_FAIL"},
		Inventory: true, TimeoutSeconds: 20}
	a := &Agent{cfg: &Config{StateDir: dir, Targets: []TargetConfig{tgt}}, log: slog.New(slog.NewTextHandler(io.Discard, nil)), state: st}
	return a, &a.cfg.Targets[0], live
}

// issueFor creates the run key the issue step would have made and a
// certificate for it.
func issueFor(t *testing.T, a *Agent, tgt *TargetConfig, run string, names ...string) string {
	t.Helper()
	k, err := loadOrCreateKey(filepath.Join(a.runDir(tgt.Name, run), "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	return chainPEM(selfSigned(t, k, names...))
}

func leafSHA256(t *testing.T, chain string) string {
	t.Helper()
	b, _ := pem.Decode([]byte(chain))
	if b == nil {
		t.Fatal("no certificate in chain")
	}
	sum := sha256.Sum256(b.Bytes)
	return hex.EncodeToString(sum[:])
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func runTask(t *testing.T, typ, target string, payload any) *agentproto.Task {
	t.Helper()
	b, _ := json.Marshal(payload)
	return &agentproto.Task{ID: typ + "-1", Type: typ, Target: target, Payload: b, NotAfter: time.Now().Add(time.Hour)}
}

func TestPluginTargetDeployVerifyRollback(t *testing.T) {
	a, tgt, live := pluginAgent(t)
	ctx := context.Background()

	first := issueFor(t, a, tgt, "run-1", "app.example.test")
	if _, err := a.handleDeploy(ctx, runTask(t, agentproto.TaskDeploy, "lb", agentproto.DeployPayload{RunID: "run-1", ChainPEM: first})); err != nil {
		t.Fatal(err)
	}
	second := issueFor(t, a, tgt, "run-2", "app.example.test")
	if _, err := a.handleDeploy(ctx, runTask(t, agentproto.TaskDeploy, "lb", agentproto.DeployPayload{RunID: "run-2", ChainPEM: second})); err != nil {
		t.Fatal(err)
	}
	want := leafSHA256(t, second)
	out, err := a.handleVerify(ctx, runTask(t, agentproto.TaskVerify, "lb", agentproto.VerifyPayload{ExpectedSHA256: want, RunID: "run-2"}))
	if err != nil || !out.(agentproto.VerifyOutput).Match {
		t.Fatalf("verify: %+v %v", out, err)
	}
	if _, err := a.handleRollback(ctx, runTask(t, agentproto.TaskRollback, "lb", agentproto.RollbackPayload{RunID: "run-2"})); err != nil {
		t.Fatal(err)
	}
	if got := leafSHA256(t, readFile(t, filepath.Join(live, "live.pem"))); got != leafSHA256(t, first) {
		t.Fatal("rollback did not restore the first certificate")
	}
	// Key material handed to the plugin is gone after the call.
	if left, _ := filepath.Glob(filepath.Join(a.cfg.StateDir, "plugin-deploy-*")); len(left) != 0 {
		t.Fatalf("temporary files left: %v", left)
	}
}

func TestPluginTargetDeployFailureRollsBack(t *testing.T) {
	a, tgt, live := pluginAgent(t)
	ctx := context.Background()
	first := issueFor(t, a, tgt, "run-1", "app.example.test")
	if _, err := a.handleDeploy(ctx, runTask(t, agentproto.TaskDeploy, "lb", agentproto.DeployPayload{RunID: "run-1", ChainPEM: first})); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_FAIL", "deploy")
	second := issueFor(t, a, tgt, "run-2", "app.example.test")
	out, err := a.handleDeploy(ctx, runTask(t, agentproto.TaskDeploy, "lb", agentproto.DeployPayload{RunID: "run-2", ChainPEM: second}))
	if err == nil || !strings.Contains(err.Error(), "appliance refused") || !out.(agentproto.DeployOutput).RolledBack {
		t.Fatalf("got %+v %v", out, err)
	}
	if got := leafSHA256(t, readFile(t, filepath.Join(live, "live.pem"))); got != leafSHA256(t, first) {
		t.Fatal("failed deploy left the new certificate live")
	}
}

func TestPluginTargetRefusesForeignSANs(t *testing.T) {
	a, tgt, live := pluginAgent(t)
	chain := issueFor(t, a, tgt, "run-1", "app.example.test", "other.example.test")
	_, err := a.handleDeploy(context.Background(), runTask(t, agentproto.TaskDeploy, "lb", agentproto.DeployPayload{RunID: "run-1", ChainPEM: chain}))
	if err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("got %v", err)
	}
	if _, err := os.Stat(filepath.Join(live, "live.pem")); err == nil {
		t.Fatal("plugin was called")
	}
}

func TestPluginTargetInventoryAndHeartbeat(t *testing.T) {
	a, tgt, _ := pluginAgent(t)
	chain := issueFor(t, a, tgt, "run-1", "app.example.test")
	if _, err := a.handleDeploy(context.Background(), runTask(t, agentproto.TaskDeploy, "lb", agentproto.DeployPayload{RunID: "run-1", ChainPEM: chain})); err != nil {
		t.Fatal(err)
	}
	inv := a.inventoryPlugins(context.Background())
	if len(inv) != 1 || inv[0].Error != "" || len(inv[0].Items) != 1 || inv[0].Items[0].UsedBy[0] != "vip-443" || inv[0].Plugin != tgt.Plugin {
		t.Fatalf("inventory: %+v", inv)
	}
	infos := a.cfg.pluginInfos()
	if len(infos) != 1 || !infos[0].Pinned || infos[0].Kinds[0] != plugin.KindDeployTarget {
		t.Fatalf("heartbeat plugins: %+v", infos)
	}
	if a.cfg.inventoryInterval() != 900 {
		t.Fatalf("interval %d", a.cfg.inventoryInterval())
	}
}

// installFake puts this test binary into a plugins dir the way
// certloom-plugin would, with an install record.
func installFake(t *testing.T, dir, name, version, trust string, kinds ...string) string {
	t.Helper()
	exe, _ := os.Executable()
	vdir := pluginstore.VersionDir(dir, name, version)
	if err := os.MkdirAll(filepath.Join(vdir, "bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(vdir, "bin", filepath.Base(exe))
	if err := os.WriteFile(dst, []byte(readFile(t, exe)), 0o755); err != nil {
		t.Fatal(err)
	}
	r := pluginstore.Record{Name: name, Version: version, Kinds: kinds, Executable: dst, ExecutableSHA256: fileSHA256(t, dst),
		ArchiveSHA256: strings.Repeat("a", 64), Trust: trust, Signer: "https://github.com/example/plugin/.github/workflows/release.yml@refs/tags/v" + version}
	b, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(vdir, pluginstore.RecordFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return dst
}

func TestInstalledPluginResolution(t *testing.T) {
	a, tgt, _ := pluginAgent(t)
	plugins := filepath.Join(a.cfg.StateDir, "plugins")
	installFake(t, plugins, "fake-target", "1.0.0", "example", plugin.KindDeployTarget)
	newest := installFake(t, plugins, "fake-target", "1.1.0", "example", plugin.KindDeployTarget)
	installFake(t, plugins, "dns-only", "1.0.0", "example", plugin.KindDNSSolver)
	installFake(t, plugins, "orphan", "1.0.0", "removed-entry", plugin.KindDeployTarget)
	a.cfg.Plugins = &pluginstore.Config{Trust: []pluginstore.Publisher{{Name: "example", PublicKey: filepath.Join(plugins, "k.pub")}}}
	src := a.cfg.pluginSource()

	if path, _, err := src.resolve("fake-target", "", plugin.KindDeployTarget); err != nil || path != newest {
		t.Fatalf("newest: %s %v", path, err)
	}
	if _, _, err := src.resolve("fake-target@1.0.0", "", plugin.KindDeployTarget); err != nil {
		t.Fatalf("pinned version: %v", err)
	}
	for ref, want := range map[string]string{
		"dns-only":          "does not implement deploy_target",
		"orphan":            "not in plugins.trust",
		"missing":           "not installed",
		"fake-target@9.0.0": "not installed",
	} {
		if _, _, err := src.resolve(ref, "", plugin.KindDeployTarget); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v, want %q", ref, err, want)
		}
	}

	// A deploy through the installed plugin works like the pinned one.
	tgt.Plugin, tgt.SHA256 = "fake-target", ""
	chain := issueFor(t, a, tgt, "run-1", "app.example.test")
	if _, err := a.handleDeploy(context.Background(), runTask(t, agentproto.TaskDeploy, "lb", agentproto.DeployPayload{RunID: "run-1", ChainPEM: chain})); err != nil {
		t.Fatal(err)
	}

	// The heartbeat lists trusted installs and leaves the orphan out.
	var names []string
	for _, p := range a.cfg.pluginInfos() {
		names = append(names, p.Name+"@"+p.Version)
	}
	if !slices.Equal(names, []string{"dns-only@1.0.0", "fake-target@1.1.0", "fake-target@1.0.0"}) {
		t.Fatalf("heartbeat: %v", names)
	}

	// A record pointing outside its own directory is refused.
	outside := installFake(t, plugins, "escape", "1.0.0", "example", plugin.KindDeployTarget)
	rec := filepath.Join(pluginstore.VersionDir(plugins, "escape", "1.0.0"), pluginstore.RecordFile)
	var r pluginstore.Record
	_ = json.Unmarshal([]byte(readFile(t, rec)), &r)
	r.Executable = filepath.Join(plugins, "fake-target", "1.1.0", "bin", filepath.Base(outside))
	b, _ := json.Marshal(r)
	_ = os.WriteFile(rec, b, 0o644)
	if _, _, err := src.resolve("escape", "", plugin.KindDeployTarget); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("escape: %v", err)
	}

	// require_signed refuses the pinned form.
	a.cfg.Plugins.RequireSigned = true
	exe, _ := os.Executable()
	if _, _, err := a.cfg.pluginSource().resolve(exe, fileSHA256(t, exe), plugin.KindDeployTarget); err == nil {
		t.Fatal("pinned plugin accepted with require_signed")
	}
}

func TestPluginTargetConfigValidation(t *testing.T) {
	sha := strings.Repeat("ab", 32)
	abs := filepath.Join(t.TempDir(), "plugin")
	base := Config{Server: "https://cp.example", StateDir: t.TempDir()}
	for name, c := range map[string]struct {
		tgt  TargetConfig
		plug *pluginstore.Config
		want string
	}{
		"installed":        {TargetConfig{Name: "lb", Type: "plugin", Plugin: "corp-f5@1.2.0", AllowedSANs: []string{"a.example"}}, nil, ""},
		"pinned":           {TargetConfig{Name: "lb", Type: "plugin", Plugin: abs, SHA256: sha, AllowedSANs: []string{"a.example"}}, nil, ""},
		"no plugin":        {TargetConfig{Name: "lb", Type: "plugin", AllowedSANs: []string{"a.example"}}, nil, "plugin is required"},
		"no sans":          {TargetConfig{Name: "lb", Type: "plugin", Plugin: "corp-f5"}, nil, "allowed_sans"},
		"nginx fields":     {TargetConfig{Name: "lb", Type: "plugin", Plugin: "corp-f5", AllowedSANs: []string{"a"}, ReloadCommand: []string{"x"}}, nil, "not nginx or iis"},
		"pinned no sha":    {TargetConfig{Name: "lb", Type: "plugin", Plugin: abs, AllowedSANs: []string{"a"}}, nil, "sha256"},
		"require signed":   {TargetConfig{Name: "lb", Type: "plugin", Plugin: abs, SHA256: sha, AllowedSANs: []string{"a"}}, &pluginstore.Config{RequireSigned: true}, "require_signed"},
		"bad trust config": {TargetConfig{Name: "lb", Type: "plugin", Plugin: "corp-f5", AllowedSANs: []string{"a"}}, &pluginstore.Config{Trust: []pluginstore.Publisher{{Name: "x"}}}, "exactly one"},
	} {
		cfg := base
		cfg.Targets = []TargetConfig{c.tgt}
		cfg.Plugins = c.plug
		err := cfg.Validate()
		if c.want == "" && err != nil || c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
			t.Errorf("%s: got %v, want %q", name, err, c.want)
		}
	}
}

func TestCheckPlugin(t *testing.T) {
	a, tgt, _ := pluginAgent(t)
	chain := issueFor(t, a, tgt, "run-1", "app.example.test")
	if _, err := a.handleDeploy(context.Background(), runTask(t, agentproto.TaskDeploy, "lb", agentproto.DeployPayload{RunID: "run-1", ChainPEM: chain})); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := CheckPlugin(context.Background(), a.cfg, "lb", "", &out); err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	for _, want := range []string{"PASS  describe", "fake-target 1.0.0", "PASS  verify", "served sha256 " + leafSHA256(t, chain), "PASS  inventory", "1 certificates"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}
	if err := CheckPlugin(context.Background(), a.cfg, "nope", "", io.Discard); err == nil {
		t.Fatal("unknown target accepted")
	}
}
