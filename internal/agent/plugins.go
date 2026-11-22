package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/pluginstore"
	"github.com/alexandrosnt/certloom/plugin"
)

// DiscoveryPluginConfig runs a discovery plugin during inventory (ADR-0027).
type DiscoveryPluginConfig struct {
	Name string `json:"name"`
	// Plugin is an installed plugin (name or name@version) or, with SHA256,
	// an absolute path pinned by digest.
	Plugin         string         `json:"plugin"`
	SHA256         string         `json:"sha256,omitempty"`
	Config         map[string]any `json:"config,omitempty"`
	Env            []string       `json:"env,omitempty"`
	TimeoutSeconds int            `json:"timeout_seconds,omitempty"`
}

// pluginSource finds the executable behind a plugin reference.
type pluginSource struct {
	cfg      *pluginstore.Config
	stateDir string
}

func (c *Config) pluginSource() pluginSource {
	return pluginSource{cfg: c.Plugins, stateDir: c.StateDir}
}

// isPinned reports whether ref is the ADR-0017 form: an absolute path whose
// digest is pinned in the config.
func isPinned(ref string) bool {
	return filepath.IsAbs(ref) || strings.HasPrefix(ref, "/")
}

// validatePluginRef checks a reference in the config without touching the
// plugins directory, which may be filled after the config is written.
func (c *Config) validatePluginRef(ref, sha string) error {
	switch {
	case ref == "":
		return errors.New("plugin is required")
	case isPinned(ref):
		if c.Plugins != nil && c.Plugins.RequireSigned {
			return errors.New("plugins pinned by path are refused (plugins.require_signed); install a signed package with certloom-plugin")
		}
		if b, err := hex.DecodeString(sha); err != nil || len(b) != 32 {
			return errors.New("sha256 must be the plugin's hex SHA-256 digest")
		}
	default:
		name, version, _ := strings.Cut(ref, "@")
		if !pluginstore.ValidName(name) || strings.Contains(version, "/") {
			return fmt.Errorf("plugin %q must be an installed plugin name, name@version, or an absolute path", ref)
		}
		if sha != "" {
			return errors.New("sha256 is only for plugins given by path; installed plugins are checked against their install record")
		}
	}
	return nil
}

// resolve returns the executable and digest to run for ref as kind.
func (s pluginSource) resolve(ref, sha, kind string) (string, string, error) {
	if isPinned(ref) {
		if s.cfg != nil && s.cfg.RequireSigned {
			return "", "", fmt.Errorf("plugin %s is pinned by path, which plugins.require_signed refuses", ref)
		}
		return ref, sha, nil
	}
	dir := s.cfg.PluginsDir(s.stateDir)
	recs, err := pluginstore.Load(dir)
	if err != nil {
		return "", "", fmt.Errorf("plugins in %s: %w", dir, err)
	}
	r, err := pluginstore.Find(recs, ref)
	if err != nil {
		return "", "", err
	}
	if err := s.trusted(dir, r); err != nil {
		return "", "", err
	}
	if !slices.Contains(r.Kinds, kind) {
		return "", "", fmt.Errorf("plugin %s %s does not implement %s (kinds: %s)", r.Name, r.Version, kind, strings.Join(r.Kinds, ", "))
	}
	return r.Executable, r.ExecutableSHA256, nil
}

// trusted checks that an install record is still covered by the config: its
// trust entry exists and its executable lies inside its own directory.
func (s pluginSource) trusted(dir string, r *pluginstore.Record) error {
	if _, ok := s.cfg.Publisher(r.Trust); !ok {
		return fmt.Errorf("plugin %s %s was installed under trust entry %q, which is not in plugins.trust", r.Name, r.Version, r.Trust)
	}
	vdir := pluginstore.VersionDir(dir, r.Name, r.Version)
	if rel, err := filepath.Rel(vdir, r.Executable); err != nil || !filepath.IsAbs(r.Executable) || rel == "." || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("plugin %s %s: executable %s is outside %s", r.Name, r.Version, r.Executable, vdir)
	}
	return nil
}

// open returns a runnable plugin for ref.
func (s pluginSource) open(ref, sha, kind string, env []string, timeoutSeconds int, stderr io.Writer) (*plugin.Plugin, error) {
	path, digest, err := s.resolve(ref, sha, kind)
	if err != nil {
		return nil, err
	}
	return &plugin.Plugin{Path: path, SHA256: digest, Env: envFrom(env),
		Timeout: time.Duration(timeoutSeconds) * time.Second, Stderr: stderr}, nil
}

// envFrom passes the named agent environment variables to a plugin.
func envFrom(names []string) map[string]string {
	env := map[string]string{}
	for _, k := range names {
		if v, ok := os.LookupEnv(k); ok {
			env[k] = v
		}
	}
	return env
}

// pluginInfos lists what the heartbeat reports: installed plugins still
// covered by the trust policy, then plugins pinned by path in the config.
func (c *Config) pluginInfos() []agentproto.PluginInfo {
	var out []agentproto.PluginInfo
	src := c.pluginSource()
	dir := src.cfg.PluginsDir(c.StateDir)
	recs, _ := pluginstore.Load(dir) // errors surface when a plugin is used
	for i := range recs {
		r := &recs[i]
		if src.trusted(dir, r) != nil {
			continue
		}
		out = append(out, agentproto.PluginInfo{Name: r.Name, Version: r.Version, Kinds: r.Kinds,
			SHA256: r.ExecutableSHA256, Trust: r.Trust, Signer: r.Signer})
	}
	pinned := map[string]int{}
	add := func(path, sha, kind string) {
		if !isPinned(path) {
			return
		}
		if i, ok := pinned[path]; ok {
			if !slices.Contains(out[i].Kinds, kind) {
				out[i].Kinds = append(out[i].Kinds, kind)
			}
			return
		}
		pinned[path] = len(out)
		out = append(out, agentproto.PluginInfo{Name: path, Kinds: []string{kind}, SHA256: strings.ToLower(sha), Pinned: true})
	}
	for _, s := range c.DNSSolvers {
		add(s.Plugin, s.SHA256, plugin.KindDNSSolver)
	}
	for _, t := range c.Targets {
		if t.Type == agentproto.TargetPlugin {
			add(t.Plugin, t.SHA256, plugin.KindDeployTarget)
		}
	}
	for _, d := range c.DiscoveryPlugins {
		add(d.Plugin, d.SHA256, plugin.KindDiscovery)
	}
	return out
}

// pluginName is the name a reference stands for in the approved spec: the
// plugin name without a version, or the path of a pinned plugin.
func pluginName(ref string) string {
	if isPinned(ref) {
		return ref
	}
	name, _, _ := strings.Cut(ref, "@")
	return name
}

func (c *Config) validatePluginTarget(t *TargetConfig) []string {
	var p []string
	if err := c.validatePluginRef(t.Plugin, t.SHA256); err != nil {
		p = append(p, fmt.Sprintf("target %s: %v", t.Name, err))
	}
	if len(t.AllowedSANs) == 0 {
		p = append(p, fmt.Sprintf("target %s: allowed_sans must list the names this host may obtain certificates for", t.Name))
	}
	if t.LiveLink != "" || len(t.TestCommand) > 0 || len(t.ReloadCommand) > 0 || t.Site != "" || len(t.Bindings) > 0 {
		p = append(p, fmt.Sprintf("target %s: plugin targets take plugin and config, not nginx or iis settings", t.Name))
	}
	return p
}

func (c *Config) validateDiscoveryPlugins() []string {
	var p []string
	seen := map[string]bool{}
	for _, d := range c.DiscoveryPlugins {
		switch {
		case !pluginstore.ValidName(d.Name):
			p = append(p, fmt.Sprintf("discovery plugin name %q must be lower case letters, digits and dashes", d.Name))
		case seen[d.Name]:
			p = append(p, "duplicate discovery plugin "+d.Name)
		}
		if err := c.validatePluginRef(d.Plugin, d.SHA256); err != nil {
			p = append(p, fmt.Sprintf("discovery plugin %s: %v", d.Name, err))
		}
		seen[d.Name] = true
	}
	return p
}

// inventoryPlugins asks discovery plugins and plugin targets with
// inventory: true what they hold. A failing plugin is reported, not fatal.
func (a *Agent) inventoryPlugins(ctx context.Context) []agentproto.PluginInventory {
	var out []agentproto.PluginInventory
	src := a.cfg.pluginSource()
	run := func(source, kind, ref, sha string, cfg map[string]any, env []string, timeout int, target string) {
		inv := agentproto.PluginInventory{Source: source, Kind: kind, Plugin: pluginName(ref)}
		items, err := func() ([]plugin.Item, error) {
			p, err := src.open(ref, sha, kind, env, timeout, &logWriter{log: a.log, solver: source})
			if err != nil {
				return nil, err
			}
			resp, err := p.Call(ctx, plugin.ActionInventory, plugin.Request{Kind: kind, Config: cfg, Target: target})
			if err != nil {
				return nil, err
			}
			return resp.Items, nil
		}()
		if err != nil {
			inv.Error = err.Error()
		}
		for _, it := range items {
			inv.Items = append(inv.Items, agentproto.PluginItem{PEM: it.Certificate, Location: it.Location, UsedBy: it.UsedBy})
		}
		out = append(out, inv)
	}
	for _, d := range a.cfg.DiscoveryPlugins {
		run(d.Name, plugin.KindDiscovery, d.Plugin, d.SHA256, d.Config, d.Env, d.TimeoutSeconds, "")
	}
	for _, t := range a.cfg.Targets {
		if t.Type == agentproto.TargetPlugin && t.Inventory {
			run(t.Name, plugin.KindDeployTarget, t.Plugin, t.SHA256, t.PluginConfig, t.Env, t.TimeoutSeconds, t.Name)
		}
	}
	return out
}

// describePlugin runs describe and checks that the plugin speaks this
// protocol and declares kind.
func describePlugin(ctx context.Context, src pluginSource, ref, sha, kind string, env []string, timeoutSeconds int) (*plugin.Response, error) {
	p, err := src.open(ref, sha, kind, env, timeoutSeconds, nil)
	if err != nil {
		return nil, err
	}
	d, err := p.Call(ctx, plugin.ActionDescribe, plugin.Request{})
	if err != nil {
		return nil, err
	}
	if !slices.Contains(d.DescribedKinds(), kind) {
		return nil, fmt.Errorf("plugin %s %s does not declare kind %s (declares %s)", d.Name, d.Version, kind, strings.Join(d.DescribedKinds(), ", "))
	}
	return d, nil
}

func pluginTargetName(t TargetConfig) string {
	if t.Type != agentproto.TargetPlugin {
		return ""
	}
	return pluginName(t.Plugin)
}

// CheckPlugin runs the read-only calls of a plugin target or discovery
// plugin from the config: describe (digest, protocol, kind), then verify
// for a target and inventory where configured. Deploy and rollback change
// the target, so they are left to a staging run. It is the conformance
// check for plugin authors and a connection check for operators.
func CheckPlugin(ctx context.Context, cfg *Config, target, discovery string, out io.Writer) error {
	type subject struct {
		kind, ref, sha, source string
		conf                   map[string]any
		env                    []string
		timeout                int
		verify, inventory      bool
	}
	var s *subject
	for _, t := range cfg.Targets {
		if target != "" && t.Name == target && t.Type == agentproto.TargetPlugin {
			s = &subject{plugin.KindDeployTarget, t.Plugin, t.SHA256, t.Name, t.PluginConfig, t.Env, t.TimeoutSeconds, t.VerifyAddress == "", t.Inventory}
		}
	}
	for _, d := range cfg.DiscoveryPlugins {
		if discovery != "" && d.Name == discovery {
			s = &subject{plugin.KindDiscovery, d.Plugin, d.SHA256, d.Name, d.Config, d.Env, d.TimeoutSeconds, false, true}
		}
	}
	if s == nil {
		return fmt.Errorf("no plugin target %q or discovery plugin %q in the config", target, discovery)
	}
	failed := false
	step := func(what string, err error) bool {
		if err != nil {
			failed = true
			fmt.Fprintf(out, "FAIL  %s: %v\n", what, err)
			return false
		}
		fmt.Fprintf(out, "PASS  %s\n", what)
		return true
	}
	src := cfg.pluginSource()
	d, err := describePlugin(ctx, src, s.ref, s.sha, s.kind, s.env, s.timeout)
	if !step("describe (digest, protocol, kind)", err) {
		return errors.New("plugin check failed")
	}
	fmt.Fprintf(out, "      plugin %s %s, kinds %s\n", d.Name, d.Version, strings.Join(d.DescribedKinds(), ", "))
	p, err := src.open(s.ref, s.sha, s.kind, s.env, s.timeout, out)
	if err != nil {
		return err
	}
	req := plugin.Request{Kind: s.kind, Config: s.conf, Target: target, IdempotencyKey: "certloom-plugin-check"}
	if s.verify {
		served, err := pluginServed(ctx, p, req)
		if step("verify (certificate served now)", err) {
			fmt.Fprintf(out, "      served sha256 %s\n", served)
		}
	}
	if s.inventory {
		resp, err := p.Call(ctx, plugin.ActionInventory, req)
		if step("inventory", err) {
			fmt.Fprintf(out, "      %d certificates\n", len(resp.Items))
		}
	}
	if failed {
		return errors.New("plugin check failed")
	}
	return nil
}
