package agent

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/dnsplugin"
	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/miekg/dns"
)

// Built-in DNS providers. Anything else is a plugin (ADR-0017).
const (
	ProviderRFC2136    = "rfc2136"
	ProviderCloudflare = "cloudflare"
)

const defaultPropagationTimeout = 2 * time.Minute

// DNSSolverConfig is one entry of dns_solvers. Exactly one of Provider and
// Plugin is set. Credentials are read from files at issue time, so rotating
// a file needs no restart.
type DNSSolverConfig struct {
	Name     string   `json:"name"`
	Provider string   `json:"provider,omitempty"`
	Plugin   string   `json:"plugin,omitempty"`
	SHA256   string   `json:"sha256,omitempty"`
	Zones    []string `json:"zones"`

	// rfc2136
	Nameserver string `json:"nameserver,omitempty"` // host:port
	TSIGFile   string `json:"tsig_file,omitempty"`  // BIND key file (tsig-keygen)

	// cloudflare
	TokenFile string `json:"token_file,omitempty"` // API token with Zone:DNS:Edit
	// APIURL overrides the Cloudflare API base URL (tests, egress proxies).
	APIURL string `json:"api_url,omitempty"`

	// plugin
	Config map[string]any `json:"config,omitempty"` // non-secret settings passed to the plugin
	// Env names agent environment variables passed through to the plugin.
	Env            []string `json:"env,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`

	// PropagationTimeoutSeconds bounds the wait for the record to be visible.
	PropagationTimeoutSeconds int `json:"propagation_timeout_seconds,omitempty"`
}

func (s *DNSSolverConfig) providerName() string {
	if s.Plugin != "" {
		return "plugin:" + strings.TrimSuffix(filepath.Base(s.Plugin), filepath.Ext(s.Plugin))
	}
	return s.Provider
}

func (s *DNSSolverConfig) validate() []string {
	var p []string
	bad := func(f string, a ...any) { p = append(p, fmt.Sprintf("dns solver %s: ", s.Name)+fmt.Sprintf(f, a...)) }
	switch {
	case s.Provider != "" && s.Plugin != "":
		bad("set provider or plugin, not both")
	case s.Provider == ProviderRFC2136:
		if _, _, err := net.SplitHostPort(s.Nameserver); err != nil {
			bad("nameserver must be host:port")
		}
		if !filepath.IsAbs(s.TSIGFile) {
			bad("tsig_file must be an absolute path (unauthenticated updates are not supported)")
		}
	case s.Provider == ProviderCloudflare:
		if !filepath.IsAbs(s.TokenFile) {
			bad("token_file must be an absolute path")
		}
		if s.APIURL != "" && !strings.HasPrefix(s.APIURL, "https://") && !strings.HasPrefix(s.APIURL, "http://127.0.0.1") {
			bad("api_url must be https")
		}
	case s.Plugin != "":
		if !filepath.IsAbs(s.Plugin) {
			bad("plugin must be an absolute path")
		}
		if b, err := hex.DecodeString(s.SHA256); err != nil || len(b) != 32 {
			bad("sha256 must be the plugin's hex SHA-256 digest")
		}
	case s.Provider == "":
		bad("provider or plugin is required")
	default:
		bad("unknown provider %q (built-in: rfc2136, cloudflare; anything else is a plugin)", s.Provider)
	}
	if len(s.Zones) == 0 {
		bad("zones must list the zones this solver may write")
	}
	for _, z := range s.Zones {
		if z == "" || strings.ContainsAny(z, "* /") {
			bad("invalid zone %q", z)
		}
	}
	return p
}

// validateDNS checks dns_solvers and resolvers.
func (c *Config) validateDNS() []string {
	var p []string
	names, zones := map[string]bool{}, map[string]string{}
	for i := range c.DNSSolvers {
		s := &c.DNSSolvers[i]
		if s.Name == "" || names[s.Name] {
			p = append(p, fmt.Sprintf("dns solver name %q must be unique and non-empty", s.Name))
		}
		names[s.Name] = true
		p = append(p, s.validate()...)
		for _, z := range s.Zones {
			z = dns.Fqdn(strings.ToLower(z))
			if other, ok := zones[z]; ok {
				p = append(p, fmt.Sprintf("zone %s is claimed by dns solvers %s and %s", z, other, s.Name))
			}
			zones[z] = s.Name
		}
	}
	for _, r := range c.Resolvers {
		if _, _, err := net.SplitHostPort(r); err != nil {
			p = append(p, fmt.Sprintf("resolver %q must be host:port", r))
		}
	}
	return p
}

func (c *Config) dnsSolverInfo() []agentproto.DNSSolver {
	var out []agentproto.DNSSolver
	for _, s := range c.DNSSolvers {
		out = append(out, agentproto.DNSSolver{Name: s.Name, Provider: s.providerName(), Zones: s.Zones})
	}
	return out
}

// dnsMux is the DNS-01 provider handed to lego. It follows the
// _acme-challenge CNAME (lego does the lookup) and sends each record to the
// solver whose zone is the longest suffix of the resulting name.
type dnsMux struct {
	solvers []*dnsSolver
	log     *slog.Logger
}

// A solver either writes records itself (rfc2136, plugins) or is a lego
// provider that does its own record naming (cloudflare).
type dnsSolver struct {
	cfg     *DNSSolverConfig
	zones   []string // FQDN form, lower case
	records dnsplugin.Handler
	lego    challenge.Provider
}

// pluginHandler adapts a plugin executable to dnsplugin.Handler.
type pluginHandler struct{ p *dnsplugin.Plugin }

func (h pluginHandler) Present(ctx context.Context, req dnsplugin.Request) error {
	_, err := h.p.Call(ctx, dnsplugin.ActionPresent, req)
	return err
}

func (h pluginHandler) Cleanup(ctx context.Context, req dnsplugin.Request) error {
	_, err := h.p.Call(ctx, dnsplugin.ActionCleanup, req)
	return err
}

func newDNSMux(cfgs []DNSSolverConfig, log *slog.Logger) (*dnsMux, error) {
	if len(cfgs) == 0 {
		return nil, errors.New("dns-01 requested but this host has no dns_solvers")
	}
	m := &dnsMux{log: log}
	for i := range cfgs {
		c := &cfgs[i]
		s := &dnsSolver{cfg: c}
		for _, z := range c.Zones {
			s.zones = append(s.zones, dns.Fqdn(strings.ToLower(z)))
		}
		var err error
		switch {
		case c.Plugin != "":
			env := map[string]string{}
			for _, k := range c.Env {
				if v, ok := os.LookupEnv(k); ok {
					env[k] = v
				}
			}
			s.records = pluginHandler{&dnsplugin.Plugin{Path: c.Plugin, SHA256: c.SHA256, Env: env,
				Timeout: time.Duration(c.TimeoutSeconds) * time.Second, Stderr: &logWriter{log: log, solver: c.Name}}}
		case c.Provider == ProviderRFC2136:
			s.records, err = newRFC2136(c)
		case c.Provider == ProviderCloudflare:
			s.lego, err = newCloudflare(c)
		}
		if err != nil {
			return nil, fmt.Errorf("dns solver %s: %w", c.Name, err)
		}
		m.solvers = append(m.solvers, s)
	}
	return m, nil
}

func (c *DNSSolverConfig) propagationTimeout() time.Duration {
	if c.PropagationTimeoutSeconds > 0 {
		return time.Duration(c.PropagationTimeoutSeconds) * time.Second
	}
	return defaultPropagationTimeout
}

func newCloudflare(c *DNSSolverConfig) (challenge.Provider, error) {
	tok, err := os.ReadFile(c.TokenFile)
	if err != nil {
		return nil, err
	}
	cfg := cloudflare.NewDefaultConfig()
	cfg.AuthToken = strings.TrimSpace(string(tok))
	if c.APIURL != "" {
		cfg.BaseURL = c.APIURL
	}
	cfg.PropagationTimeout = c.propagationTimeout()
	return cloudflare.NewDNSProviderConfig(cfg)
}

// pick returns the solver and zone for a challenge record name.
func (m *dnsMux) pick(fqdn string) (*dnsSolver, string, error) {
	fqdn = strings.ToLower(dns.Fqdn(fqdn))
	var best *dnsSolver
	var zone string
	for _, s := range m.solvers {
		for _, z := range s.zones {
			if (fqdn == z || strings.HasSuffix(fqdn, "."+z)) && len(z) > len(zone) {
				best, zone = s, z
			}
		}
	}
	if best == nil {
		return nil, "", &dnsplugin.Error{Plugin: "agent", Action: "select", Class: dnsplugin.ClassPermanent,
			Msg: fmt.Sprintf("no dns solver covers %s", fqdn)}
	}
	return best, zone, nil
}

func (m *dnsMux) Present(ctx context.Context, domain, token, keyAuth string) error {
	return m.call(ctx, dnsplugin.ActionPresent, domain, token, keyAuth)
}

func (m *dnsMux) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	return m.call(ctx, dnsplugin.ActionCleanup, domain, token, keyAuth)
}

func (m *dnsMux) call(ctx context.Context, action, domain, token, keyAuth string) error {
	info := dns01.GetChallengeInfo(ctx, domain, keyAuth)
	s, zone, err := m.pick(info.EffectiveFQDN)
	if err != nil {
		return err
	}
	m.log.Info("dns-01 "+action, "record", info.EffectiveFQDN, "solver", s.cfg.Name, "zone", zone)
	if s.records != nil {
		req := dnsplugin.Request{Protocol: dnsplugin.Protocol, FQDN: info.EffectiveFQDN, Value: info.Value, Zone: zone, Config: s.cfg.Config,
			Domain: domain, Token: token, KeyAuth: keyAuth}
		if action == dnsplugin.ActionPresent {
			return s.records.Present(ctx, req)
		}
		return s.records.Cleanup(ctx, req)
	}
	if action == dnsplugin.ActionPresent {
		return s.lego.Present(ctx, domain, token, keyAuth)
	}
	return s.lego.CleanUp(ctx, domain, token, keyAuth)
}

// Timeout is the longest propagation timeout of any solver; lego asks once
// per challenge, before it knows which solver the record went to.
func (m *dnsMux) Timeout() (timeout, interval time.Duration) {
	for _, s := range m.solvers {
		timeout = max(timeout, s.cfg.propagationTimeout())
	}
	return timeout, dns01.DefaultPollingInterval
}

// setDNSResolvers points lego's propagation checks at the configured
// resolvers. lego keeps this client process-wide.
func setDNSResolvers(resolvers []string) {
	if len(resolvers) == 0 {
		return
	}
	opts := dns01.NewOptions()
	opts.RecursiveNameservers = resolvers
	dns01.SetDefaultClient(dns01.NewClient(opts))
}

type logWriter struct {
	log    *slog.Logger
	solver string
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.log.Warn("dns plugin stderr", "solver", w.solver, "output", strings.TrimSpace(string(p)))
	return len(p), nil
}
