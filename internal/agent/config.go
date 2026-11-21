// Package agent is certloom-agent. The control plane only ever names a target;
// paths, commands and allowed SANs come from the local config file.
package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"sigs.k8s.io/yaml"
)

// Config is /etc/certloom-agent/config.yaml.
type Config struct {
	Server   string `json:"server"`
	StateDir string `json:"state_dir"`
	Name     string `json:"name,omitempty"`
	// ACMECAFile adds a trust anchor for the ACME directory (e.g. a test CA).
	ACMECAFile string `json:"acme_ca_file,omitempty"`
	// AllowedTasks restricts task types; empty means all known types.
	AllowedTasks []string `json:"allowed_tasks,omitempty"`
	// DiscoveryPaths are globs of certificate files reported by inventory.scan.
	DiscoveryPaths []string `json:"discovery_paths,omitempty"`
	// CertbotDir is read (never written) for lineage discovery; default /etc/letsencrypt.
	CertbotDir string         `json:"certbot_dir,omitempty"`
	Targets    []TargetConfig `json:"targets"`
	// DNSSolvers create DNS-01 records; credentials stay on this host.
	DNSSolvers []DNSSolverConfig `json:"dns_solvers,omitempty"`
	// Resolvers are used for DNS-01 propagation checks and CNAME lookups.
	Resolvers []string `json:"resolvers,omitempty"`
}

// TargetConfig is a locally configured deployment target.
type TargetConfig struct {
	Name string `json:"name"`
	Type string `json:"type"` // nginx
	// LiveLink is a symlink the web server reads through, e.g.
	// /etc/certloom/live/www -> <state_dir>/certs/www/<run>. The server config
	// references LiveLink/fullchain.pem and LiveLink/privkey.pem.
	LiveLink      string   `json:"live_link"`
	Webroot       string   `json:"webroot,omitempty"` // HTTP-01 challenge files are written under .well-known/acme-challenge; not needed for DNS-01
	TestCommand   []string `json:"test_command"`
	ReloadCommand []string `json:"reload_command"`
	VerifyAddress string   `json:"verify_address"` // host:port for local TLS verification
	AllowedSANs   []string `json:"allowed_sans"`
}

// LoadConfig reads and validates a config file.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.UnmarshalStrict(b, &c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &c, c.Validate()
}

// Validate checks the configuration.
func (c *Config) Validate() error {
	var p []string
	if !strings.HasPrefix(c.Server, "https://") {
		p = append(p, "server must be an https URL")
	}
	if c.StateDir == "" || !filepath.IsAbs(c.StateDir) {
		p = append(p, "state_dir must be an absolute path")
	}
	for _, t := range c.AllowedTasks {
		if !slices.Contains(agentproto.AllTaskTypes, t) {
			p = append(p, "unknown task type in allowed_tasks: "+t)
		}
	}
	seen := map[string]bool{}
	for _, t := range c.Targets {
		switch {
		case t.Name == "" || strings.ContainsAny(t.Name, `/\. `):
			p = append(p, fmt.Sprintf("target name %q must be non-empty without / \\ . or spaces", t.Name))
		case seen[t.Name]:
			p = append(p, "duplicate target "+t.Name)
		case t.Type != "nginx":
			p = append(p, fmt.Sprintf("target %s: type must be nginx", t.Name))
		case !filepath.IsAbs(t.LiveLink):
			p = append(p, fmt.Sprintf("target %s: live_link must be absolute", t.Name))
		case len(t.TestCommand) == 0 || len(t.ReloadCommand) == 0:
			p = append(p, fmt.Sprintf("target %s: test_command and reload_command are required", t.Name))
		case t.VerifyAddress == "":
			p = append(p, fmt.Sprintf("target %s: verify_address is required", t.Name))
		case len(t.AllowedSANs) == 0:
			p = append(p, fmt.Sprintf("target %s: allowed_sans must list the names this host may obtain certificates for", t.Name))
		}
		seen[t.Name] = true
	}
	p = append(p, c.validateDNS()...)
	if len(p) > 0 {
		return errors.New("invalid agent config: " + strings.Join(p, "; "))
	}
	return nil
}

func (c *Config) target(name string) (*TargetConfig, bool) {
	for i := range c.Targets {
		if c.Targets[i].Name == name {
			return &c.Targets[i], true
		}
	}
	return nil, false
}

func (c *Config) taskAllowed(t string) bool {
	if len(c.AllowedTasks) == 0 {
		return slices.Contains(agentproto.AllTaskTypes, t)
	}
	return slices.Contains(c.AllowedTasks, t)
}
