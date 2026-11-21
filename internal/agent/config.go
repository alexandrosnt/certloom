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
	// CentralDNSSolvers: set false to refuse solvers and credentials sent by the
	// control plane (ADR-0018); only dns_solvers above are used then.
	CentralDNSSolvers *bool `json:"central_dns_solvers,omitempty"`
	// ACMEEAB holds External Account Binding keys for CAs that require them.
	// A key here is used instead of one sent by the control plane.
	ACMEEAB []EABConfig `json:"acme_eab,omitempty"`
	// CentralEAB: set false to refuse EAB keys sent by the control plane
	// (ADR-0019).
	CentralEAB *bool `json:"central_eab,omitempty"`
	// Kubernetes switches the agent to in-cluster observation (ADR-0023):
	// it then only runs inventory tasks and has no targets.
	Kubernetes *KubeConfig `json:"kubernetes,omitempty"`
	// WinACMEDir is read (never written) for win-acme discovery on Windows;
	// default %ProgramData%win-acme.
	WinACMEDir string `json:"win_acme_dir,omitempty"`
}

// EABConfig is a host-local EAB key for one ACME directory.
type EABConfig struct {
	DirectoryURL string `json:"directory_url"`
	KID          string `json:"kid"`
	// HMACFile holds the base64url HMAC key as issued by the CA.
	HMACFile string `json:"hmac_file"`
}

// TargetConfig is a locally configured deployment target.
type TargetConfig struct {
	Name string `json:"name"`
	Type string `json:"type"` // nginx or iis
	// LiveLink is a symlink the web server reads through, e.g.
	// /etc/certloom/live/www -> <state_dir>/certs/www/<run>. The server config
	// references LiveLink/fullchain.pem and LiveLink/privkey.pem.
	LiveLink      string   `json:"live_link"`
	Webroot       string   `json:"webroot,omitempty"` // HTTP-01 challenge files are written under .well-known/acme-challenge; not needed for DNS-01
	TestCommand   []string `json:"test_command"`
	ReloadCommand []string `json:"reload_command"`
	VerifyAddress string   `json:"verify_address"` // host:port for local TLS verification
	AllowedSANs   []string `json:"allowed_sans"`
	// Site and Bindings are used by iis targets: the IIS site name and the
	// https bindings (ip:port:host, as in applicationHost.config) whose
	// certificate the agent replaces.
	Site     string   `json:"site,omitempty"`
	Bindings []string `json:"bindings,omitempty"`
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
	if c.Kubernetes != nil {
		p = append(p, c.validateKube()...)
	}
	seen := map[string]bool{}
	for _, t := range c.Targets {
		switch {
		case t.Name == "" || strings.ContainsAny(t.Name, `/\. `):
			p = append(p, fmt.Sprintf("target name %q must be non-empty without / \\ . or spaces", t.Name))
		case seen[t.Name]:
			p = append(p, "duplicate target "+t.Name)
		case t.Type == agentproto.TargetIIS:
			p = append(p, t.validateIIS()...)
		case t.Type != agentproto.TargetNginx:
			p = append(p, fmt.Sprintf("target %s: type must be nginx or iis", t.Name))
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
	p = append(p, c.validateEAB()...)
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
	if c.Kubernetes != nil && t != agentproto.TaskInventoryScan {
		return false // observation only; never stand in for cert-manager
	}
	if len(c.AllowedTasks) == 0 {
		return slices.Contains(agentproto.AllTaskTypes, t)
	}
	return slices.Contains(c.AllowedTasks, t)
}

func (c *Config) centralDNSAllowed() bool {
	return c.CentralDNSSolvers == nil || *c.CentralDNSSolvers
}

func (c *Config) centralEABAllowed() bool {
	return c.CentralEAB == nil || *c.CentralEAB
}

func (c *Config) validateEAB() []string {
	var p []string
	seen := map[string]bool{}
	for _, e := range c.ACMEEAB {
		switch {
		case !strings.HasPrefix(e.DirectoryURL, "https://"):
			p = append(p, fmt.Sprintf("acme_eab: directory_url %q must be an https URL", e.DirectoryURL))
		case seen[e.DirectoryURL]:
			p = append(p, "acme_eab: duplicate directory_url "+e.DirectoryURL)
		case e.KID == "":
			p = append(p, "acme_eab "+e.DirectoryURL+": kid is required")
		case !filepath.IsAbs(e.HMACFile):
			p = append(p, "acme_eab "+e.DirectoryURL+": hmac_file must be an absolute path")
		}
		seen[e.DirectoryURL] = true
	}
	return p
}

func (c *Config) localEAB(directoryURL string) *EABConfig {
	for i := range c.ACMEEAB {
		if c.ACMEEAB[i].DirectoryURL == directoryURL {
			return &c.ACMEEAB[i]
		}
	}
	return nil
}

// inventoryInterval is how often this agent wants to be asked for an
// inventory: in-cluster observation polls, and IIS hosts report bindings so
// drift is noticed between renewals.
func (c *Config) inventoryInterval() int {
	if c.Kubernetes != nil {
		if c.Kubernetes.IntervalSeconds > 0 {
			return c.Kubernetes.IntervalSeconds
		}
		return 300
	}
	for _, t := range c.Targets {
		if t.Type == agentproto.TargetIIS {
			return 900
		}
	}
	return 0
}
