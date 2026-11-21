package agent

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// dnsSolversFor returns the solvers for one issue task: the host's own,
// then the central ones it received (ADR-0018). Local solvers come first, so
// a local solver wins when both claim the same zone.
func (a *Agent) dnsSolversFor(t *agentproto.Task, p agentproto.IssuePayload) ([]DNSSolverConfig, error) {
	out := append([]DNSSolverConfig(nil), a.cfg.DNSSolvers...)
	if len(p.DNSSolvers) == 0 {
		return out, nil
	}
	if !a.cfg.centralDNSAllowed() {
		a.log.Warn("ignoring dns solvers sent by the control plane (central_dns_solvers: false)", "count", len(p.DNSSolvers))
		return out, nil
	}
	for _, c := range p.DNSSolvers {
		s, err := a.centralSolver(t, c)
		if err != nil {
			return nil, fmt.Errorf("central dns solver %s: %w", c.Name, err)
		}
		out = append(out, s)
	}
	return out, nil
}

func (a *Agent) centralSolver(t *agentproto.Task, c agentproto.CentralDNSSolver) (DNSSolverConfig, error) {
	s := DNSSolverConfig{Name: c.Name, Zones: c.Zones, Config: c.Config, central: true}
	switch c.Provider {
	case ProviderRFC2136:
		s.Provider = ProviderRFC2136
		s.Nameserver, _ = c.Config["nameserver"].(string)
	case ProviderCloudflare:
		s.Provider = ProviderCloudflare
		s.APIURL, _ = c.Config["api_url"].(string)
	case "plugin":
		if !filepath.IsAbs(c.Plugin) {
			return s, fmt.Errorf("plugin path %q must be absolute", c.Plugin)
		}
		if b, err := hex.DecodeString(c.SHA256); err != nil || len(b) != 32 {
			return s, fmt.Errorf("plugin sha256 must be a hex SHA-256 digest")
		}
		s.Plugin, s.SHA256 = c.Plugin, c.SHA256
	default:
		return s, fmt.Errorf("unknown provider %q", c.Provider)
	}
	if v, ok := c.Config["propagation_timeout_seconds"].(float64); ok {
		s.PropagationTimeoutSeconds = int(v)
	}
	if c.Ambient {
		if s.Plugin == "" {
			return s, fmt.Errorf("ambient credentials are only for plugins")
		}
		return s, nil
	}
	if len(c.Sealed) == 0 {
		return s, fmt.Errorf("no credential was sent")
	}
	b, err := a.openSecret(agentproto.SealInfo(a.id.AgentID, t.ID, c.ID), c.Sealed)
	if err != nil {
		return s, fmt.Errorf("cannot open the sealed credential (sealed for another agent, task or key)")
	}
	if err := json.Unmarshal(b, &s.secret); err != nil {
		return s, fmt.Errorf("credential is not a JSON object of strings")
	}
	return s, nil
}
