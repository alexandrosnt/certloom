package app

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strings"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/policy"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Central DNS-01 solvers (ADR-0018). Stored secrets are encrypted with the
// KEK, bound to the solver id, never returned, and reach an agent only
// sealed to it inside an issue task.

// DNSSolverInput describes a new solver.
type DNSSolverInput struct {
	Name, Provider, Plugin, PluginSHA256 string
	Zones                                []string
	Config                               map[string]any
	// Credential is "stored" (default) or "ambient" (plugins only).
	Credential string
	// Secret is a JSON object of strings, e.g. {"api_token": "..."}.
	Secret secret.Value
}

func secretAAD(solverID string) string { return "dns_solver:" + solverID }

// secretKeys lists the keys a built-in provider needs in its secret.
var secretKeys = map[string]string{"rfc2136": "tsig_key", "cloudflare": "api_token"}

func (s *Service) checkDNSSolver(in *DNSSolverInput) error {
	if strings.TrimSpace(in.Name) == "" {
		return invalid("name is required")
	}
	if in.Credential == "" {
		in.Credential = "stored"
	}
	if in.Config == nil {
		in.Config = map[string]any{}
	}
	switch in.Provider {
	case "rfc2136":
		ns, _ := in.Config["nameserver"].(string)
		if _, _, err := net.SplitHostPort(ns); err != nil {
			return invalid("config.nameserver must be host:port")
		}
	case "cloudflare":
		if u, _ := in.Config["api_url"].(string); u != "" && !strings.HasPrefix(u, "https://") {
			return invalid("config.api_url must be https")
		}
	case "plugin":
		if !path.IsAbs(in.Plugin) {
			return invalid("plugin must be an absolute path on the agent hosts")
		}
		if b, err := hex.DecodeString(in.PluginSHA256); err != nil || len(b) != 32 {
			return invalid("plugin_sha256 must be the plugin's hex SHA-256 digest")
		}
	default:
		return invalid("provider must be rfc2136, cloudflare or plugin")
	}
	if in.Provider != "plugin" && (in.Plugin != "" || in.PluginSHA256 != "") {
		return invalid("plugin and plugin_sha256 are only for provider plugin")
	}
	if len(in.Zones) == 0 {
		return invalid("zones must list the zones this solver may write")
	}
	for i, z := range in.Zones {
		z = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(z), "."))
		if z == "" || strings.ContainsAny(z, "* /") {
			return invalid("invalid zone %q", in.Zones[i])
		}
		in.Zones[i] = z
	}
	switch in.Credential {
	case "ambient":
		if in.Provider != "plugin" {
			return invalid("ambient credentials (the host's cloud identity) are only for plugins")
		}
		if !in.Secret.IsEmpty() {
			return invalid("an ambient solver takes no secret")
		}
	case "stored":
		if err := checkSecret(in.Provider, in.Secret); err != nil {
			return err
		}
	default:
		return invalid("credential must be stored or ambient")
	}
	return nil
}

func checkSecret(provider string, v secret.Value) error {
	var m map[string]string
	if err := json.Unmarshal(v.Reveal(), &m); err != nil || len(m) == 0 {
		return invalid("secret must be a non-empty JSON object of strings")
	}
	if k := secretKeys[provider]; k != "" && strings.TrimSpace(m[k]) == "" {
		return invalid("secret for %s needs %q", provider, k)
	}
	return nil
}

func (s *Service) centralAllowed(ctx context.Context, tx *store.Tx) (bool, error) {
	pv, err := tx.ActivePolicy(ctx)
	if err != nil {
		return false, err
	}
	return pv.Document.Spec.DNS.CentralCredentials != policy.CentralCredentialsForbidden, nil
}

// CreateDNSSolver defines a solver.
func (s *Service) CreateDNSSolver(ctx context.Context, p authz.Principal, in DNSSolverInput) (*store.DNSSolver, error) {
	if s.PKI == nil {
		return nil, ErrAgentsDisabled
	}
	if err := s.checkDNSSolver(&in); err != nil {
		return nil, err
	}
	d := &store.DNSSolver{ID: store.NewDNSSolverID(), Name: in.Name, Provider: in.Provider, Plugin: in.Plugin,
		PluginSHA256: strings.ToLower(in.PluginSHA256), Zones: in.Zones, Config: in.Config, Credential: in.Credential}
	err := s.tx(ctx, p, authz.ManageDNS, func(tx *store.Tx) error {
		if d.Credential == "stored" {
			ok, err := s.centralAllowed(ctx, tx)
			if err != nil {
				return err
			}
			if !ok {
				return invalid("policy dns.centralCredentials is forbidden: credentials must stay on the agent hosts")
			}
			if d.SecretCiphertext, err = s.PKI.KEK.Seal(in.Secret.Reveal(), secretAAD(d.ID)); err != nil {
				return err
			}
		}
		if err := tx.CreateDNSSolver(ctx, d, p.Actor); err != nil {
			return err
		}
		d.HasSecret = len(d.SecretCiphertext) > 0
		return s.audit(ctx, tx, p, "dns_solvers.create", "dns_solver", d.ID, map[string]any{"name": d.Name,
			"provider": d.Provider, "plugin": d.Plugin, "plugin_sha256": d.PluginSHA256, "zones": d.Zones,
			"config": d.Config, "credential": d.Credential})
	})
	return d, err
}

// ListDNSSolvers lists solvers without their secrets.
func (s *Service) ListDNSSolvers(ctx context.Context, p authz.Principal) (out []*store.DNSSolver, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListDNSSolvers(ctx, ""); return err })
	return out, err
}

// GetDNSSolver returns one solver without its secret.
func (s *Service) GetDNSSolver(ctx context.Context, p authz.Principal, ref string) (d *store.DNSSolver, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { d, err = tx.GetDNSSolver(ctx, ref); return err })
	return d, err
}

// SetDNSSolverSecret replaces (rotates) a stored secret; the next issuance uses it.
func (s *Service) SetDNSSolverSecret(ctx context.Context, p authz.Principal, ref string, v secret.Value) error {
	if s.PKI == nil {
		return ErrAgentsDisabled
	}
	return s.tx(ctx, p, authz.ManageDNS, func(tx *store.Tx) error {
		d, err := tx.GetDNSSolver(ctx, ref)
		if err != nil {
			return err
		}
		if d.Credential != "stored" {
			return invalid("solver %s uses ambient credentials and stores no secret", d.Name)
		}
		if ok, err := s.centralAllowed(ctx, tx); err != nil || !ok {
			if err != nil {
				return err
			}
			return invalid("policy dns.centralCredentials is forbidden")
		}
		if err := checkSecret(d.Provider, v); err != nil {
			return err
		}
		ct, err := s.PKI.KEK.Seal(v.Reveal(), secretAAD(d.ID))
		if err != nil {
			return err
		}
		if err := tx.SetDNSSolverSecret(ctx, d.ID, ct); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "dns_solvers.set_secret", "dns_solver", d.ID, map[string]any{"name": d.Name})
	})
}

// AssignDNSSolver makes a solver available to an agent, or removes it.
func (s *Service) AssignDNSSolver(ctx context.Context, p authz.Principal, solverRef, agentRef string, assign bool) error {
	return s.tx(ctx, p, authz.ManageDNS, func(tx *store.Tx) error {
		d, err := tx.GetDNSSolver(ctx, solverRef)
		if err != nil {
			return err
		}
		a, err := tx.GetAgent(ctx, agentRef)
		if err != nil {
			return invalid("agent %q not found", agentRef)
		}
		action := "dns_solvers.assign"
		if assign {
			if a.State != "active" {
				return invalid("agent %q is not active", a.Name)
			}
			err = tx.AssignDNSSolver(ctx, d.ID, a.ID)
		} else {
			action = "dns_solvers.unassign"
			err = tx.UnassignDNSSolver(ctx, d.ID, a.ID)
		}
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, p, action, "dns_solver", d.ID, map[string]any{"name": d.Name, "agent": a.ID})
	})
}

// DeleteDNSSolver deletes a solver and its stored secret.
func (s *Service) DeleteDNSSolver(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ManageDNS, func(tx *store.Tx) error {
		d, err := tx.GetDNSSolver(ctx, ref)
		if err != nil {
			return err
		}
		if err := tx.DeleteDNSSolver(ctx, d.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "dns_solvers.delete", "dns_solver", d.ID, map[string]any{"name": d.Name})
	})
}

// centralSolversFor builds the solvers an issue task carries, sealing each
// stored secret to the agent for this task. Nothing is sent when policy
// forbids central credentials or the agent refuses them (no sealing key).
func (s *Service) centralSolversFor(ctx context.Context, tx *store.Tx, a *store.Agent, runID, taskID string) ([]agentproto.CentralDNSSolver, error) {
	ok, err := s.centralAllowed(ctx, tx)
	if err != nil || !ok {
		return nil, err
	}
	if len(a.Capabilities.SealKey) == 0 {
		return nil, nil
	}
	solvers, err := tx.ListDNSSolvers(ctx, a.ID)
	if err != nil {
		return nil, err
	}
	var out []agentproto.CentralDNSSolver
	for _, d := range solvers {
		c := agentproto.CentralDNSSolver{ID: d.ID, Name: d.Name, Provider: d.Provider, Plugin: d.Plugin, SHA256: d.PluginSHA256,
			Zones: d.Zones, Config: d.Config, Ambient: d.Credential == "ambient"}
		if !c.Ambient {
			if len(d.SecretCiphertext) == 0 {
				continue
			}
			plain, err := s.PKI.KEK.Open(d.SecretCiphertext, secretAAD(d.ID))
			if err != nil {
				return nil, fmt.Errorf("dns solver %s: stored secret cannot be decrypted: %w", d.Name, err)
			}
			c.Sealed, err = agentproto.SealSecret(a.Capabilities.SealKey, agentproto.SealInfo(a.ID, taskID, d.ID), plain)
			clear(plain)
			if err != nil {
				return nil, fmt.Errorf("dns solver %s: %w", d.Name, err)
			}
			if err := s.systemAudit(ctx, tx, workflowActor, "dns_solvers.secret_delivered", "dns_solver", d.ID,
				map[string]any{"name": d.Name, "agent": a.ID, "run": runID, "task": taskID}); err != nil {
				return nil, err
			}
		}
		out = append(out, c)
	}
	return out, nil
}
