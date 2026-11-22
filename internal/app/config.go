package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Get, update and delete for configuration objects, so API clients such as
// the Terraform provider can manage their whole lifecycle. Patch inputs use
// nil for "leave unchanged".

// ---------- teams ----------

// TeamPatch changes a team.
type TeamPatch struct {
	Name    *string
	Contact *string
}

// GetTeam returns a team by id or name.
func (s *Service) GetTeam(ctx context.Context, p authz.Principal, ref string) (t *store.Team, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { t, err = tx.TeamByRef(ctx, ref); return err })
	return t, err
}

// UpdateTeam applies a patch to a team.
func (s *Service) UpdateTeam(ctx context.Context, p authz.Principal, ref string, in TeamPatch) (t *store.Team, err error) {
	if in.Name != nil && strings.TrimSpace(*in.Name) == "" {
		return nil, invalid("team name is required")
	}
	err = s.tx(ctx, p, authz.ManageOwnership, func(tx *store.Tx) error {
		if t, err = tx.TeamByRef(ctx, ref); err != nil {
			return err
		}
		setIf(&t.Name, in.Name)
		setIf(&t.Contact, in.Contact)
		if err := tx.UpdateTeam(ctx, t); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "teams.update", "team", t.ID, map[string]any{"name": t.Name})
	})
	return t, err
}

// DeleteTeam removes a team that owns no lineages or endpoints.
func (s *Service) DeleteTeam(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ManageOwnership, func(tx *store.Tx) error {
		t, err := tx.TeamByRef(ctx, ref)
		if err != nil {
			return err
		}
		if err := tx.DeleteTeam(ctx, t.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "teams.delete", "team", t.ID, map[string]any{"name": t.Name})
	})
}

// ---------- scopes ----------

// ScopePatch changes a probe scope. Config replaces the whole config.
type ScopePatch struct {
	Name   *string
	Config *store.ScopeConfig
}

// GetScope returns a scope by id or name.
func (s *Service) GetScope(ctx context.Context, p authz.Principal, ref string) (sc *store.ProbeScope, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { sc, err = tx.ScopeByRef(ctx, ref); return err })
	return sc, err
}

// UpdateScope applies a patch to a scope. Like creation, the audit event
// records every address-class override so widening a scope is visible.
func (s *Service) UpdateScope(ctx context.Context, p authz.Principal, ref string, in ScopePatch) (sc *store.ProbeScope, err error) {
	err = s.tx(ctx, p, authz.ManageScopes, func(tx *store.Tx) error {
		if sc, err = tx.ScopeByRef(ctx, ref); err != nil {
			return err
		}
		setIf(&sc.Name, in.Name)
		if in.Config != nil {
			sc.Config = *in.Config
		}
		if err := validateScope(sc.Name, sc.Config); err != nil {
			return err
		}
		if err := tx.UpdateScope(ctx, sc); err != nil {
			if errors.Is(err, store.ErrConflict) || errors.Is(err, store.ErrNotFound) {
				return err
			}
			return invalid("%v", err)
		}
		cfg := sc.Config
		return s.audit(ctx, tx, p, "scopes.update", "scope", sc.ID, map[string]any{
			"name": sc.Name, "allow_cidrs": cfg.AllowCIDRs, "allow_hosts": cfg.AllowHosts, "ports": cfg.Ports,
			"allow_loopback": cfg.AllowLoopback, "allow_private": cfg.AllowPrivate, "allow_link_local": cfg.AllowLinkLocal,
		})
	})
	return sc, err
}

// DeleteScope removes a scope no endpoint uses.
func (s *Service) DeleteScope(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ManageScopes, func(tx *store.Tx) error {
		sc, err := tx.ScopeByRef(ctx, ref)
		if err != nil {
			return err
		}
		if err := tx.DeleteScope(ctx, sc.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "scopes.delete", "scope", sc.ID, map[string]any{"name": sc.Name})
	})
}

// ---------- endpoints ----------

// EndpointPatch changes an endpoint's settings. Team and Lineage take an id
// or name; an empty string clears them.
type EndpointPatch struct {
	Scope    *string
	Team     *string
	Lineage  *string
	Interval *time.Duration
	Enabled  *bool
}

// UpdateEndpoint applies a patch to an endpoint. ifVersion, if non-nil, is
// the version the caller last saw (If-Match).
func (s *Service) UpdateEndpoint(ctx context.Context, p authz.Principal, id string, in EndpointPatch, ifVersion *int64) (e *store.Endpoint, err error) {
	if in.Interval != nil && *in.Interval < time.Minute {
		return nil, invalid("interval must be at least 1m")
	}
	err = s.tx(ctx, p, authz.ManageEndpoints, func(tx *store.Tx) error {
		if e, err = tx.GetEndpoint(ctx, id); err != nil {
			return err
		}
		changes := map[string]any{}
		if in.Scope != nil {
			sc, err := tx.ScopeByRef(ctx, *in.Scope)
			if err != nil {
				return invalid("scope %q not found", *in.Scope)
			}
			if err := scopeAllows(sc, e.Host, e.Port); err != nil {
				return err
			}
			e.ScopeID, changes["scope"] = sc.ID, sc.Name
		}
		if in.Team != nil {
			e.TeamID = nil
			if *in.Team != "" {
				t, err := tx.TeamByRef(ctx, *in.Team)
				if err != nil {
					return invalid("team %q not found", *in.Team)
				}
				e.TeamID = &t.ID
			}
			changes["team"] = e.TeamID
		}
		if in.Lineage != nil {
			e.LineageID = nil
			if *in.Lineage != "" {
				l, err := tx.LineageByRef(ctx, *in.Lineage)
				if err != nil {
					return invalid("lineage %q not found", *in.Lineage)
				}
				e.LineageID = &l.ID
			}
			changes["lineage"] = e.LineageID
		}
		if in.Interval != nil {
			e.IntervalSeconds = int(in.Interval.Seconds())
			changes["interval_seconds"] = e.IntervalSeconds
		}
		if in.Enabled != nil {
			e.Enabled, changes["enabled"] = *in.Enabled, *in.Enabled
		}
		if err := tx.UpdateEndpoint(ctx, e, ifVersion); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "endpoints.update", "endpoint", e.ID, changes)
	})
	return e, err
}

// DeleteEndpoint removes an endpoint, resolving its open findings first so
// no alert is left pointing at it. Endpoints used by a deployment stay.
func (s *Service) DeleteEndpoint(ctx context.Context, p authz.Principal, id string) error {
	return s.tx(ctx, p, authz.ManageEndpoints, func(tx *store.Tx) error {
		e, err := tx.GetEndpoint(ctx, id)
		if err != nil {
			return err
		}
		if _, err := tx.SyncFindings(ctx, "endpoint", e.ID, nil, s.now()); err != nil {
			return err
		}
		if err := tx.DeleteEndpoint(ctx, e.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "endpoints.delete", "endpoint", e.ID, map[string]any{"host": e.Host, "port": e.Port, "sni": e.SNI})
	})
}

// ---------- channels ----------

// ChannelPatch changes a notification channel. Config replaces the whole
// config; the kind is fixed.
type ChannelPatch struct {
	Name          *string
	Config        json.RawMessage
	CredentialRef *string
	MinSeverity   *string
	Enabled       *bool
}

// GetChannel returns a channel by id.
func (s *Service) GetChannel(ctx context.Context, p authz.Principal, id string) (c *store.Channel, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { c, err = tx.GetChannel(ctx, id); return err })
	return c, err
}

// UpdateChannel applies a patch to a channel. A channel the active policy
// names cannot be renamed, since the policy would silently stop matching it.
func (s *Service) UpdateChannel(ctx context.Context, p authz.Principal, id string, in ChannelPatch) (c *store.Channel, err error) {
	err = s.tx(ctx, p, authz.ManageChannels, func(tx *store.Tx) error {
		if c, err = tx.GetChannel(ctx, id); err != nil {
			return err
		}
		if in.Name != nil && *in.Name != c.Name {
			if err := channelNotInPolicy(ctx, tx, c.Name); err != nil {
				return err
			}
			c.Name = *in.Name
		}
		if in.Config != nil {
			c.Config = in.Config
		}
		setIf(&c.CredentialRef, in.CredentialRef)
		setIf(&c.MinSeverity, in.MinSeverity)
		if in.Enabled != nil {
			c.Enabled = *in.Enabled
		}
		if err := ValidateChannel(c); err != nil {
			return invalid("%v", err)
		}
		if err := tx.UpdateChannel(ctx, c); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "channels.update", "channel", c.ID, map[string]any{"name": c.Name, "kind": c.Kind,
			"min_severity": c.MinSeverity, "enabled": c.Enabled, "has_credential": c.CredentialRef != ""})
	})
	return c, err
}

// DeleteChannel removes a channel the active policy does not name.
func (s *Service) DeleteChannel(ctx context.Context, p authz.Principal, id string) error {
	return s.tx(ctx, p, authz.ManageChannels, func(tx *store.Tx) error {
		c, err := tx.GetChannel(ctx, id)
		if err != nil {
			return err
		}
		if err := channelNotInPolicy(ctx, tx, c.Name); err != nil {
			return err
		}
		if err := tx.DeleteChannel(ctx, c.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "channels.delete", "channel", c.ID, map[string]any{"name": c.Name, "kind": c.Kind})
	})
}

func channelNotInPolicy(ctx context.Context, tx *store.Tx, name string) error {
	pv, err := tx.ActivePolicy(ctx)
	if err != nil {
		return err
	}
	spec := pv.Document.Spec
	if slices.Contains(spec.Escalation.Channels, name) || slices.Contains(spec.Approvals.Channels, name) {
		return fmt.Errorf("%w: channel %s is named in the active policy; remove it there first", store.ErrInUse, name)
	}
	return nil
}

// ---------- issuers ----------

// IssuerPatch changes an issuer. The kind, URL, settings and terms-of-service
// decision are fixed; a different CA is a new issuer. Email and profile are
// ACME settings; the CA bundle (rotated CA roots) belongs to the other kinds.
type IssuerPatch struct {
	Name     *string
	Email    *string
	Profile  *string
	CABundle *string
}

// GetIssuer returns an issuer by id or name.
func (s *Service) GetIssuer(ctx context.Context, p authz.Principal, ref string) (i *store.Issuer, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { i, err = tx.GetIssuer(ctx, ref); return err })
	return i, err
}

// UpdateIssuer applies a patch to an issuer.
func (s *Service) UpdateIssuer(ctx context.Context, p authz.Principal, ref string, in IssuerPatch) (i *store.Issuer, err error) {
	if in.Name != nil && strings.TrimSpace(*in.Name) == "" {
		return nil, invalid("issuer name is required")
	}
	err = s.tx(ctx, p, authz.ManageIssuers, func(tx *store.Tx) error {
		if i, err = tx.GetIssuer(ctx, ref); err != nil {
			return err
		}
		if i.Native() && (in.Email != nil || in.Profile != nil) {
			return invalid("email and profile belong to ACME issuers")
		}
		if !i.Native() && in.CABundle != nil {
			return invalid("ca_bundle belongs to vault and stepca issuers; ACME issuers use the system roots")
		}
		setIf(&i.Name, in.Name)
		setIf(&i.Email, in.Email)
		setIf(&i.Profile, in.Profile)
		if in.CABundle != nil {
			if err := checkCABundle(*in.CABundle); err != nil {
				return err
			}
			i.CABundle = *in.CABundle
		}
		if err := tx.UpdateIssuer(ctx, i); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "issuers.update", "issuer", i.ID, map[string]any{"name": i.Name, "profile": i.Profile,
			"ca_bundle_changed": in.CABundle != nil})
	})
	return i, err
}

// DeleteIssuer removes an issuer no deployment or EAB key uses.
func (s *Service) DeleteIssuer(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ManageIssuers, func(tx *store.Tx) error {
		i, err := tx.GetIssuer(ctx, ref)
		if err != nil {
			return err
		}
		if err := tx.DeleteIssuer(ctx, i.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "issuers.delete", "issuer", i.ID, map[string]any{"name": i.Name, "directory_url": i.DirectoryURL})
	})
}

func setIf[T any](dst *T, v *T) {
	if v != nil {
		*dst = *v
	}
}
