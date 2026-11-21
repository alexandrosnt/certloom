package app

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/audit"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/oidcauth"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

// ErrNoMembership is returned when a verified identity is not a member of any
// (or the requested) organization.
var ErrNoMembership = errors.New("this identity is not a member of the requested organization")

// ErrChooseOrg is returned when an identity belongs to several orgs and none was chosen.
type ErrChooseOrg struct{ Orgs []string }

func (e *ErrChooseOrg) Error() string {
	return "member of several organizations; choose one: " + strings.Join(e.Orgs, ", ")
}

func (s *Service) sessionTTL() time.Duration {
	if s.SessionTTL > 0 {
		return s.SessionTTL
	}
	return 12 * time.Hour
}

// SignIn creates a session for a verified identity. orgName selects the org
// when the identity has several memberships.
func (s *Service) SignIn(ctx context.Context, id *oidcauth.Identity, orgName, via string) (secret.Value, *store.Member, error) {
	ms, err := s.DB.MembershipsFor(ctx, id.Issuer, id.Email)
	if err != nil {
		return secret.Value{}, nil, err
	}
	var chosen *store.Member
	switch {
	case orgName != "":
		o, err := s.DB.OrgByName(ctx, orgName)
		if err != nil {
			return secret.Value{}, nil, ErrNoMembership
		}
		for i := range ms {
			if ms[i].OrgID == o.ID {
				chosen = &ms[i]
			}
		}
	case len(ms) == 1:
		chosen = &ms[0]
	case len(ms) > 1:
		e := &ErrChooseOrg{}
		for _, m := range ms {
			if o, err := s.orgName(ctx, m.OrgID); err == nil {
				e.Orgs = append(e.Orgs, o)
			}
		}
		return secret.Value{}, nil, e
	}
	if chosen == nil {
		return secret.Value{}, nil, ErrNoMembership
	}
	var tok secret.Value
	err = s.DB.WithOrg(ctx, chosen.OrgID, func(tx *store.Tx) (err error) {
		if tok, err = tx.CreateSession(ctx, chosen.ID, s.sessionTTL()); err != nil {
			return err
		}
		return audit.Write(ctx, tx, &audit.Event{OrgID: chosen.OrgID, Actor: "user:" + chosen.Email, Action: "auth.sign_in",
			ResourceType: "member", ResourceID: chosen.ID, RequestID: RequestID(ctx),
			Detail: map[string]any{"via": via, "issuer": id.Issuer, "subject": id.Subject, "role": chosen.Role}})
	})
	return tok, chosen, err
}

func (s *Service) orgName(ctx context.Context, id string) (string, error) {
	var n string
	err := s.DB.Pool.QueryRow(ctx, `SELECT name FROM organizations WHERE id = $1`, id).Scan(&n)
	return n, err
}

// SignOut revokes a session token (no-op for API tokens).
func (s *Service) SignOut(ctx context.Context, token string) error {
	org, ok := store.ParseSessionOrg(token)
	if !ok {
		return nil
	}
	return s.DB.WithOrg(ctx, org, func(tx *store.Tx) error { return tx.RevokeSession(ctx, token) })
}

func (s *Service) authenticateSession(ctx context.Context, token string) (authz.Principal, error) {
	org, ok := store.ParseSessionOrg(token)
	if !ok {
		return authz.Principal{}, store.ErrInvalidToken
	}
	var p authz.Principal
	err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
		m, err := tx.AuthenticateSession(ctx, token)
		if err != nil {
			return err
		}
		p = authz.Principal{OrgID: org, Actor: "user:" + m.Email, Role: m.Role}
		return nil
	})
	return p, err
}

// ---------- members ----------

// CreateMember grants an OIDC identity (by verified email) a role.
func (s *Service) CreateMember(ctx context.Context, p authz.Principal, email, role string) (*store.Member, error) {
	if s.OIDC == nil {
		return nil, invalid("OIDC is not configured on this server")
	}
	if _, err := mail.ParseAddress(email); err != nil || strings.ContainsAny(email, "<> ") {
		return nil, invalid("invalid email %q", email)
	}
	if !store.ValidRole(role) {
		return nil, invalid("unknown role %q", role)
	}
	if role == store.RoleOwner && p.Role != store.RoleOwner {
		return nil, authz.ErrForbidden
	}
	var m *store.Member
	err := s.tx(ctx, p, authz.ManageMembers, func(tx *store.Tx) (err error) {
		if m, err = tx.CreateMember(ctx, s.OIDC.Issuer(), email, role, p.Actor); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "members.create", "member", m.ID, map[string]any{"email": m.Email, "role": role, "issuer": m.Issuer})
	})
	return m, err
}

// ListMembers lists members.
func (s *Service) ListMembers(ctx context.Context, p authz.Principal) (out []store.Member, err error) {
	err = s.tx(ctx, p, authz.ManageMembers, func(tx *store.Tx) error { out, err = tx.ListMembers(ctx); return err })
	return out, err
}

// DeleteMember removes a member and ends their sessions.
func (s *Service) DeleteMember(ctx context.Context, p authz.Principal, id string) error {
	return s.tx(ctx, p, authz.ManageMembers, func(tx *store.Tx) error {
		if err := tx.DeleteMember(ctx, id); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "members.delete", "member", id, nil)
	})
}

// AuthConfig is the public description of sign-in options.
type AuthConfig struct {
	OIDC          bool   `json:"oidc"`
	Issuer        string `json:"issuer,omitempty"`
	CLIClientID   string `json:"cli_client_id,omitempty"`
	DeviceAuthURL string `json:"device_authorization_endpoint,omitempty"`
	TokenURL      string `json:"token_endpoint,omitempty"`
}

// PublicAuthConfig describes how clients can sign in.
func (s *Service) PublicAuthConfig() AuthConfig {
	if s.OIDC == nil {
		return AuthConfig{}
	}
	c := AuthConfig{OIDC: true, Issuer: s.OIDC.Issuer()}
	if s.OIDC.CLIClientID() != "" && s.OIDC.DeviceAuthURL() != "" {
		c.CLIClientID, c.DeviceAuthURL, c.TokenURL = s.OIDC.CLIClientID(), s.OIDC.DeviceAuthURL(), s.OIDC.TokenURL()
	}
	return c
}

// ExchangeCLIToken turns a device-flow ID token into a session.
func (s *Service) ExchangeCLIToken(ctx context.Context, idToken, org string) (secret.Value, *store.Member, error) {
	if s.OIDC == nil {
		return secret.Value{}, nil, invalid("OIDC is not configured on this server")
	}
	id, err := s.OIDC.VerifyCLIToken(ctx, idToken)
	if err != nil {
		return secret.Value{}, nil, fmt.Errorf("%w: %v", store.ErrInvalidToken, err)
	}
	return s.SignIn(ctx, id, org, "cli-device-flow")
}
