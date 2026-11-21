// Package oidcauth implements OIDC sign-in: authorization code +
// PKCE for browsers, and ID-token exchange for the CLI's device flow.
// Only identities with a verified email are accepted.
package oidcauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// Config holds provider settings.
type Config struct {
	Issuer       string
	ClientID     string       // confidential web client
	ClientSecret secret.Value // from a credential reference
	RedirectURL  string       // https://certloom.example/auth/oidc/callback
	// CLIClientID is a public client allowed to use the device flow.
	// Its ID tokens are accepted by the session-exchange endpoint.
	CLIClientID string
}

// Identity is a verified sign-in.
type Identity struct {
	Issuer  string
	Subject string
	Email   string
}

// Provider wraps discovery and token verification.
type Provider struct {
	cfg      Config
	provider *oidc.Provider
	oauth    oauth2.Config
	web      *oidc.IDTokenVerifier
	cli      *oidc.IDTokenVerifier
}

// ErrUnverifiedEmail is returned when the IdP does not assert email_verified.
var ErrUnverifiedEmail = errors.New("identity provider did not assert a verified email")

// New discovers the provider.
func New(ctx context.Context, cfg Config) (*Provider, error) {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.RedirectURL == "" {
		return nil, errors.New("oidc: issuer, client id and redirect url are required")
	}
	p, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	pr := &Provider{cfg: cfg, provider: p,
		oauth: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret.RevealString(), RedirectURL: cfg.RedirectURL,
			Endpoint: p.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "email", "profile"}},
		web: p.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}
	if cfg.CLIClientID != "" {
		pr.cli = p.Verifier(&oidc.Config{ClientID: cfg.CLIClientID})
	}
	return pr, nil
}

// Issuer returns the configured issuer URL.
func (p *Provider) Issuer() string { return p.cfg.Issuer }

// CLIClientID returns the public client id for the device flow ("" if disabled).
func (p *Provider) CLIClientID() string { return p.cfg.CLIClientID }

// DeviceAuthURL returns the device authorization endpoint, if advertised.
func (p *Provider) DeviceAuthURL() string { return p.provider.Endpoint().DeviceAuthURL }

// TokenURL returns the token endpoint.
func (p *Provider) TokenURL() string { return p.provider.Endpoint().TokenURL }

// Random returns a URL-safe random string for state, nonce and PKCE.
func Random() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// AuthCodeURL builds the authorization redirect with state, nonce and PKCE (S256).
func (p *Provider) AuthCodeURL(state, nonce, pkceVerifier string) string {
	return p.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(pkceVerifier))
}

// Exchange redeems a code and verifies the ID token, its nonce and the email.
func (p *Provider) Exchange(ctx context.Context, code, pkceVerifier, nonce string) (*Identity, error) {
	tok, err := p.oauth.Exchange(ctx, code, oauth2.VerifierOption(pkceVerifier))
	if err != nil {
		return nil, fmt.Errorf("oidc code exchange: %w", err)
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("oidc: no id_token in token response")
	}
	idt, err := p.web.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	if idt.Nonce != nonce {
		return nil, errors.New("oidc: nonce mismatch")
	}
	return identity(idt)
}

// VerifyCLIToken verifies an ID token obtained by the CLI's device flow.
func (p *Provider) VerifyCLIToken(ctx context.Context, raw string) (*Identity, error) {
	if p.cli == nil {
		return nil, errors.New("oidc: CLI sign-in is not enabled on this server")
	}
	idt, err := p.cli.Verify(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("oidc: %w", err)
	}
	return identity(idt)
}

func identity(idt *oidc.IDToken) (*Identity, error) {
	var c struct {
		Email         string `json:"email"`
		EmailVerified any    `json:"email_verified"` // some IdPs send "true" as a string
	}
	if err := idt.Claims(&c); err != nil {
		return nil, err
	}
	verified := c.EmailVerified == true || c.EmailVerified == "true"
	if c.Email == "" || !verified {
		return nil, ErrUnverifiedEmail
	}
	return &Identity{Issuer: idt.Issuer, Subject: idt.Subject, Email: c.Email}, nil
}
