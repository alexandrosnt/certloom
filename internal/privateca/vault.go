package privateca

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/alexandrosnt/certloom/internal/secret"
)

// Vault signs through a PKI secrets engine role (POST <mount>/sign/<role>).
// sign-verbatim is never used, so the role's own name rules still apply.
type Vault struct {
	Addr      string // https://vault.example:8200
	Mount     string // pki_int
	Role      string
	IssuerRef string // optional: sign with this issuer instead of the default
	Namespace string // optional (Vault Enterprise / HCP)
	TTL       string // optional, e.g. "720h"
	// AuthMethod is "approle" (RoleID plus Secret as the secret_id, logged
	// in under AuthMount, default "approle") or "token" (Secret is the token).
	AuthMethod string
	AuthMount  string
	RoleID     string
	Secret     secret.Value
	HTTP       *http.Client
}

// Vault auth methods.
const (
	VaultAppRole = "approle"
	VaultToken   = "token"
)

// ValidVaultPath reports whether s is safe as one or more path segments of a
// Vault API URL (mount names may contain slashes, never dot segments).
func ValidVaultPath(s string, slashes bool) bool {
	if s == "" || strings.HasPrefix(s, "/") || strings.HasSuffix(s, "/") {
		return false
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." || seg == ".." || (!slashes && seg != s) {
			return false
		}
		if strings.ContainsFunc(seg, func(r rune) bool { return !pathRune(r) }) {
			return false
		}
	}
	return true
}

func pathRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("-_.", r)
}

func (v *Vault) url(path string) string {
	return strings.TrimSuffix(v.Addr, "/") + "/v1/" + path
}

func (v *Vault) header(token string) http.Header {
	h := http.Header{}
	if token != "" {
		h.Set("X-Vault-Token", token)
	}
	if v.Namespace != "" {
		h.Set("X-Vault-Namespace", v.Namespace)
	}
	return h
}

// vaultMsg pulls Vault's {"errors": [...]} out of an error body.
func vaultMsg(b []byte) string {
	var e struct {
		Errors []string `json:"errors"`
	}
	if json.Unmarshal(b, &e) == nil && len(e.Errors) > 0 {
		return strings.Join(e.Errors, "; ")
	}
	return ""
}

// login returns a token and whether it belongs to this call (and should be
// revoked after it).
func (v *Vault) login(ctx context.Context) (string, bool, error) {
	switch v.AuthMethod {
	case VaultToken:
		return v.Secret.RevealString(), false, nil
	case VaultAppRole:
		mount := v.AuthMount
		if mount == "" {
			mount = "approle"
		}
		var out struct {
			Auth struct {
				ClientToken string `json:"client_token"`
			} `json:"auth"`
		}
		body := map[string]string{"role_id": v.RoleID, "secret_id": v.Secret.RevealString()}
		if err := postJSON(ctx, v.HTTP, v.url("auth/"+mount+"/login"), v.header(""), body, &out, vaultMsg); err != nil {
			var e *Error
			if errors.As(err, &e) && e.Status == http.StatusBadRequest {
				e.Permanent = true // invalid role_id or secret_id
			}
			return "", false, err
		}
		if out.Auth.ClientToken == "" {
			return "", false, &Error{Permanent: true, Msg: "Vault AppRole login returned no token"}
		}
		return out.Auth.ClientToken, true, nil
	}
	return "", false, &Error{Permanent: true, Msg: "unknown Vault auth method " + v.AuthMethod}
}

// Sign implements Signer. sans is not sent: the role signs the names in the
// CSR, which the caller has already checked.
func (v *Vault) Sign(ctx context.Context, csrPEM string, _ []string) (string, error) {
	token, own, err := v.login(ctx)
	if err != nil {
		return "", err
	}
	if own {
		// Best effort: the token is single-purpose and expires anyway.
		defer func() {
			_ = postJSON(context.WithoutCancel(ctx), v.HTTP, v.url("auth/token/revoke-self"), v.header(token), struct{}{}, nil, vaultMsg)
		}()
	}
	path := v.Mount + "/sign/" + url.PathEscape(v.Role)
	if v.IssuerRef != "" {
		path = v.Mount + "/issuer/" + url.PathEscape(v.IssuerRef) + "/sign/" + url.PathEscape(v.Role)
	}
	body := map[string]string{"csr": csrPEM, "format": "pem"}
	if v.TTL != "" {
		body["ttl"] = v.TTL
	}
	var out struct {
		Data struct {
			Certificate string   `json:"certificate"`
			IssuingCA   string   `json:"issuing_ca"`
			CAChain     []string `json:"ca_chain"`
		} `json:"data"`
	}
	if err := postJSON(ctx, v.HTTP, v.url(path), v.header(token), body, &out, vaultMsg); err != nil {
		return "", err
	}
	parts := append([]string{out.Data.Certificate}, out.Data.CAChain...)
	if len(out.Data.CAChain) == 0 {
		parts = append(parts, out.Data.IssuingCA)
	}
	return chain(parts...)
}
