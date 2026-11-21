// Package oidctest is a minimal OpenID Provider for tests: discovery, JWKS,
// authorization code with PKCE (auto-approves), and the device flow
// (auto-approves). Never use outside tests.
package oidctest

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// User is the identity the provider signs in.
type User struct {
	Subject       string
	Email         string
	EmailVerified bool
}

// Server is a running test provider.
type Server struct {
	*httptest.Server
	t      testing.TB
	key    *rsa.PrivateKey
	mu     sync.Mutex
	User   User
	codes  map[string]codeGrant
	device map[string]string // device_code -> client_id
}

type codeGrant struct {
	clientID, challenge, nonce string
}

// New starts a provider.
func New(t testing.TB) *Server {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{t: t, key: k, codes: map[string]codeGrant{}, device: map[string]string{},
		User: User{Subject: "u-1", Email: "alice@example.test", EmailVerified: true}}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", s.discovery)
	mux.HandleFunc("/jwks", s.jwks)
	mux.HandleFunc("/authorize", s.authorize)
	mux.HandleFunc("/token", s.token)
	mux.HandleFunc("/device", s.deviceAuth)
	s.Server = httptest.NewServer(mux)
	t.Cleanup(s.Close)
	return s
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, map[string]any{
		"issuer": s.URL, "authorization_endpoint": s.URL + "/authorize", "token_endpoint": s.URL + "/token",
		"jwks_uri": s.URL + "/jwks", "device_authorization_endpoint": s.URL + "/device",
		"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"}, "code_challenge_methods_supported": []string{"S256"},
	})
}

func (s *Server) jwks(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &s.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
}

func rnd() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
		http.Error(w, "PKCE S256 required", 400)
		return
	}
	code := rnd()
	s.mu.Lock()
	s.codes[code] = codeGrant{clientID: q.Get("client_id"), challenge: q.Get("code_challenge"), nonce: q.Get("nonce")}
	s.mu.Unlock()
	u, _ := url.Parse(q.Get("redirect_uri"))
	v := u.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	u.RawQuery = v.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func (s *Server) deviceAuth(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	dc := rnd()
	s.mu.Lock()
	s.device[dc] = r.Form.Get("client_id")
	s.mu.Unlock()
	writeJSON(w, 200, map[string]any{"device_code": dc, "user_code": "ABCD-EFGH", "verification_uri": s.URL + "/activate",
		"expires_in": 300, "interval": 1})
}

func (s *Server) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	clientID := r.Form.Get("client_id")
	if u, _, ok := r.BasicAuth(); ok {
		clientID = u
	}
	var nonce string
	switch r.Form.Get("grant_type") {
	case "authorization_code":
		s.mu.Lock()
		g, ok := s.codes[r.Form.Get("code")]
		delete(s.codes, r.Form.Get("code"))
		s.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || g.clientID != clientID || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
		nonce = g.nonce
	case "urn:ietf:params:oauth:grant-type:device_code":
		s.mu.Lock()
		cid, ok := s.device[r.Form.Get("device_code")]
		delete(s.device, r.Form.Get("device_code"))
		s.mu.Unlock()
		if !ok || cid != clientID {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return
		}
	default:
		writeJSON(w, 400, map[string]string{"error": "unsupported_grant_type"})
		return
	}
	writeJSON(w, 200, map[string]any{"access_token": rnd(), "token_type": "Bearer", "expires_in": 300,
		"id_token": s.IDToken(clientID, nonce)})
}

// IDToken signs an ID token for the current user and audience.
func (s *Server) IDToken(aud, nonce string) string {
	s.mu.Lock()
	u := s.User
	s.mu.Unlock()
	claims := map[string]any{"iss": s.URL, "sub": u.Subject, "aud": aud, "iat": time.Now().Unix(),
		"exp": time.Now().Add(5 * time.Minute).Unix(), "email": u.Email, "email_verified": u.EmailVerified}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	payload, _ := json.Marshal(claims)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: s.key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	if err != nil {
		s.t.Fatal(err)
	}
	obj, err := signer.Sign(payload)
	if err != nil {
		s.t.Fatal(err)
	}
	out, _ := obj.CompactSerialize()
	return out
}

// SetUser changes the identity signed in by subsequent flows.
func (s *Server) SetUser(u User) {
	s.mu.Lock()
	s.User = u
	s.mu.Unlock()
}
