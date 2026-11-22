package privateca

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/testpki"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

func makeCSR(t *testing.T, key crypto.Signer, tmpl *x509.CertificateRequest) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestCheckCSR(t *testing.T) {
	key := p256(t)
	sans := []string{"a.example.test", "b.example.test"}
	good := makeCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "a.example.test"}, DNSNames: sans})
	if _, err := CheckCSR(good, []string{"B.example.test.", "a.example.test"}, "ecdsa-p256"); err != nil {
		t.Fatalf("good CSR rejected: %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ext := pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: []byte{0x30, 0x03, 0x01, 0x01, 0xff}} // CA:true
	bad := map[string]string{
		"extra name":     makeCSR(t, key, &x509.CertificateRequest{DNSNames: append(sans, "c.example.test")}),
		"missing name":   makeCSR(t, key, &x509.CertificateRequest{DNSNames: sans[:1]}),
		"rsa key":        makeCSR(t, rsaKey, &x509.CertificateRequest{DNSNames: sans}),
		"organization":   makeCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{Organization: []string{"x"}}, DNSNames: sans}),
		"foreign cn":     makeCSR(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "evil.test"}, DNSNames: sans}),
		"ca extension":   makeCSR(t, key, &x509.CertificateRequest{DNSNames: sans, ExtraExtensions: []pkix.Extension{ext}}),
		"email name":     makeCSR(t, key, &x509.CertificateRequest{DNSNames: sans, EmailAddresses: []string{"a@example.test"}}),
		"trailing data":  good + good,
		"not a CSR":      string(testpki.NewHierarchy(t, "a.example.test").Leaf.PEM()),
		"bad signature":  tamper(t, good),
		"unknown keyalg": "",
	}
	for name, csr := range bad {
		alg := "ecdsa-p256"
		if name == "unknown keyalg" {
			csr, alg = good, "rsa-2048"
		}
		if _, err := CheckCSR(csr, sans, alg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// tamper flips a bit in the CSR's signature.
func tamper(t *testing.T, csrPEM string) string {
	t.Helper()
	blk, _ := pem.Decode([]byte(csrPEM))
	b := append([]byte(nil), blk.Bytes...)
	b[len(b)-3] ^= 0x01
	return string(pem.EncodeToMemory(&pem.Block{Type: blk.Type, Bytes: b}))
}

// signCSR issues a leaf for the CSR's key and names from the hierarchy's
// intermediate.
func signCSR(t *testing.T, h *testpki.Hierarchy, csrPEM string) string {
	blk, _ := pem.Decode([]byte(csrPEM))
	csr, err := x509.ParseCertificateRequest(blk.Bytes)
	if err != nil {
		t.Error(err)
		return ""
	}
	leaf := testpki.IssueWithKey(t, h.Intermediate, fakeSigner{csr.PublicKey}, testpki.Options{CommonName: csr.Subject.CommonName, DNSNames: csr.DNSNames})
	return string(leaf.PEM())
}

// fakeSigner lets IssueWithKey take a bare public key.
type fakeSigner struct{ pub crypto.PublicKey }

func (f fakeSigner) Public() crypto.PublicKey { return f.pub }
func (fakeSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("not a private key")
}

func caClient(t *testing.T, srv *httptest.Server) *http.Client {
	t.Helper()
	c, err := HTTPClient(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestVaultAppRoleSign(t *testing.T) {
	h := testpki.NewHierarchy(t, "x.test")
	var revoked atomic.Bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Namespace") != "team-a" {
			http.Error(w, `{"errors":["missing namespace"]}`, http.StatusBadRequest)
			return
		}
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/v1/auth/approle-ci/login":
			if body["role_id"] != "rid" || body["secret_id"] != "sid" {
				http.Error(w, `{"errors":["invalid role or secret ID"]}`, http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"auth":{"client_token":"hvs.short"}}`))
		case "/v1/pki/int/issuer/second/sign/web":
			if r.Header.Get("X-Vault-Token") != "hvs.short" || body["ttl"] != "72h" || body["format"] != "pem" {
				http.Error(w, `{"errors":["permission denied"]}`, http.StatusForbidden)
				return
			}
			out := map[string]any{"data": map[string]any{"certificate": signCSR(t, h, body["csr"]),
				"issuing_ca": string(h.Intermediate.PEM()), "ca_chain": []string{string(h.Intermediate.PEM()), string(h.Root.PEM())}}}
			_ = json.NewEncoder(w).Encode(out)
		case "/v1/auth/token/revoke-self":
			if r.Header.Get("X-Vault-Token") == "hvs.short" {
				revoked.Store(true)
			}
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	v := &Vault{Addr: srv.URL + "/", Mount: "pki/int", Role: "web", IssuerRef: "second", Namespace: "team-a", TTL: "72h",
		AuthMethod: VaultAppRole, AuthMount: "approle-ci", RoleID: "rid", Secret: secret.FromString("sid"), HTTP: caClient(t, srv)}
	csr := makeCSR(t, p256(t), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x.test"}, DNSNames: []string{"x.test"}})
	chainPEM, err := v.Sign(context.Background(), csr, []string{"x.test"})
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(chainPEM, "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("chain has %d certificates, want leaf + intermediate (root dropped)", n)
	}
	if !revoked.Load() {
		t.Fatal("AppRole token was not revoked after use")
	}

	v.Secret = secret.FromString("wrong")
	_, err = v.Sign(context.Background(), csr, []string{"x.test"})
	var e *Error
	if !errors.As(err, &e) || !e.Permanent || !strings.Contains(e.Msg, "invalid role or secret ID") {
		t.Fatalf("bad secret_id: %v", err)
	}
}

func TestVaultErrorClasses(t *testing.T) {
	status := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch status {
		case 429:
			w.Header().Set("Retry-After", "120")
		case 302:
			w.Header().Set("Location", "https://elsewhere.test/")
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"errors":["subject alternate name x.test not allowed by this role"]}`))
	}))
	defer srv.Close()
	v := &Vault{Addr: srv.URL, Mount: "pki", Role: "web", AuthMethod: VaultToken, Secret: secret.FromString("t"), HTTP: caClient(t, srv)}
	for _, tc := range []struct {
		status    int
		permanent bool
		retry     time.Duration
	}{{400, true, 0}, {403, true, 0}, {302, true, 0}, {503, false, 0}, {429, false, 2 * time.Minute}} {
		status = tc.status
		_, err := v.Sign(context.Background(), "csr", nil)
		var e *Error
		if !errors.As(err, &e) || e.Status != tc.status || e.Permanent != tc.permanent || e.RetryAfter != tc.retry {
			t.Errorf("status %d: got %+v", tc.status, err)
		}
	}
	if !strings.Contains(func() string { status = 400; _, err := v.Sign(context.Background(), "csr", nil); return err.Error() }(), "not allowed by this role") {
		t.Error("Vault's message is not passed through")
	}
}

func TestVaultUntrustedServer(t *testing.T) {
	// A server whose certificate comes from a CA that is not in ca_bundle.
	h := testpki.NewHierarchy(t, "localhost")
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{h.Leaf.DER, h.Intermediate.DER}, PrivateKey: h.Leaf.Key}}}
	srv.StartTLS()
	defer srv.Close()
	other := httptest.NewTLSServer(http.NotFoundHandler())
	defer other.Close()
	v := &Vault{Addr: srv.URL, Mount: "pki", Role: "web", AuthMethod: VaultToken, Secret: secret.FromString("t"), HTTP: caClient(t, other)}
	_, err := v.Sign(context.Background(), "csr", nil)
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("server outside ca_bundle accepted: %v", err)
	}
}

func TestStepCASign(t *testing.T) {
	h := testpki.NewHierarchy(t, "x.test")
	key := p256(t)
	jwk := jose.JSONWebKey{Key: key, KeyID: "kid-1", Algorithm: string(jose.ES256), Use: "sig"}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if kid, err := ParseProvisionerKey(jwkJSON); err != nil || kid != "kid-1" {
		t.Fatalf("ParseProvisionerKey = %q, %v", kid, err)
	}
	pubJSON, _ := json.Marshal(jwk.Public())
	if _, err := ParseProvisionerKey(pubJSON); err == nil {
		t.Fatal("public JWK accepted as provisioner key")
	}
	now := time.Now()
	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/1.0/sign" {
			http.NotFound(w, r)
			return
		}
		var body struct{ CSR, OTT string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		tok, err := jwt.ParseSigned(body.OTT, []jose.SignatureAlgorithm{jose.ES256})
		if err != nil {
			http.Error(w, `{"message":"bad token"}`, http.StatusUnauthorized)
			return
		}
		var std jwt.Claims
		var extra struct {
			SANs []string `json:"sans"`
		}
		if err := tok.Claims(key.Public(), &std, &extra); err != nil {
			http.Error(w, `{"message":"bad signature"}`, http.StatusUnauthorized)
			return
		}
		ok := tok.Headers[0].KeyID == "kid-1" && std.Issuer == "certloom" && std.Subject == "x.test" &&
			len(extra.SANs) == 2 && std.ID != "" && std.Expiry.Time().Sub(std.NotBefore.Time()) == tokenLifetime &&
			std.Validate(jwt.Expected{AnyAudience: jwt.Audience{srvURL + "/1.0/sign"}, Time: now}) == nil
		if !ok {
			http.Error(w, `{"message":"token claims wrong"}`, http.StatusUnauthorized)
			return
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"crt": signCSR(t, h, body.CSR), "ca": string(h.Intermediate.PEM()),
			"certChain": []string{signCSR(t, h, body.CSR), string(h.Intermediate.PEM())}})
	}))
	defer srv.Close()
	srvURL = srv.URL
	s := &StepCA{URL: srv.URL, Provisioner: "certloom", JWK: secret.New(jwkJSON), HTTP: caClient(t, srv), Now: func() time.Time { return now }}
	sans := []string{"x.test", "y.test"}
	csr := makeCSR(t, p256(t), &x509.CertificateRequest{Subject: pkix.Name{CommonName: "x.test"}, DNSNames: sans})
	chainPEM, err := s.Sign(context.Background(), csr, sans)
	if err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(chainPEM, "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("chain has %d certificates, want 2", n)
	}
	s.Provisioner = "other"
	_, err = s.Sign(context.Background(), csr, sans)
	var e *Error
	if !errors.As(err, &e) || !e.Permanent || e.Msg != "token claims wrong" {
		t.Fatalf("refused token: %v", err)
	}
}
