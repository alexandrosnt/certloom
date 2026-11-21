package agent

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeKubeAPI serves list responses for the paths the agent reads and
// records which bearer tokens were sent.
type fakeKubeAPI struct {
	mu        sync.Mutex
	tokens    []string
	throttled bool
	lists     map[string][]string // path -> pages of items JSON
}

func (f *fakeKubeAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Method != http.MethodGet {
		http.Error(w, "read only", http.StatusMethodNotAllowed)
		return
	}
	f.tokens = append(f.tokens, r.Header.Get("Authorization"))
	if strings.Contains(r.URL.Path, "secrets") || strings.Contains(r.URL.Path, "configmaps") {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path == "/apis/cert-manager.io/v1/certificaterequests" && !f.throttled {
		f.throttled = true
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}
	pages, ok := f.lists[r.URL.Path]
	if !ok {
		http.NotFound(w, r)
		return
	}
	i := 0
	if c := r.URL.Query().Get("continue"); c != "" {
		_, _ = fmt.Sscan(c, &i)
	}
	cont := ""
	if i+1 < len(pages) {
		cont = fmt.Sprint(i + 1)
	}
	fmt.Fprintf(w, `{"metadata":{"continue":%q},"items":[%s]}`, cont, pages[i])
}

func kubeTestAgent(t *testing.T, api *fakeKubeAPI) (*Agent, string) {
	t.Helper()
	srv := httptest.NewTLSServer(api)
	t.Cleanup(srv.Close)
	dir := t.TempDir()
	ca := filepath.Join(dir, "ca.crt")
	_ = os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600)
	tok := filepath.Join(dir, "token")
	_ = os.WriteFile(tok, []byte("token-1\n"), 0o600)
	cfg := &Config{StateDir: dir, Kubernetes: &KubeConfig{Cluster: "prod-eu", APIServer: srv.URL, CAFile: ca, TokenFile: tok}}
	return &Agent{cfg: cfg, log: slog.New(slog.NewTextHandler(io.Discard, nil))}, tok
}

func TestInventoryKube(t *testing.T) {
	pemCert := base64.StdEncoding.EncodeToString([]byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"))
	api := &fakeKubeAPI{lists: map[string][]string{
		"/apis/cert-manager.io/v1/certificates": {
			`{"metadata":{"namespace":"web","name":"shop"},"spec":{"secretName":"shop-tls","dnsNames":["shop.example.test"],"issuerRef":{"name":"le","kind":"ClusterIssuer"}},
			  "status":{"revision":2,"notAfter":"2027-01-01T00:00:00Z","renewalTime":"2026-12-01T00:00:00Z","conditions":[{"type":"Ready","status":"True","reason":"Ready"}]}}`,
			`{"metadata":{"namespace":"web","name":"blog"},"spec":{"secretName":"blog-tls","dnsNames":["blog.example.test"],"issuerRef":{"name":"local"}},
			  "status":{"revision":1,"conditions":[{"type":"Ready","status":"False","reason":"Failed","message":"issuer refused"}]}}`,
		},
		"/apis/cert-manager.io/v1/certificaterequests": {
			`{"metadata":{"namespace":"web","name":"shop-1","annotations":{"cert-manager.io/certificate-name":"shop","cert-manager.io/certificate-revision":"1"}},"status":{"certificate":"` + pemCert + `"}},
			 {"metadata":{"namespace":"web","name":"shop-2","annotations":{"cert-manager.io/certificate-name":"shop","cert-manager.io/certificate-revision":"2"}},"status":{"certificate":"` + pemCert + `"}},
			 {"metadata":{"namespace":"web","name":"blog-2","annotations":{"cert-manager.io/certificate-name":"blog","cert-manager.io/certificate-revision":"2"}},
			  "status":{"conditions":[{"type":"Denied","status":"True","reason":"PolicyDenied","message":"names not allowed"}]}}`,
		},
		"/apis/cert-manager.io/v1/issuers":        {`{"metadata":{"namespace":"web","name":"local"},"spec":{"selfSigned":{}},"status":{"conditions":[{"type":"Ready","status":"True"}]}}`},
		"/apis/cert-manager.io/v1/clusterissuers": {`{"metadata":{"name":"le"},"spec":{"acme":{"server":"x"}},"status":{"conditions":[{"type":"Ready","status":"False","reason":"ErrRegisterACMEAccount"}]}}`},
		"/apis/networking.k8s.io/v1/ingresses":    {`{"metadata":{"namespace":"web","name":"shop"},"spec":{"tls":[{"hosts":["shop.example.test"],"secretName":"shop-tls"}]}}`},
		// trust-manager is not installed: bundles return 404.
	}}
	a, tok := kubeTestAgent(t, api)
	inv, err := a.inventoryKube(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if inv.Cluster != "prod-eu" || len(inv.Certificates) != 2 || len(inv.Issuers) != 2 || len(inv.Ingresses) != 1 || len(inv.Bundles) != 0 {
		t.Fatalf("%+v", inv)
	}
	shop, blog := inv.Certificates[0], inv.Certificates[1]
	if shop.RequestName != "shop-2" || !strings.Contains(shop.ChainPEM, "BEGIN CERTIFICATE") || shop.IssuerKind != "ClusterIssuer" {
		t.Fatalf("shop: %+v", shop)
	}
	if blog.IssuerKind != "Issuer" || blog.ChainPEM != "" || !strings.HasPrefix(blog.RequestFailed, "Denied: PolicyDenied") {
		t.Fatalf("blog: %+v", blog)
	}
	if inv.Issuers[1].Type != "acme" || inv.Issuers[0].Type != "selfSigned" {
		t.Fatalf("issuers: %+v", inv.Issuers)
	}
	if len(inv.Errors) != 1 || !strings.Contains(inv.Errors[0], "bundles") {
		t.Fatalf("errors: %v", inv.Errors)
	}
	if !api.throttled {
		t.Fatal("429 path not exercised")
	}

	// A rotated projected token is picked up on the next request.
	_ = os.WriteFile(tok, []byte("token-2"), 0o600)
	if _, err := a.inventoryKube(context.Background()); err != nil {
		t.Fatal(err)
	}
	if last := api.tokens[len(api.tokens)-1]; last != "Bearer token-2" {
		t.Fatalf("token not re-read: %q", last)
	}
	for _, tk := range api.tokens {
		if tk == "" {
			t.Fatal("request without token")
		}
	}
}

func TestKubeModeIsInventoryOnly(t *testing.T) {
	c := &Config{Kubernetes: &KubeConfig{Cluster: "c"}}
	for _, tt := range []string{"acme.issue", "deploy.activate", "deploy.rollback", "verify.local"} {
		if c.taskAllowed(tt) {
			t.Errorf("%s allowed in kubernetes mode", tt)
		}
	}
	if !c.taskAllowed("inventory.scan") || c.inventoryInterval() != 300 {
		t.Fatal("inventory must be allowed and polled")
	}
}
