package workflow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"golang.org/x/oauth2"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/cloudobs"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

// redirect sends every request to srv, whatever host it names, so the real
// provider endpoints can stand for a test server.
type redirect struct {
	srv *url.URL
	rt  http.RoundTripper // nil: http.DefaultTransport
}

func (r redirect) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.srv.Scheme, r.srv.Host
	req.URL.Path = strings.TrimPrefix(req.URL.Path, "/client/v4")
	if r.rt != nil {
		return r.rt.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}

// fakeCloudflare serves one zone with a failing certificate pack and one
// Origin CA certificate, and counts requests without the right token.
func fakeCloudflare(t *testing.T, originPEM string) (*httptest.Server, *int) {
	t.Helper()
	unauthorized := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer cf-token" {
			unauthorized++
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
			return
		}
		res := func(v any) {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": v, "result_info": map[string]any{"total_pages": 1}})
		}
		switch r.URL.Path {
		case "/zones":
			res([]any{map[string]any{"id": "z1", "name": "example.test"}})
		case "/zones/z1/ssl/certificate_packs":
			res([]any{map[string]any{"id": "p1", "type": "advanced", "status": "validation_timed_out", "hosts": []string{"new.example.test"}}})
		case "/certificates":
			res([]any{map[string]any{"id": "o1", "certificate": originPEM, "hostnames": []string{"origin.example.test"},
				"expires_on": "2041-01-01 00:00:00 +0000 UTC"}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &unauthorized
}

func runCloudScans(t *testing.T, e *env) {
	t.Helper()
	q := &jobs.Queue{Pool: e.db.Pool, WorkerID: "test"}
	js, err := q.Claim(ctx, []string{app.JobKindCloudScan}, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, j := range js {
		if err := e.svc.RunCloudScan(ctx, j); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCloudAccountScan(t *testing.T) {
	e := newEnv(t)
	origin := testpki.Issue(t, e.ca, testpki.Options{CommonName: "origin.example.test", DNSNames: []string{"origin.example.test"}})
	srv, unauthorized := fakeCloudflare(t, string(origin.PEM()))
	u, _ := url.Parse(srv.URL)
	e.svc.CloudHooks = &cloudobs.Hooks{HTTPClient: &http.Client{Transport: redirect{srv: u}}}

	a, err := e.svc.CreateCloudAccount(ctx, e.owner, app.CloudAccountInput{Name: "cf-main", Provider: "cloudflare", Credential: "stored",
		Settings: json.RawMessage(`{"zones":["example.test"],"origin_ca":true}`), Secret: secret.New([]byte(`{"api_token":"cf-token"}`))})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(a); strings.Contains(string(b), "cf-token") || !a.HasSecret {
		t.Fatalf("account JSON: %s", b)
	}
	runCloudScans(t, e)
	if *unauthorized > 0 {
		t.Fatalf("%d requests without the stored token", *unauthorized)
	}

	fs := findings(t, e)
	failing := openOf(fs, "cloud_renewal_failing")
	if len(failing) != 1 || !strings.HasPrefix(failing[0].subjectID, a.ID+"/") {
		t.Fatalf("renewal failing: %+v", failing)
	}
	var n int
	if err := e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE sha256 = $1`, sha(origin)).Scan(&n); err != nil || n != 1 {
		t.Fatalf("origin certificate imported: %d %v", n, err)
	}
	inv, err := e.svc.CloudAccountInventory(ctx, e.owner, "cf-main")
	if err != nil || inv["scanned_at"] == nil || strings.Contains(fmt.Sprintf("%s", inv["cloud"]), "BEGIN CERTIFICATE") {
		t.Fatalf("stored inventory: %v %v", inv, err)
	}

	// Deleting the account resolves what it reported.
	if err := e.svc.DeleteCloudAccount(ctx, e.owner, "cf-main"); err != nil {
		t.Fatal(err)
	}
	if open := openOf(findings(t, e), "cloud_renewal_failing"); len(open) != 0 {
		t.Fatalf("findings left after delete: %+v", open)
	}
}

func TestCloudAccountSettingsAreRestricted(t *testing.T) {
	e := newEnv(t)
	cf := secret.New([]byte(`{"api_token":"t"}`))
	cases := []app.CloudAccountInput{
		// No endpoint overrides or local files from the API.
		{Name: "a", Provider: "cloudflare", Credential: "stored", Settings: json.RawMessage(`{"api_url":"https://evil.example"}`), Secret: cf},
		{Name: "a", Provider: "aws", Settings: json.RawMessage(`{"regions":["us-east-1"],"endpoint_url":"https://evil.example"}`)},
		{Name: "a", Provider: "aws", Settings: json.RawMessage(`{"regions":["us-east-1"],"credentials_file":"/etc/certloom/kek"}`)},
		{Name: "a", Provider: "gcp", Settings: json.RawMessage(`{"project":"my-project-1","credentials_file":"/x"}`)},
		{Name: "a", Provider: "azure", Settings: json.RawMessage(`{"vaults":["https://evil.example.com"]}`)},
		{Name: "a", Provider: "azure", Settings: json.RawMessage(`{"vaults":["https://corp.vault.azure.net/"]}`)},
		{Name: "a", Provider: "aws", Settings: json.RawMessage(`{"regions":["us-east-1","us-east-1"]}`)},
		{Name: "a", Provider: "azure", Settings: json.RawMessage(`{"vaults":["https://corp.vault.azure.net.evil.example"]}`)},
		// Federation configs can name local files and token URLs.
		{Name: "a", Provider: "gcp", Credential: "stored", Settings: json.RawMessage(`{"project":"my-project-1"}`),
			Secret: secret.New([]byte(`{"service_account_key":"{\"type\":\"external_account\",\"credential_source\":{\"file\":\"/etc/certloom/kek\"}}"}`))},
		{Name: "a", Provider: "cloudflare", Settings: json.RawMessage(`{}`)},
		{Name: "a", Provider: "aws", Settings: json.RawMessage(`{"regions":["us-east-1"]}`), IntervalSeconds: 60},
		{Name: "a/b", Provider: "aws", Settings: json.RawMessage(`{"regions":["us-east-1"]}`)},
	}
	for i, in := range cases {
		if _, err := e.svc.CreateCloudAccount(ctx, e.owner, in); !errors.Is(err, app.ErrInvalid) {
			t.Errorf("case %d: want invalid, got %v", i, err)
		}
	}
	if _, err := e.svc.CreateCloudAccount(ctx, e.owner, app.CloudAccountInput{Name: "prod", Provider: "aws",
		Settings: json.RawMessage(`{"regions":["eu-west-1","us-east-1"],"assume_role_arn":"arn:aws:iam::111122223333:role/certloom","external_id":"x"}`)}); err != nil {
		t.Fatal(err)
	}
}

// staticAzureCred hands out a fixed token, standing in for Entra ID.
type staticAzureCred struct{}

func (staticAzureCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "az-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

// Azure and Google accounts go through the same server path as Cloudflare;
// tokens come from test hooks since neither cloud can be faked at login.
func TestCloudAccountAzureAndGoogle(t *testing.T) {
	e := newEnv(t)
	kv := testpki.Issue(t, e.ca, testpki.Options{CommonName: "api.example.test", DNSNames: []string{"api.example.test"}})
	gcm := testpki.Issue(t, e.ca, testpki.Options{CommonName: "shop.example.test", DNSNames: []string{"shop.example.test"}})
	const vault = "https://corp.vault.azure.net"
	const gp = "/v1/projects/shop-prod/locations/global"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := strings.TrimSuffix(r.URL.Path, "/")
		var out any
		switch {
		case r.Host == "corp.vault.azure.net" && r.Header.Get("Authorization") == "":
			w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/tenant", resource="https://vault.azure.net"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		case p == "/certificates":
			out = map[string]any{"value": []any{map[string]any{"id": vault + "/certificates/api", "attributes": map[string]any{"enabled": true}}}}
		case p == "/certificates/api":
			out = map[string]any{"id": vault + "/certificates/api/v1", "cer": base64.StdEncoding.EncodeToString(kv.DER),
				"attributes": map[string]any{"enabled": true, "exp": kv.Cert.NotAfter.Unix()}}
		case p == "/certificates/api/versions":
			out = map[string]any{"value": []any{}}
		case p == "/certificates/api/pending":
			w.WriteHeader(http.StatusNotFound)
			out = map[string]any{"error": map[string]any{"code": "CertificateOperationNotFound"}}
		case p == gp+"/certificates":
			if r.Header.Get("Authorization") != "Bearer gcp-token" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			out = map[string]any{"certificates": []any{map[string]any{"name": "projects/shop-prod/locations/global/certificates/web",
				"sanDnsnames": []string{"shop.example.test"}, "pemCertificate": string(gcm.PEM()), "managed": map[string]any{"state": "ACTIVE"}}}}
		case p == gp+"/certificateMaps":
			out = map[string]any{}
		default:
			w.WriteHeader(http.StatusNotFound)
			out = map[string]any{"error": map[string]any{"code": "NotFound"}}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	e.svc.CloudHooks = &cloudobs.Hooks{HTTPClient: &http.Client{Transport: redirect{srv: u, rt: srv.Client().Transport}},
		AzureCred: staticAzureCred{}, GCPTokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "gcp-token"}),
		GCPBase: map[string]string{"certificatemanager.googleapis.com": srv.URL}}

	for _, in := range []app.CloudAccountInput{
		{Name: "corp", Provider: "azure", Settings: json.RawMessage(`{"vaults":["https://corp.vault.azure.net"]}`)},
		{Name: "shop", Provider: "gcp", Settings: json.RawMessage(`{"project":"shop-prod"}`)},
	} {
		if _, err := e.svc.CreateCloudAccount(ctx, e.owner, in); err != nil {
			t.Fatalf("%s: %v", in.Name, err)
		}
	}
	runCloudScans(t, e)
	for _, c := range []*testpki.Cert{kv, gcm} {
		var n int
		if err := e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE sha256 = $1`, sha(c)).Scan(&n); err != nil || n != 1 {
			t.Errorf("%s not imported: %d %v", c.Cert.Subject.CommonName, n, err)
		}
	}
	for _, name := range []string{"corp", "shop"} {
		inv, err := e.svc.CloudAccountInventory(ctx, e.owner, name)
		if err != nil || strings.Contains(fmt.Sprintf("%s", inv["cloud"]), `"errors"`) {
			t.Errorf("%s: %s %v", name, inv["cloud"], err)
		}
	}
}
