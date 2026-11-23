package cloudobs

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
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
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/aws/smithy-go/encoding/cbor"
	"golang.org/x/oauth2"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

// callLog records the calls a fake provider received.
type callLog struct {
	mu    sync.Mutex
	calls []string
}

func (l *callLog) add(s string) {
	l.mu.Lock()
	l.calls = append(l.calls, s)
	l.mu.Unlock()
}

func (l *callLog) all() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.calls...)
}

func testPEM(t *testing.T, names ...string) (string, []byte) {
	t.Helper()
	c := testpki.Issue(t, nil, testpki.Options{CommonName: names[0], DNSNames: names})
	return string(c.PEM()), c.DER
}

var discard = slog.New(slog.NewTextHandler(io.Discard, nil))

func objectsBy(inv *agentproto.CloudInventory, provider string) map[string]agentproto.CloudObject {
	m := map[string]agentproto.CloudObject{}
	for _, o := range inv.Objects {
		if o.Provider == provider {
			m[o.ID] = o
		}
	}
	return m
}

func TestCloudAWS(t *testing.T) {
	certPEM, _ := testPEM(t, "www.example.test")
	var log callLog
	const arnIssued = "arn:aws:acm:us-east-1:111122223333:certificate/issued"
	const arnImported = "arn:aws:acm:us-east-1:111122223333:certificate/imported"
	const arnPending = "arn:aws:acm:us-east-1:111122223333:certificate/pending"
	exp := float64(time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC).Unix())
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		target := r.Header.Get("X-Amz-Target")
		// Private CA speaks Smithy RPC v2 CBOR, ACM JSON 1.1.
		cborOp := strings.HasPrefix(r.URL.Path, "/service/ACMPrivateCA/operation/")
		if cborOp {
			target = "ACMPrivateCA." + strings.TrimPrefix(r.URL.Path, "/service/ACMPrivateCA/operation/")
		}
		body, _ := io.ReadAll(r.Body)
		log.add(target)
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 ") {
			t.Errorf("%s: request not signed", target)
		}
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		var out any
		switch target {
		case "CertificateManager.ListCertificates":
			inc, _ := in["Includes"].(map[string]any)
			if kt, _ := inc["keyTypes"].([]any); len(kt) < 5 {
				t.Errorf("ListCertificates without all key types: %v", in)
			}
			if in["NextToken"] == nil {
				out = map[string]any{"CertificateSummaryList": []any{map[string]any{"CertificateArn": arnIssued}, map[string]any{"CertificateArn": arnImported}}, "NextToken": "p2"}
			} else {
				out = map[string]any{"CertificateSummaryList": []any{map[string]any{"CertificateArn": arnPending}}}
			}
		case "CertificateManager.DescribeCertificate":
			d := map[string]any{"CertificateArn": in["CertificateArn"], "DomainName": "www.example.test", "NotAfter": exp,
				"SubjectAlternativeNames": []string{"www.example.test", "www.example.test"}}
			switch in["CertificateArn"] {
			case arnIssued:
				d["Type"], d["Status"], d["RenewalEligibility"] = "AMAZON_ISSUED", "ISSUED", "ELIGIBLE"
				d["InUseBy"] = []string{"arn:aws:elasticloadbalancing:us-east-1:111122223333:loadbalancer/app/web/1"}
				d["RenewalSummary"] = map[string]any{"RenewalStatus": "FAILED", "RenewalStatusReason": "CAA_ERROR", "UpdatedAt": exp - 86400*30,
					"DomainValidationOptions": []any{}}
			case arnImported:
				d["Type"], d["Status"], d["RenewalEligibility"] = "IMPORTED", "ISSUED", "INELIGIBLE"
			case arnPending:
				d["Type"], d["Status"] = "AMAZON_ISSUED", "PENDING_VALIDATION"
				d["CreatedAt"] = exp - 86400*400
			}
			out = map[string]any{"Certificate": d}
		case "CertificateManager.GetCertificate":
			if in["CertificateArn"] == arnPending {
				t.Error("GetCertificate called for a certificate that is not issued")
			}
			out = map[string]any{"Certificate": certPEM}
		case "ACMPrivateCA.ListCertificateAuthorities":
			out = map[string]any{"CertificateAuthorities": []any{
				map[string]any{"Arn": "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/root", "Status": "ACTIVE", "NotAfter": time.Unix(int64(exp), 0),
					"CertificateAuthorityConfiguration": map[string]any{"Subject": map[string]any{"CommonName": "Example Root"}}},
				map[string]any{"Arn": "arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/new", "Status": "PENDING_CERTIFICATE"},
			}}
		case "ACMPrivateCA.GetCertificateAuthorityCertificate":
			out = map[string]any{"Certificate": certPEM}
		default:
			w.WriteHeader(http.StatusBadRequest)
			out = map[string]any{"__type": "UnknownOperationException"}
		}
		if cborOp {
			w.Header().Set("Content-Type", "application/cbor")
			w.Header().Set("Smithy-Protocol", "rpc-v2-cbor")
			_, _ = w.Write(cbor.Encode(toCBOR(out)))
			return
		}
		w.Header().Set("Content-Type", "application/x-amz-json-1.1")
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()

	// Static keys through the environment, nothing from the developer's
	// own AWS configuration.
	t.Setenv("AWS_ACCESS_KEY_ID", "AKIDEXAMPLE")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "test-secret")
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	cc := &Config{AWS: []AWSAccountConfig{{Name: "prod", Regions: []string{"us-east-1"}, PrivateCA: true, EndpointURL: srv.URL}}}
	inv := Collect(context.Background(), cc, &Hooks{HTTPClient: srv.Client()}, discard)
	if len(inv.Errors) > 0 {
		t.Fatalf("errors: %+v", inv.Errors)
	}
	acm := objectsBy(inv, agentproto.CloudAWSACM)
	if len(acm) != 3 {
		t.Fatalf("acm objects: %+v", acm)
	}
	is := acm[arnIssued]
	if !is.Managed || is.Renewal != agentproto.RenewalFailed || is.RenewalReason != "CAA_ERROR" || is.ChainPEM == "" ||
		is.NotAfter != "2027-03-01T00:00:00Z" || len(is.InUseBy) != 1 || len(is.DNSNames) != 1 || is.Scope != "prod/us-east-1" {
		t.Errorf("issued: %+v", is)
	}
	if im := acm[arnImported]; im.Managed || im.Renewal != "" {
		t.Errorf("imported: %+v", im)
	}
	if p := acm[arnPending]; p.Renewal != agentproto.RenewalPending || p.ChainPEM != "" || p.RenewalSince == "" {
		t.Errorf("pending: %+v", p)
	}
	pca := objectsBy(inv, agentproto.CloudAWSPCA)
	if root := pca["arn:aws:acm-pca:us-east-1:111122223333:certificate-authority/root"]; !root.CA || root.ChainPEM == "" || root.Name != "Example Root" {
		t.Errorf("pca root: %+v", root)
	}
	if len(pca) != 2 {
		t.Errorf("pca: %+v", pca)
	}
	allowed := map[string]bool{"CertificateManager.ListCertificates": true, "CertificateManager.DescribeCertificate": true,
		"CertificateManager.GetCertificate": true, "ACMPrivateCA.ListCertificateAuthorities": true,
		"ACMPrivateCA.GetCertificateAuthorityCertificate": true}
	for _, c := range log.all() {
		if !allowed[c] {
			t.Errorf("call outside ADR-0024 list: %s", c)
		}
	}
}

// toCBOR builds the CBOR tree for a fake Private CA response; times are
// epoch-seconds tags as in the Smithy protocol.
func toCBOR(v any) cbor.Value {
	switch x := v.(type) {
	case string:
		return cbor.String(x)
	case time.Time:
		return &cbor.Tag{ID: 1, Value: cbor.Float64(float64(x.Unix()))}
	case []any:
		l := cbor.List{}
		for _, e := range x {
			l = append(l, toCBOR(e))
		}
		return l
	case map[string]any:
		m := cbor.Map{}
		for k, e := range x {
			m[k] = toCBOR(e)
		}
		return m
	}
	panic(fmt.Sprintf("toCBOR: %T", v))
}

type staticAzureCred struct{}

func (staticAzureCred) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{Token: "test-token", ExpiresOn: time.Now().Add(time.Hour)}, nil
}

func TestCloudAzureKeyVault(t *testing.T) {
	pemNew, derNew := testPEM(t, "api.example.test")
	_, derOld := testPEM(t, "api.example.test")
	var log callLog
	var base string
	created := func(d int) int64 { return time.Date(2026, 11, d, 0, 0, 0, 0, time.UTC).Unix() }
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.URL.Path)
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", `Bearer authorization="https://login.microsoftonline.com/tenant", resource="https://vault.azure.net"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		p := strings.TrimSuffix(r.URL.Path, "/")
		var out any
		switch p {
		case "/certificates":
			out = map[string]any{"value": []any{
				map[string]any{"id": base + "/certificates/api", "attributes": map[string]any{"enabled": true}},
				map[string]any{"id": base + "/certificates/manual", "attributes": map[string]any{"enabled": true}},
			}}
		case "/certificates/api", "/certificates/api/v2":
			out = map[string]any{"id": base + "/certificates/api/v2", "cer": base64.StdEncoding.EncodeToString(derNew),
				"attributes": map[string]any{"enabled": true, "exp": created(30) + 86400*365},
				"policy": map[string]any{"lifetime_actions": []any{map[string]any{"action": map[string]any{"action_type": "AutoRenew"},
					"trigger": map[string]any{"lifetime_percentage": 80}}},
					"x509_props": map[string]any{"sans": map[string]any{"dns_names": []string{"api.example.test"}}}}}
		case "/certificates/api/v1":
			out = map[string]any{"id": base + "/certificates/api/v1", "cer": base64.StdEncoding.EncodeToString(derOld)}
		case "/certificates/api/versions":
			out = map[string]any{"value": []any{
				map[string]any{"id": base + "/certificates/api/v1", "attributes": map[string]any{"enabled": true, "created": created(1)}},
				map[string]any{"id": base + "/certificates/api/v2", "attributes": map[string]any{"enabled": true, "created": created(20)}},
			}}
		case "/certificates/api/pending":
			w.WriteHeader(http.StatusNotFound)
			out = map[string]any{"error": map[string]any{"code": "CertificateOperationNotFound"}}
		case "/certificates/manual":
			out = map[string]any{"id": base + "/certificates/manual/m1", "attributes": map[string]any{"enabled": true}}
		case "/certificates/manual/pending":
			out = map[string]any{"status": "failed", "error": map[string]any{"code": "Unauthorized", "message": "CA rejected the request"}}
		case "/certificates/manual/versions":
			out = map[string]any{"value": []any{}}
		default:
			w.WriteHeader(http.StatusNotFound)
			out = map[string]any{"error": map[string]any{"code": "NotFound"}}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	base = srv.URL
	cc := &Config{Azure: []AzureConfig{{Name: "corp", Vaults: []string{srv.URL}}}}
	inv := Collect(context.Background(), cc, &Hooks{HTTPClient: srv.Client(), AzureCred: staticAzureCred{}, AzureAnyResource: true}, discard)
	if len(inv.Errors) > 0 {
		t.Fatalf("errors: %+v", inv.Errors)
	}
	kv := objectsBy(inv, agentproto.CloudAzureKeyVault)
	api := kv[srv.URL+"/api"]
	if !api.Managed || api.ChainPEM != pemNew || len(api.DNSNames) != 1 || api.NotAfter == "" {
		t.Errorf("api: %+v", api)
	}
	sum := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
	if len(api.Versions) != 2 || api.Versions[0].ID != "v2" || api.Versions[0].SHA256 != sum(derNew) || api.Versions[1].SHA256 != sum(derOld) {
		t.Errorf("versions: %+v", api.Versions)
	}
	if m := kv[srv.URL+"/manual"]; m.Managed || m.Renewal != agentproto.RenewalFailed || !strings.Contains(m.RenewalReason, "Unauthorized") {
		t.Errorf("manual: %+v", m)
	}
	for _, p := range log.all() {
		if !strings.HasPrefix(p, "/certificates") {
			t.Errorf("call outside the certificates API: %s", p)
		}
	}
}

func TestCloudGCP(t *testing.T) {
	certPEM, _ := testPEM(t, "shop.example.test")
	var log callLog
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.Host + r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer gcp-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		const p = "/v1/projects/shop/locations/global"
		var out any
		switch r.URL.Path {
		case p + "/certificates":
			if r.URL.Query().Get("pageToken") == "" {
				out = map[string]any{"certificates": []any{map[string]any{"name": "projects/shop/locations/global/certificates/web",
					"sanDnsnames": []string{"shop.example.test"}, "pemCertificate": certPEM, "expireTime": "2027-01-02T03:04:05.123456Z",
					"managed": map[string]any{"state": "ACTIVE"}}}, "nextPageToken": "x"}
			} else {
				out = map[string]any{"certificates": []any{map[string]any{"name": "projects/shop/locations/global/certificates/broken",
					"sanDnsnames": []string{"new.example.test"}, "updateTime": "2026-11-01T00:00:00Z",
					"managed": map[string]any{"state": "PROVISIONING", "authorizationAttemptInfo": []any{
						map[string]any{"domain": "new.example.test", "state": "FAILED", "failureReason": "CAA", "details": "CAA forbids"}}}}}}
			}
		case p + "/certificateMaps":
			out = map[string]any{"certificateMaps": []any{map[string]any{"name": "projects/shop/locations/global/certificateMaps/main"}}}
		case p + "/certificateMaps/main/certificateMapEntries":
			out = map[string]any{"certificateMapEntries": []any{map[string]any{"hostname": "shop.example.test",
				"certificates": []string{"projects/shop/locations/global/certificates/web"}}}}
		case p + "/caPools":
			out = map[string]any{"caPools": []any{map[string]any{"name": "projects/shop/locations/global/caPools/pool"}}}
		case p + "/caPools/pool/certificateAuthorities":
			out = map[string]any{"certificateAuthorities": []any{map[string]any{"name": "projects/shop/locations/global/caPools/pool/certificateAuthorities/root",
				"state": "ENABLED", "pemCaCertificates": []string{certPEM}, "expireTime": "2035-01-01T00:00:00Z"}}}
		default:
			w.WriteHeader(http.StatusNotFound)
			out = map[string]any{"error": map[string]any{"status": "NOT_FOUND", "message": "no " + r.URL.Path}}
		}
		_ = json.NewEncoder(w).Encode(out)
	}))
	defer srv.Close()
	cc := &Config{GCP: []GCPConfig{{Name: "shop", Project: "shop", CAS: true}}}
	h := &Hooks{HTTPClient: srv.Client(), GCPTokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "gcp-token"}),
		GCPBase: map[string]string{gcpCertManager: srv.URL, gcpPrivateCA: srv.URL}}
	inv := Collect(context.Background(), cc, h, discard)
	if len(inv.Errors) > 0 {
		t.Fatalf("errors: %+v", inv.Errors)
	}
	cm := objectsBy(inv, agentproto.CloudGCPCertManager)
	web := cm["projects/shop/locations/global/certificates/web"]
	if !web.Managed || web.Renewal != "" || web.NotAfter != "2027-01-02T03:04:05Z" || web.ChainPEM == "" ||
		len(web.InUseBy) != 1 || web.InUseBy[0] != "main: shop.example.test" {
		t.Errorf("web: %+v", web)
	}
	if b := cm["projects/shop/locations/global/certificates/broken"]; b.Renewal != agentproto.RenewalFailed || !strings.Contains(b.RenewalReason, "CAA") {
		t.Errorf("broken: %+v", b)
	}
	if cas := objectsBy(inv, agentproto.CloudGCPCAS); len(cas) != 1 {
		t.Errorf("cas: %+v", cas)
	}
}

func TestCloudGCPScopeErrorDoesNotStopOthers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"status":"PERMISSION_DENIED","message":"denied"}}`))
	}))
	defer srv.Close()
	cc := &Config{GCP: []GCPConfig{{Name: "a", Project: "a", Locations: []string{"global", "europe-west1"}}}}
	h := &Hooks{HTTPClient: srv.Client(), GCPTokens: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "t"}),
		GCPBase: map[string]string{gcpCertManager: srv.URL}}
	inv := Collect(context.Background(), cc, h, discard)
	if len(inv.Errors) != 2 || inv.Errors[1].Scope != "a/europe-west1" || !strings.Contains(inv.Errors[0].Error, "PERMISSION_DENIED") {
		t.Fatalf("errors: %+v", inv.Errors)
	}
}

func TestCloudflare(t *testing.T) {
	originPEM, _ := testPEM(t, "origin.example.test")
	var log callLog
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.add(r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer cf-token" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}]}`))
			return
		}
		res := func(v any, pages int) {
			_ = json.NewEncoder(w).Encode(map[string]any{"success": true, "result": v, "result_info": map[string]any{"total_pages": pages}})
		}
		switch r.URL.Path {
		case "/zones":
			if r.URL.Query().Get("name") != "example.test" {
				t.Errorf("zone lookup: %s", r.URL.RawQuery)
			}
			res([]any{map[string]any{"id": "z1", "name": "example.test"}}, 1)
		case "/zones/z1/ssl/certificate_packs":
			if r.URL.Query().Get("status") != "all" {
				t.Errorf("packs without status=all")
			}
			if r.URL.Query().Get("page") == "1" {
				res([]any{map[string]any{"id": "p1", "type": "universal", "status": "active", "hosts": []string{"example.test", "*.example.test"},
					"primary_certificate": "c2", "certificates": []any{
						map[string]any{"id": "c1", "expires_on": "2027-01-01T00:00:00Z"},
						map[string]any{"id": "c2", "expires_on": "2027-02-01T00:00:00Z"}}}}, 2)
			} else {
				res([]any{map[string]any{"id": "p2", "type": "advanced", "status": "validation_timed_out", "hosts": []string{"new.example.test"}}}, 2)
			}
		case "/certificates":
			if r.URL.Query().Get("zone_id") != "z1" {
				t.Errorf("origin ca query: %s", r.URL.RawQuery)
			}
			res([]any{map[string]any{"id": "o1", "certificate": originPEM, "hostnames": []string{"origin.example.test"},
				"expires_on": "2041-01-01 00:00:00 +0000 UTC"}}, 1)
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"success":false}`))
		}
	}))
	defer srv.Close()
	tok := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(tok, []byte("cf-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cc := &Config{Cloudflare: []CloudflareConfig{{Name: "main", APITokenFile: tok, Zones: []string{"example.test"}, OriginCA: true, APIURL: srv.URL}}}
	inv := Collect(context.Background(), cc, &Hooks{HTTPClient: srv.Client()}, discard)
	if len(inv.Errors) > 0 {
		t.Fatalf("errors: %+v", inv.Errors)
	}
	edge := objectsBy(inv, agentproto.CloudCloudflareEdge)
	if p := edge["example.test/p1"]; !p.Managed || p.NotAfter != "2027-02-01T00:00:00Z" || p.Renewal != "" || len(p.DNSNames) != 2 {
		t.Errorf("p1: %+v", p)
	}
	if p := edge["example.test/p2"]; p.Renewal != agentproto.RenewalFailed {
		t.Errorf("p2: %+v", p)
	}
	o := objectsBy(inv, agentproto.CloudCloudflareOrigin)["example.test/o1"]
	if !o.NotPubliclyTrusted || o.ChainPEM == "" || o.NotAfter != "2041-01-01T00:00:00Z" {
		t.Errorf("origin: %+v", o)
	}
}

func TestCloudConfigValidation(t *testing.T) {
	bad := []Config{
		{},
		{IntervalSeconds: 60, AWS: []AWSAccountConfig{{Name: "a", Regions: []string{"us-east-1"}}}},
		{AWS: []AWSAccountConfig{{Name: "a"}}},
		{AWS: []AWSAccountConfig{{Name: "a", Regions: []string{"x"}, EndpointURL: "http://acm.example.test"}}},
		{AWS: []AWSAccountConfig{{Name: "a", Regions: []string{"x"}}, {Name: "a", Regions: []string{"y"}}}},
		{Azure: []AzureConfig{{Name: "z", Vaults: []string{"http://v.vault.azure.net"}}}},
		{Azure: []AzureConfig{{Name: "z", Vaults: []string{"https://v.vault.azure.net"}, ClientSecretFile: "/s"}}},
		{GCP: []GCPConfig{{Name: "g"}}},
		{Cloudflare: []CloudflareConfig{{Name: "c", APITokenFile: "token"}}},
	}
	for i, cc := range bad {
		if len(cc.Validate()) == 0 {
			t.Errorf("case %d accepted: %+v", i, cc)
		}
	}
	good := &Config{AWS: []AWSAccountConfig{{Name: "a", Regions: []string{"eu-west-1"}}}}
	if p := good.Validate(); len(p) > 0 {
		t.Errorf("good config rejected: %v", p)
	}
}
