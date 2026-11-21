// Package e2e runs the monitoring scenarios against real binaries, a real
// PostgreSQL and a real Nginx container.
//
// Requirements: CERTLOOM_TEST_DATABASE_URL (see internal/store/storetest) and a
// working `docker` CLI. The test is skipped when either is missing.
package e2e

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/notify"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
	"github.com/alexandrosnt/certloom/internal/testpki"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

const nginxImage = "nginx:1.29-alpine"

var binDir string

func TestMain(m *testing.M) {
	if os.Getenv(storetest.EnvURL) == "" {
		fmt.Println("skipping e2e: " + storetest.EnvURL + " not set")
		os.Exit(0)
	}
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Println("skipping e2e: docker not found")
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "certloom-e2e-bin")
	if err != nil {
		panic(err)
	}
	binDir = dir
	root, _ := filepath.Abs("../..")
	build := exec.Command("go", "build", "-o", dir+string(os.PathSeparator), "./cmd/certloom", "./cmd/certloomd")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Printf("build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

func bin(name string) string {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(binDir, name)
}

// ---------- environment helpers ----------

type env struct {
	t      *testing.T
	server string
	cfg    string
	token  string
	dbURL  string
	// ownerURL is the schema-owner connection (for pg_dump).
	ownerURL string
	// logPath holds certloomd's combined output (debug level), for log scanning.
	logPath string
}

// logText returns everything certloomd has logged so far.
func (e *env) logText() string {
	b, _ := os.ReadFile(e.logPath)
	return string(b)
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// startServer runs certloomd serve and bootstraps an org.
func startServer(t *testing.T, extraEnv ...string) *env {
	return startServerFn(t, func(string) []string { return extraEnv })
}

// startServerFn is startServer with environment computed from the server URL
// (needed for OIDC redirect URLs).
func startServerFn(t *testing.T, envFn func(serverURL string) []string) *env {
	db := storetest.New(t)
	port := freePort(t)
	e := &env{t: t, server: fmt.Sprintf("http://127.0.0.1:%d", port), cfg: filepath.Join(t.TempDir(), "certloom.json"),
		dbURL: db.AppURL, ownerURL: db.OwnerURL}

	boot := exec.Command(bin("certloomd"), "bootstrap", "--org", "e2e")
	boot.Env = append(os.Environ(), "CERTLOOM_DATABASE_URL="+db.AppURL)
	var stdout bytes.Buffer
	boot.Stdout = &stdout
	boot.Stderr = io.Discard
	if err := boot.Run(); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	e.token = strings.TrimSpace(stdout.String())

	logPath := filepath.Join(t.TempDir(), "certloomd.log")
	e.logPath = logPath
	logf, _ := os.Create(logPath)
	srv := exec.Command(bin("certloomd"), "serve")
	srv.Env = append(os.Environ(), "CERTLOOM_DATABASE_URL="+db.AppURL, fmt.Sprintf("CERTLOOM_LISTEN=127.0.0.1:%d", port), "CERTLOOM_LOG_LEVEL=debug")
	srv.Env = append(srv.Env, envFn(e.server)...)
	srv.Stdout, srv.Stderr = logf, logf
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = srv.Process.Kill()
		_, _ = srv.Process.Wait()
		logf.Close()
		if t.Failed() {
			b, _ := os.ReadFile(logPath)
			t.Logf("certloomd log:\n%s", tail(string(b), 60))
		}
	})
	waitFor(t, 20*time.Second, "certloomd ready", func() bool {
		resp, err := http.Get(e.server + "/readyz")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == 200
	})
	login := exec.Command(bin("certloom"), "login", "--server", e.server, "--token-stdin")
	login.Env = append(os.Environ(), "CERTLOOM_CONFIG="+e.cfg)
	login.Stdin = strings.NewReader(e.token + "\n")
	if out, err := login.CombinedOutput(); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	return e
}

func tail(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return strings.Join(lines, "\n")
}

// certloom runs the CLI; it fails the test on a non-zero exit unless wantExit is given.
func (e *env) cli(stdin string, args ...string) (string, int) {
	e.t.Helper()
	cmd := exec.Command(bin("certloom"), args...)
	cmd.Env = append(os.Environ(), "CERTLOOM_CONFIG="+e.cfg)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	code := 0
	if ee := (*exec.ExitError)(nil); errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		e.t.Fatalf("certloom %v: %v", args, err)
	}
	return out.String() + errb.String(), code
}

func (e *env) mustCLI(args ...string) string {
	e.t.Helper()
	out, code := e.cli("", args...)
	if code != 0 {
		e.t.Fatalf("certloom %s: exit %d\n%s", strings.Join(args, " "), code, out)
	}
	return out
}

func (e *env) jsonCLI(v any, args ...string) {
	e.t.Helper()
	out := e.mustCLI(append([]string{"-o", "json"}, args...)...)
	if err := json.Unmarshal([]byte(out), v); err != nil {
		e.t.Fatalf("certloom %v: bad json: %v\n%s", args, err, out)
	}
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(300 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// ---------- nginx ----------

type nginx struct {
	t    *testing.T
	id   string
	dir  string
	Port int
}

const nginxConf = `server {
    listen 443 ssl;
    server_name www.e2e.test;
    ssl_certificate     /etc/nginx/conf.d/www.chain.pem;
    ssl_certificate_key /etc/nginx/conf.d/www.key;
    return 200 "ok\n";
}
server {
    listen 443 ssl default_server;
    server_name api.e2e.test;
    ssl_certificate     /etc/nginx/conf.d/api.chain.pem;
    ssl_certificate_key /etc/nginx/conf.d/api.key;
    return 200 "ok\n";
}
`

func startNginx(t *testing.T, www, api []*testpki.Cert) *nginx {
	dir := t.TempDir()
	n := &nginx{t: t, dir: dir}
	n.writeCert("www", www)
	n.writeCert("api", api)
	if err := os.WriteFile(filepath.Join(dir, "default.conf"), []byte(nginxConf), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("docker", "run", "-d", "--rm", "-p", "127.0.0.1::443", "-v", dir+":/etc/nginx/conf.d:ro", nginxImage).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run nginx: %v\n%s", err, out)
	}
	n.id = strings.TrimSpace(string(out))
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", n.id).Run() })
	pout, err := exec.Command("docker", "port", n.id, "443/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	_, p, _ := net.SplitHostPort(strings.TrimSpace(strings.Split(string(pout), "\n")[0]))
	fmt.Sscan(p, &n.Port)
	waitFor(t, 20*time.Second, "nginx up", func() bool {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", n.Port), time.Second)
		if err != nil {
			return false
		}
		c.Close()
		return true
	})
	return n
}

// writeCert writes leaf+chain and the key for a vhost.
func (n *nginx) writeCert(name string, chain []*testpki.Cert) {
	var b []byte
	for _, c := range chain {
		b = append(b, c.PEM()...)
	}
	must(n.t, os.WriteFile(filepath.Join(n.dir, name+".chain.pem"), b, 0o644))
	must(n.t, os.WriteFile(filepath.Join(n.dir, name+".key"), chain[0].KeyPEM(n.t), 0o644))
}

func (n *nginx) reload() {
	if out, err := exec.Command("docker", "exec", n.id, "nginx", "-s", "reload").CombinedOutput(); err != nil {
		n.t.Fatalf("nginx reload: %v\n%s", err, out)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// ---------- webhook receiver ----------

type hook struct {
	mu     sync.Mutex
	events []map[string]any
	badSig int
}

func (h *hook) handler(secret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		defer h.mu.Unlock()
		if r.Header.Get("X-Certloom-Signature") != notify.Sign([]byte(secret), body) {
			h.badSig++
			w.WriteHeader(401)
			return
		}
		var m map[string]any
		_ = json.Unmarshal(body, &m)
		h.events = append(h.events, m)
	}
}

func (h *hook) find(event, check string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.events {
		if e["event"] == event && (check == "" || e["check"] == check) {
			return true
		}
	}
	return false
}

// ---------- the scenario ----------

func TestMonitoringEndToEnd(t *testing.T) {
	if out, err := exec.Command("docker", "image", "inspect", nginxImage).CombinedOutput(); err != nil {
		if pout, perr := exec.Command("docker", "pull", nginxImage).CombinedOutput(); perr != nil {
			t.Skipf("cannot pull %s: %v\n%s\n%s", nginxImage, perr, out, pout)
		}
	}

	// PKI: one private root with an intermediate, trusted by certloomd via CERTLOOM_TRUST_BUNDLE.
	root := testpki.Issue(t, nil, testpki.Options{CommonName: "e2e root", IsCA: true, NotAfter: time.Now().Add(5 * 365 * 24 * time.Hour)})
	inter := testpki.Issue(t, root, testpki.Options{CommonName: "e2e intermediate", IsCA: true, NotAfter: time.Now().Add(3 * 365 * 24 * time.Hour)})
	wwwV1 := testpki.Issue(t, inter, testpki.Options{CommonName: "www.e2e.test", DNSNames: []string{"www.e2e.test"}})
	wwwV2 := testpki.Issue(t, inter, testpki.Options{CommonName: "www.e2e.test", DNSNames: []string{"www.e2e.test"}})
	// api serves a certificate that is expiring in 3 days and lacks its intermediate.
	apiCert := testpki.Issue(t, inter, testpki.Options{CommonName: "api.e2e.test", DNSNames: []string{"api.e2e.test"},
		NotBefore: time.Now().Add(-80 * 24 * time.Hour), NotAfter: time.Now().Add(3 * 24 * time.Hour)})

	trust := filepath.Join(t.TempDir(), "trust.pem")
	must(t, os.WriteFile(trust, root.PEM(), 0o644))

	const hookSecret = "e2e-webhook-secret"
	h := &hook{}
	hs := httptest.NewServer(h.handler(hookSecret))
	defer hs.Close()

	auditFile := filepath.Join(t.TempDir(), "audit.jsonl")
	e := startServer(t, "CERTLOOM_TRUST_BUNDLE="+trust, "CERTLOOM_E2E_HOOK_SECRET="+hookSecret, "CERTLOOM_AUDIT_EXPORT=file:"+auditFile)
	ngx := startNginx(t, []*testpki.Cert{wwwV1, inter}, []*testpki.Cert{apiCert})

	t.Run("import the same certificate as PEM, DER and PFX gives one identity", func(t *testing.T) {
		dir := t.TempDir()
		pemF, derF, pfxF, pwF := filepath.Join(dir, "c.pem"), filepath.Join(dir, "c.der"), filepath.Join(dir, "c.pfx"), filepath.Join(dir, "pw")
		must(t, os.WriteFile(pemF, append(wwwV1.PEM(), inter.PEM()...), 0o600))
		must(t, os.WriteFile(derF, wwwV1.DER, 0o600))
		pfx, err := pkcs12.Modern.Encode(wwwV1.Key, wwwV1.Cert, []*x509.Certificate{inter.Cert}, "pfx-pass")
		must(t, err)
		must(t, os.WriteFile(pfxF, pfx, 0o600))
		must(t, os.WriteFile(pwF, []byte("pfx-pass\n"), 0o600))

		e.mustCLI("inventory", "import", pemF, "--lineage", "www-prod")
		e.mustCLI("inventory", "import", derF)
		out := e.mustCLI("inventory", "import", pfxF, "--password-file", pwF)
		if !strings.Contains(out, "0 new") || !strings.Contains(out, "discarded") {
			t.Fatalf("PFX import should add nothing new and report the key was discarded:\n%s", out)
		}
		var list struct {
			Items []struct {
				SHA256 string `json:"sha256"`
			} `json:"items"`
		}
		e.jsonCLI(&list, "inventory", "list", "--include-ca")
		if len(list.Items) != 2 { // leaf + intermediate
			t.Fatalf("want 2 certificates (leaf, intermediate), got %d", len(list.Items))
		}
		// A dry run stores nothing.
		dry := filepath.Join(dir, "dry.pem")
		must(t, os.WriteFile(dry, apiCert.PEM(), 0o600))
		e.mustCLI("inventory", "import", dry, "--dry-run")
		e.jsonCLI(&list, "inventory", "list", "--include-ca")
		if len(list.Items) != 2 {
			t.Fatalf("dry run stored data: %d certificates", len(list.Items))
		}
	})

	t.Run("probe scope denies loopback by default", func(t *testing.T) {
		e.mustCLI("scope", "create", "default-deny", "--port", fmt.Sprint(ngx.Port))
		out, code := e.cli("", "endpoint", "add", "127.0.0.1", "--port", fmt.Sprint(ngx.Port), "--scope", "default-deny")
		if code != 6 || !strings.Contains(out, "loopback") {
			t.Fatalf("want exit 6 (invalid) mentioning loopback, got %d:\n%s", code, out)
		}
	})

	e.mustCLI("scope", "create", "lab", "--allow-loopback", "--port", fmt.Sprint(ngx.Port))
	chOut := e.mustCLI("channel", "create-webhook", "hook", "--url", hs.URL, "--allow-private",
		"--secret-ref", "env:CERTLOOM_E2E_HOOK_SECRET", "--min-severity", "warning")
	_ = chOut

	var www, api struct {
		ID string `json:"id"`
	}
	e.jsonCLI(&www, "endpoint", "add", "127.0.0.1", "--port", fmt.Sprint(ngx.Port), "--sni", "www.e2e.test", "--scope", "lab", "--lineage", "www-prod")
	e.jsonCLI(&api, "endpoint", "add", "127.0.0.1", "--port", fmt.Sprint(ngx.Port), "--sni", "api.e2e.test", "--scope", "lab")

	type obs struct {
		LastLeaf *string `json:"last_leaf_sha256"`
		Findings []struct {
			Check, Severity string
		} `json:"findings"`
	}
	show := func(id string) obs {
		var o obs
		e.jsonCLI(&o, "endpoint", "show", id)
		return o
	}
	has := func(o obs, check, sev string) bool {
		for _, f := range o.Findings {
			if f.Check == check && (sev == "" || f.Severity == sev) {
				return true
			}
		}
		return false
	}
	fp := func(c *testpki.Cert) string {
		b, _ := pem.Decode(c.PEM())
		x, _ := x509.ParseCertificate(b.Bytes)
		return certFP(x)
	}

	t.Run("probe captures the served chain per SNI", func(t *testing.T) {
		waitFor(t, 30*time.Second, "first www observation", func() bool { o := show(www.ID); return o.LastLeaf != nil })
		if o := show(www.ID); *o.LastLeaf != fp(wwwV1) || len(o.Findings) != 0 {
			t.Fatalf("www: leaf %v findings %+v", *o.LastLeaf, o.Findings)
		}
		waitFor(t, 30*time.Second, "api findings", func() bool { o := show(api.ID); return has(o, "expiry", "critical") })
		o := show(api.ID)
		if *o.LastLeaf != fp(apiCert) || !has(o, "chain_incomplete", "warning") {
			t.Fatalf("api: expected expiry critical + chain_incomplete warning, got %+v", o.Findings)
		}
	})

	t.Run("alerts are delivered to the webhook, signed", func(t *testing.T) {
		waitFor(t, 30*time.Second, "webhook expiry alert", func() bool { return h.find("finding.opened", "expiry") })
		if h.badSig != 0 {
			t.Fatalf("%d webhook deliveries had bad signatures", h.badSig)
		}
	})

	t.Run("swapping the served certificate is detected as lineage mismatch", func(t *testing.T) {
		ngx.writeCert("www", []*testpki.Cert{wwwV2, inter})
		ngx.reload()
		e.mustCLI("endpoint", "probe", www.ID)
		waitFor(t, 30*time.Second, "lineage mismatch", func() bool { return has(show(www.ID), "lineage_mismatch", "critical") })
		o := show(www.ID)
		if *o.LastLeaf != fp(wwwV2) || !has(o, "fingerprint_changed", "warning") {
			t.Fatalf("after swap: %+v", o)
		}
		var metrics []struct {
			Key   string
			Value int
		}
		e.jsonCLI(&metrics, "status")
		for _, m := range metrics {
			if m.Key == "endpoint_mismatch" && m.Value != 1 {
				t.Fatalf("overview endpoint_mismatch = %d, want 1", m.Value)
			}
		}
		waitFor(t, 30*time.Second, "webhook lineage alert", func() bool { return h.find("finding.opened", "lineage_mismatch") })
	})

	t.Run("updating the lineage resolves the mismatch and notifies resolution", func(t *testing.T) {
		dir := t.TempDir()
		f := filepath.Join(dir, "v2.pem")
		must(t, os.WriteFile(f, wwwV2.PEM(), 0o600))
		e.mustCLI("inventory", "import", f, "--lineage", "www-prod")
		e.mustCLI("endpoint", "probe", www.ID)
		waitFor(t, 30*time.Second, "mismatch resolved", func() bool {
			o := show(www.ID)
			return !has(o, "lineage_mismatch", "") && *o.LastLeaf == fp(wwwV2)
		})
		waitFor(t, 30*time.Second, "webhook resolution", func() bool { return h.find("finding.resolved", "lineage_mismatch") })
	})

	t.Run("viewer tokens cannot mutate", func(t *testing.T) {
		var tok struct{ Secret string }
		e.jsonCLI(&tok, "token", "create", "ro", "--role", "viewer")
		cfg := filepath.Join(t.TempDir(), "viewer.json")
		cmd := exec.Command(bin("certloom"), "endpoint", "add", "127.0.0.1", "--scope", "lab", "--port", fmt.Sprint(ngx.Port))
		cmd.Env = append(os.Environ(), "CERTLOOM_CONFIG="+cfg, "CERTLOOM_SERVER="+e.server, "CERTLOOM_TOKEN="+tok.Secret)
		out, _ := cmd.CombinedOutput()
		if cmd.ProcessState.ExitCode() != 5 {
			t.Fatalf("viewer mutation: want exit 5 (forbidden), got %d\n%s", cmd.ProcessState.ExitCode(), out)
		}
	})

	t.Run("audit trail is complete and verifies", func(t *testing.T) {
		var events []struct{ Action string }
		e.jsonCLI(&events, "audit", "query", "--limit", "1000")
		want := []string{"org.bootstrap", "certificates.import", "lineages.create", "lineages.set_current", "scopes.create",
			"channels.create", "endpoints.create", "endpoints.probe_requested", "tokens.create"}
		got := map[string]bool{}
		for _, ev := range events {
			got[ev.Action] = true
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("audit missing action %q", w)
			}
		}
		out := e.mustCLI("audit", "verify")
		if !strings.Contains(out, "consistent") {
			t.Fatalf("audit verify: %s", out)
		}
	})

	t.Run("no secret material in the database", func(t *testing.T) {
		// Private keys, the PFX password, the webhook secret and the raw tokens must never be stored.
		needles := map[string]string{
			"pfx password":   "pfx-pass",
			"webhook secret": hookSecret,
			"owner token":    e.token[len(e.token)-20:],
		}
		keyPEM := string(wwwV1.KeyPEM(t))
		needles["private key (base64)"] = strings.Split(keyPEM, "\n")[1][:40]
		// The private scalar itself, hex-encoded as a bytea column would dump.
		// (Not the PKCS#8 tail: that embeds the public key, which is legitimately
		// present in every stored certificate.)
		ec, ok := wwwV1.Key.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatal("expected an ECDSA test key")
		}
		scalar, err := ec.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		needles["private key (hex scalar)"] = hex.EncodeToString(scalar)
		dump := dockerPG(t, pgClientImage(t), nil, e.ownerURL, "pg_dump")
		// Positive control: the dump must contain known public data, or the search proves nothing.
		if !bytes.Contains(dump, []byte("www.e2e.test")) || !bytes.Contains(dump, []byte("certificates.import")) {
			t.Fatalf("positive control failed: dump (%d bytes) lacks expected public data", len(dump))
		}
		for what, n := range needles {
			if bytes.Contains(dump, []byte(n)) {
				t.Errorf("%s found in database dump", what)
			}
		}
	})

	t.Run("no secret material in server logs (debug level)", func(t *testing.T) {
		logs := e.logText()
		if !strings.Contains(logs, `"msg":"listening"`) || !strings.Contains(logs, "scheduled probes") {
			t.Fatalf("positive control failed: expected startup and debug lines in log (%d bytes)", len(logs))
		}
		keyPEM := string(wwwV1.KeyPEM(t))
		for what, n := range map[string]string{
			"pfx password": "pfx-pass", "webhook secret": hookSecret, "owner token": e.token[len(e.token)-20:],
			"private key": strings.Split(keyPEM, "\n")[1][:40],
		} {
			if strings.Contains(logs, n) {
				t.Errorf("%s found in certloomd log", what)
			}
		}
	})

	t.Run("external audit export matches the database", func(t *testing.T) {
		waitFor(t, 20*time.Second, "audit export caught up", func() bool {
			var st []struct {
				Lag int64 `json:"lag"`
			}
			e.jsonCLI(&st, "audit", "export-status")
			return len(st) == 1 && st[0].Lag == 0
		})
		cmd := exec.Command(bin("certloomd"), "audit-verify-export", auditFile, "--compare")
		cmd.Env = append(os.Environ(), "CERTLOOM_DATABASE_URL="+e.dbURL)
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "database matches export") {
			t.Fatalf("audit-verify-export: %v\n%s", err, out)
		}
	})
}
