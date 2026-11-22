// Package acme runs a full renewal against real services: ACME issuance from Pebble with real
// HTTP-01 validation against Nginx, a real certloom-agent next to Nginx, a real
// certloomd, all on a private Docker network, driven by the real certloom CLI.
//
// Requires only Docker. Set CERTLOOM_ACME_E2E=1 to run (it pulls images and takes
// a minute or two).
package acme

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/testpki"
)

const (
	pgImage     = "postgres:18-alpine"
	pebbleImage = "ghcr.io/letsencrypt/pebble:latest"
	nginxImage  = "nginx:1.29-alpine"
	runImage    = "gcr.io/distroless/static-debian12:nonroot"
)

var linuxBin, hostBin string

// e2eVersion is stamped into the Linux binaries the same way deploy/packaging/build.sh does.
const e2eVersion = "0.0.0-e2e"

func TestMain(m *testing.M) {
	if os.Getenv("CERTLOOM_ACME_E2E") == "" {
		fmt.Println("skipping ACME e2e: set CERTLOOM_ACME_E2E=1")
		os.Exit(0)
	}
	root, _ := filepath.Abs("../..")
	linuxBin, _ = os.MkdirTemp("", "certloom-acme-linux")
	hostBin, _ = os.MkdirTemp("", "certloom-acme-host")
	b := exec.Command("go", "build", "-ldflags", "-X github.com/alexandrosnt/certloom/internal/version.Version="+e2eVersion,
		"-o", linuxBin+"/", "./cmd/certloomd", "./cmd/certloom-agent", "./test/acme/hookrecv")
	b.Dir, b.Env = root, append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if out, err := b.CombinedOutput(); err != nil {
		fmt.Printf("linux build: %v\n%s", err, out)
		os.Exit(1)
	}
	// certloom-plugin is its own module (ADR-0027) and goes into the agent package.
	p := exec.Command("go", "build", "-ldflags", "-X github.com/alexandrosnt/certloom/internal/version.Version="+e2eVersion,
		"-o", linuxBin+"/certloom-plugin", ".")
	p.Dir, p.Env = filepath.Join(root, "cmd", "certloom-plugin"), b.Env
	if out, err := p.CombinedOutput(); err != nil {
		fmt.Printf("linux build of certloom-plugin: %v\n%s", err, out)
		os.Exit(1)
	}
	h := exec.Command("go", "build", "-o", hostBin+string(os.PathSeparator), "./cmd/certloom")
	h.Dir = root
	if out, err := h.CombinedOutput(); err != nil {
		fmt.Printf("host build: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(linuxBin)
	_ = os.RemoveAll(hostBin)
	os.Exit(code)
}

func rnd(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func docker(t *testing.T, stdin string, args ...string) string {
	t.Helper()
	cmd := exec.Command("docker", args...)
	cmd.Stdin = strings.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker %s: %v\n%s%s", strings.Join(args, " "), err, out.String(), errb.String())
	}
	return strings.TrimSpace(out.String())
}

func tryDocker(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Second)
	}
	t.Fatalf("timed out after %s waiting for %s", d, what)
}

func mount(src, dst string) string { return src + ":" + dst + ":ro" }

const nginxConf = `server {
    listen 80;
    server_name www.m2.test;
    location /.well-known/acme-challenge/ { root /var/www/acme; }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl;
    server_name www.m2.test;
    ssl_certificate     /etc/certloom/live/www/fullchain.pem;
    ssl_certificate_key /etc/certloom/live/www/privkey.pem;
    return 200 "ok\n";
}
`

const agentConfig = `server: https://certloomd:8444
state_dir: /var/lib/certloom-agent
name: web
acme_ca_file: /m2/pebble.minica.pem
targets:
  - name: www
    type: nginx
    live_link: /etc/certloom/live/www
    webroot: /var/www/acme
    test_command: [nginx, -t]
    reload_command: [nginx, -s, reload]
    verify_address: 127.0.0.1:443
    allowed_sans: [www.m2.test]
`

const pebbleConfig = `{"pebble": {"listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
 "certificate": "test/certs/localhost/cert.pem", "privateKey": "test/certs/localhost/key.pem",
 "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": false,
 "retryAfter": {"authz": 1, "order": 1}, "keyAlgorithm": "ecdsa",
 "profiles": {"default": {"description": "default", "validityPeriod": 7776000}}}}`

type stack struct {
	t         *testing.T
	net       string
	nginx     string
	certloomd string
	cfg       string
	apiURL    string
	tmp       string
	ownerTok  string
	// agentLog is the command (run in the web container) that prints the
	// agent's log on failure; nil means the default /tmp/agent.log.
	agentLog []string
}

// webStarter starts the container serving www.m2.test (nginx + certloom-agent) and
// returns its ID. run starts a container on the stack's network under the
// given alias; m2 and boot are host directories with the shared files and the
// bootstrap certificate.
type webStarter func(s *stack, run func(name string, args ...string) string, m2, boot string) string

func (s *stack) cli(args ...string) (string, error) {
	cmd := exec.Command(filepath.Join(hostBin, "certloom"+exe()), args...)
	cmd.Env = append(os.Environ(), "CERTLOOM_CONFIG="+s.cfg)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *stack) mustCLI(args ...string) string {
	s.t.Helper()
	out, err := s.cli(args...)
	if err != nil {
		s.t.Fatalf("certloom %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

func (s *stack) jsonCLI(v any, args ...string) {
	s.t.Helper()
	out := s.mustCLI(append([]string{"-o", "json"}, args...)...)
	if err := json.Unmarshal([]byte(out), v); err != nil {
		s.t.Fatalf("certloom %v: %v\n%s", args, err, out)
	}
}

func exe() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

func (s *stack) logs() {
	for _, c := range []string{s.certloomd, s.nginx} {
		if c == "" {
			continue
		}
		out, _ := tryDocker("logs", "--tail", "60", c)
		s.t.Logf("---- %s logs ----\n%s", c, out)
	}
	if s.nginx != "" {
		cmd := s.agentLog
		if cmd == nil {
			cmd = []string{"tail", "-n", "60", "/tmp/agent.log"}
		}
		out, _ := tryDocker(append([]string{"exec", s.nginx}, cmd...)...)
		s.t.Logf("---- agent log ----\n%s", out)
	}
	if s.certloomd != "" {
		deps, _ := s.cli("deployment", "list")
		runs, _ := s.cli("run", "list")
		s.t.Logf("---- deployments ----\n%s\n---- runs ----\n%s", deps, runs)
	}
}

// up starts the stack. By default the web container is nginx:alpine with the
// agent binary mounted at /certloom; pass a webStarter to replace it.
func up(t *testing.T, web ...webStarter) *stack {
	return upWith(t, upOptions{}, web...)
}

// upOptions changes the default stack.
type upOptions struct {
	agentConfig  string   // replaces agentConfig
	pebbleArgs   []string // extra Pebble flags
	pebbleConfig string   // replaces pebbleConfig
	// before starts extra containers before Pebble; m2 is the shared directory.
	before func(run func(name string, args ...string) string, m2 string)
}

func upWith(t *testing.T, o upOptions, web ...webStarter) *stack {
	for _, img := range []string{pgImage, pebbleImage, nginxImage, runImage} {
		if _, err := tryDocker("image", "inspect", img); err != nil {
			if out, err := tryDocker("pull", img); err != nil {
				t.Skipf("cannot pull %s: %v\n%s", img, err, out)
			}
		}
	}
	id := rnd(4)
	s := &stack{t: t, net: "certloom-acme-" + id, tmp: t.TempDir()}
	s.cfg = filepath.Join(s.tmp, "certloom.json")
	docker(t, "", "network", "create", s.net)
	var containers []string
	t.Cleanup(func() {
		if t.Failed() {
			s.logs()
		}
		for _, c := range containers {
			_, _ = tryDocker("rm", "-f", c)
		}
		_, _ = tryDocker("network", "rm", s.net)
	})
	run := func(name string, args ...string) string {
		full := append([]string{"run", "-d", "--name", name + "-" + id, "--network", s.net, "--network-alias", name}, args...)
		c := docker(t, "", full...)
		containers = append(containers, c)
		return c
	}

	// Files shared into containers.
	m2 := filepath.Join(s.tmp, "m2")
	_ = os.MkdirAll(m2, 0o755)
	write := func(name, data string) { _ = os.WriteFile(filepath.Join(m2, name), []byte(data), 0o644) }
	if o.pebbleConfig == "" {
		o.pebbleConfig = pebbleConfig
	}
	write("pebble.json", o.pebbleConfig)
	write("nginx.conf", nginxConf)
	if o.agentConfig == "" {
		o.agentConfig = agentConfig
	}
	write("agent.yaml", o.agentConfig)
	cid := docker(t, "", "create", pebbleImage)
	docker(t, "", "cp", cid+":/test/certs/pebble.minica.pem", filepath.Join(m2, "pebble.minica.pem"))
	docker(t, "", "rm", cid)
	// A bootstrap certificate so nginx can start before the first renewal.
	boot := testpki.Issue(t, nil, testpki.Options{CommonName: "www.m2.test", DNSNames: []string{"www.m2.test"}})
	bootDir := filepath.Join(s.tmp, "boot")
	_ = os.MkdirAll(bootDir, 0o755)
	_ = os.WriteFile(filepath.Join(bootDir, "fullchain.pem"), boot.PEM(), 0o644)
	_ = os.WriteFile(filepath.Join(bootDir, "privkey.pem"), boot.KeyPEM(t), 0o644)
	_ = os.WriteFile(filepath.Join(s.tmp, "boot.pem"), boot.PEM(), 0o644)

	pgPass := rnd(12)
	pg := run("db", "-e", "POSTGRES_USER=certloom_owner", "-e", "POSTGRES_PASSWORD="+pgPass, "-e", "POSTGRES_DB=certloom", pgImage)
	waitFor(t, 60*time.Second, "postgres", func() bool {
		_, err := tryDocker("exec", pg, "pg_isready", "-U", "certloom_owner", "-d", "certloom")
		return err == nil
	})
	time.Sleep(2 * time.Second) // initdb restarts the server once after the first ready signal
	waitFor(t, 30*time.Second, "postgres after init", func() bool {
		_, err := tryDocker("exec", pg, "psql", "-U", "certloom_owner", "-d", "certloom", "-c", "select 1")
		return err == nil
	})
	docker(t, "", "run", "--rm", "--network", s.net, "-v", mount(linuxBin, "/certloom"), "-e",
		"CERTLOOM_MIGRATE_DATABASE_URL=postgres://certloom_owner:"+pgPass+"@db:5432/certloom?sslmode=disable", runImage, "/certloom/certloomd", "migrate")
	appPass := rnd(12)
	docker(t, "", "exec", pg, "psql", "-U", "certloom_owner", "-d", "certloom", "-c", "ALTER ROLE certloom_app LOGIN PASSWORD '"+appPass+"'")

	if o.before != nil {
		o.before(run, m2)
	}
	run("pebble", append([]string{"-v", mount(m2, "/m2"), "-e", "PEBBLE_VA_NOSLEEP=1", pebbleImage, "-config", "/m2/pebble.json"}, o.pebbleArgs...)...)

	kek := base64.StdEncoding.EncodeToString([]byte(rnd(16)))
	s.certloomd = run("certloomd", "-p", "127.0.0.1::8443", "-v", mount(linuxBin, "/certloom"), "-v", mount(m2, "/m2"),
		"-e", "CERTLOOM_DATABASE_URL=postgres://certloom_app:"+appPass+"@db:5432/certloom?sslmode=disable",
		"-e", "CERTLOOM_LISTEN=0.0.0.0:8443", "-e", "CERTLOOM_AGENT_LISTEN=0.0.0.0:8444", "-e", "CERTLOOM_KEK="+kek,
		"-e", "CERTLOOM_AGENT_SERVER_NAMES=certloomd", "-e", "CERTLOOM_AGENT_PUBLIC_URL=https://certloomd:8444",
		"-e", "CERTLOOM_ACME_CA_FILE=/m2/pebble.minica.pem", "-e", "CERTLOOM_LOG_LEVEL=debug",
		runImage, "/certloom/certloomd", "serve", "--insecure-http")
	port := docker(t, "", "port", s.certloomd, "8443/tcp")
	s.apiURL = "http://" + strings.Split(port, "\n")[0]
	s.ownerTok = docker(t, "", "exec", s.certloomd, "/certloom/certloomd", "bootstrap", "--org", "m2")
	login := exec.Command(filepath.Join(hostBin, "certloom"+exe()), "login", "--server", s.apiURL, "--token-stdin")
	login.Env = append(os.Environ(), "CERTLOOM_CONFIG="+s.cfg)
	login.Stdin = strings.NewReader(s.ownerTok + "\n")
	waitFor(t, 30*time.Second, "certloomd login", func() bool {
		return login.Run() == nil || func() bool {
			login = exec.Command(filepath.Join(hostBin, "certloom"+exe()), "login", "--server", s.apiURL, "--token-stdin")
			login.Env = append(os.Environ(), "CERTLOOM_CONFIG="+s.cfg)
			login.Stdin = strings.NewReader(s.ownerTok + "\n")
			return false
		}()
	})

	if len(web) > 0 {
		s.nginx = web[0](s, run, m2, bootDir)
		return s
	}
	// nginx + agent: the live link starts at the bootstrap certificate.
	s.nginx = run("www.m2.test", "-v", mount(linuxBin, "/certloom"), "-v", mount(m2, "/m2"), "-v", mount(bootDir, "/bootstrap"),
		"--entrypoint", "sh", nginxImage, "-c",
		"mkdir -p /etc/certloom/live /var/www/acme /etc/certloom-agent && cp /m2/nginx.conf /etc/nginx/conf.d/default.conf && "+
			"cp /m2/agent.yaml /etc/certloom-agent/config.yaml && ln -sfn /bootstrap /etc/certloom/live/www && exec nginx -g 'daemon off;'")
	return s
}

func TestM2RenewDeployVerifyRollback(t *testing.T) {
	s := up(t)

	// --- enrollment ---
	var tok struct {
		Token  string `json:"token"`
		CAHash string `json:"ca_hash"`
	}
	s.jsonCLI(&tok, "agent", "token", "--name", "web")
	out := docker(t, tok.Token+"\n", "exec", "-i", s.nginx, "/certloom/certloom-agent", "enroll", "--config", "/etc/certloom-agent/config.yaml", "--ca-hash", tok.CAHash)
	_ = out
	docker(t, "", "exec", "-d", s.nginx, "sh", "-c", "/certloom/certloom-agent run --config /etc/certloom-agent/config.yaml > /tmp/agent.log 2>&1")
	waitFor(t, 60*time.Second, "agent heartbeat with target", func() bool {
		o, err := s.cli("agent", "list")
		return err == nil && strings.Contains(o, "active") && strings.Contains(o, "www")
	})
	// Re-using the token fails.
	if _, err := tryDocker("exec", "-i", s.nginx, "sh", "-c", "echo "+tok.Token+" | /certloom/certloom-agent enroll --config /etc/certloom-agent/config.yaml --ca-hash "+tok.CAHash); err == nil {
		t.Fatal("enrolling twice should fail")
	}

	// --- configuration ---
	s.mustCLI("issuer", "create", "pebble", "--directory", "https://pebble:14000/dir", "--agree-tos")
	s.mustCLI("scope", "create", "lab", "--allow-private", "--allow-host", "*.m2.test", "--port", "443")
	var ep struct{ ID string }
	s.jsonCLI(&ep, "endpoint", "add", "www.m2.test", "--scope", "lab")
	s.mustCLI("inventory", "import", filepath.Join(s.tmp, "boot.pem"), "--lineage", "www")
	var dep struct{ ID string }
	s.jsonCLI(&dep, "deployment", "create", "--lineage", "www", "--agent", "web", "--target", "www", "--issuer", "pebble",
		"--endpoint", ep.ID, "--san", "www.m2.test")

	type runView struct {
		ID, State, Error string
		Issued           *string `json:"issued_sha256"`
		Steps            []struct{ State, Detail string }
	}
	renew := func() runView {
		t.Helper()
		var r runView
		s.jsonCLI(&r, "deployment", "renew", dep.ID)
		waitFor(t, 3*time.Minute, "run "+r.ID+" to finish", func() bool {
			s.jsonCLI(&r, "run", "show", r.ID)
			return r.State == "verified" || r.State == "failed" || r.State == "rolled_back" || r.State == "cancelled"
		})
		return r
	}
	served := func() string {
		var e struct {
			LastLeaf *string `json:"last_leaf_sha256"`
		}
		s.mustCLI("endpoint", "probe", ep.ID)
		time.Sleep(3 * time.Second)
		s.jsonCLI(&e, "endpoint", "show", ep.ID)
		if e.LastLeaf == nil {
			return ""
		}
		return *e.LastLeaf
	}

	// --- 1: real issuance from Pebble, deployed and verified ---
	r1 := renew()
	if r1.State != "verified" || r1.Issued == nil {
		t.Fatalf("first renewal: %+v", r1)
	}
	var cert struct {
		Issuer string   `json:"issuer"`
		DNS    []string `json:"dns_names"`
	}
	s.jsonCLI(&cert, "inventory", "show", *r1.Issued)
	if !strings.Contains(strings.ToLower(cert.Issuer), "pebble") || len(cert.DNS) != 1 || cert.DNS[0] != "www.m2.test" {
		t.Fatalf("issued certificate not from Pebble for www.m2.test: %+v", cert)
	}
	waitFor(t, 30*time.Second, "endpoint serving the issued certificate", func() bool { return served() == *r1.Issued })

	// --- ARI: the control plane fetched Pebble's renewal window ---
	waitFor(t, 60*time.Second, "ARI-based renewal time", func() bool {
		o, _ := s.cli("deployment", "list")
		return strings.Contains(o, "ARI window")
	})

	// --- 2: activation failure (nginx -t fails) is rolled back by the agent ---
	docker(t, "", "exec", s.nginx, "sh", "-c", "echo 'this is not valid nginx config;' > /etc/nginx/conf.d/zz-broken.conf")
	r2 := renew()
	if r2.State != "rolled_back" || !strings.Contains(r2.Error, "config test failed") {
		t.Fatalf("broken config renewal: %+v", r2)
	}
	if got := served(); got != *r1.Issued {
		t.Fatalf("after rollback the endpoint must still serve run 1's certificate; serves %s", got)
	}
	docker(t, "", "exec", s.nginx, "rm", "/etc/nginx/conf.d/zz-broken.conf")

	// --- 3: a normal renewal replaces run 1's certificate (RFC 9773 replaces) ---
	r3 := renew()
	if r3.State != "verified" || *r3.Issued == *r1.Issued {
		t.Fatalf("third renewal: %+v", r3)
	}
	// Probes run on the scheduler tick; wait for an observation of the new certificate.
	waitFor(t, 45*time.Second, "endpoint serving run 3's certificate", func() bool { return served() == *r3.Issued })
	var r3full struct {
		Steps []struct{ State, Detail string }
	}
	s.jsonCLI(&r3full, "run", "show", r3.ID)
	if last := r3full.Steps[len(r3full.Steps)-1].Detail; !strings.Contains(last, "externally by the control plane") {
		t.Fatalf("verification should include the control plane's external probe: %q", last)
	}

	// --- 4: the agent process is killed in the middle of a deploy ---
	// The config test is slowed down so the kill lands after the live link
	// was switched to the new certificate but before nginx was reloaded.
	slow := strings.Replace(agentConfig, "test_command: [nginx, -t]",
		`test_command: [sh, -c, "touch /tmp/in-test && sleep 20 && nginx -t"]`, 1)
	restartAgent := func(cfg string) {
		t.Helper()
		_, _ = tryDocker("exec", s.nginx, "pkill", "-9", "-f", "certloom-agent run")
		docker(t, cfg, "exec", "-i", s.nginx, "sh", "-c", "cat > /etc/certloom-agent/config.yaml")
		docker(t, "", "exec", "-d", s.nginx, "sh", "-c", "/certloom/certloom-agent run --config /etc/certloom-agent/config.yaml >> /tmp/agent.log 2>&1")
	}
	restartAgent(slow)
	var r4 runView
	s.jsonCLI(&r4, "deployment", "renew", dep.ID)
	waitFor(t, 3*time.Minute, "deploy to reach the config test", func() bool {
		_, err := tryDocker("exec", s.nginx, "test", "-f", "/tmp/in-test")
		return err == nil
	})
	if link := docker(t, "", "exec", s.nginx, "readlink", "/etc/certloom/live/www"); !strings.HasSuffix(link, r4.ID) {
		t.Fatalf("live link should point at run 4 while the config test runs, got %s", link)
	}
	_, _ = tryDocker("exec", s.nginx, "pkill", "-9", "-f", "certloom-agent run")
	restartAgent(agentConfig)
	waitFor(t, 3*time.Minute, "run "+r4.ID+" to finish after the crash", func() bool {
		s.jsonCLI(&r4, "run", "show", r4.ID)
		return r4.State == "verified" || r4.State == "failed" || r4.State == "rolled_back" || r4.State == "cancelled"
	})
	if r4.State != "rolled_back" || !strings.Contains(r4.Error, "interrupted") {
		t.Fatalf("crash mid-deploy: want rolled_back after an interrupted deploy, got %s %q", r4.State, r4.Error)
	}
	if link := docker(t, "", "exec", s.nginx, "readlink", "/etc/certloom/live/www"); !strings.HasSuffix(link, r3.ID) {
		t.Fatalf("after the crash the live link must be back on run 3, got %s", link)
	}
	waitFor(t, 45*time.Second, "endpoint serving run 3's certificate after the crash", func() bool { return served() == *r3.Issued })

	// --- the private key never left the agent host ---
	key := docker(t, "", "exec", s.nginx, "sh", "-c", "sed -n 2p /var/lib/certloom-agent/certs/www/"+r3.ID+"/privkey.pem")
	logs, _ := tryDocker("logs", s.certloomd)
	if len(key) < 20 || strings.Contains(logs, key[:20]) {
		t.Fatal("private key material appears in control-plane logs (or key missing)")
	}
	audit := s.mustCLI("audit", "query", "--limit", "1000")
	for _, want := range []string{"agents.enroll", "issuers.create", "deployments.create", "renewals.request", "renewals.issued",
		"renewals.verified", "renewals.rolled_back"} {
		if !strings.Contains(audit, want) {
			t.Errorf("audit missing %s", want)
		}
	}
}
