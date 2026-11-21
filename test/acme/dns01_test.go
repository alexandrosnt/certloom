package acme

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

const bindImage = "internetsystemsconsortium/bind9:9.20"

// BIND is authoritative for m2.test and for validation.test, the zone that
// _acme-challenge.app.m2.test is delegated to by CNAME. Updates need the TSIG
// key and may only touch TXT records. Recursion is on so that Pebble, which
// asks BIND directly, gets the CNAME followed the way a CA's recursive
// validating resolver would; with it off BIND answers only the CNAME.
const namedConf = `key "certloom-e2e" { algorithm hmac-sha256; secret "%SECRET%"; };
options {
  directory "/tmp/bind";
  listen-on { any; };
  listen-on-v6 { none; };
  allow-query { any; };
  recursion yes;
  allow-recursion { any; };
  dnssec-validation no;
};
zone "m2.test" { type primary; file "/tmp/bind/m2.test.zone"; update-policy { grant certloom-e2e zonesub TXT; }; };
zone "validation.test" { type primary; file "/tmp/bind/validation.test.zone"; update-policy { grant certloom-e2e zonesub TXT; }; };
`

// The zone files need the container's own address for ns.m2.test, which is
// only known once it runs.
const bindStart = `set -e
mkdir -p /tmp/bind
set -- $(hostname -i)
cat > /tmp/bind/m2.test.zone <<EOF
\$TTL 60
@ IN SOA ns.m2.test. admin.m2.test. 1 60 60 600 60
@ IN NS ns.m2.test.
ns IN A $1
_acme-challenge.app IN CNAME app.validation.test.
EOF
cat > /tmp/bind/validation.test.zone <<EOF
\$TTL 60
@ IN SOA ns.m2.test. admin.m2.test. 1 60 60 600 60
@ IN NS ns.m2.test.
EOF
cp /m2/named.conf /tmp/bind/named.conf
exec named -g -c /tmp/bind/named.conf
`

const dnsAgentConfig = `server: https://certloomd:8444
state_dir: /var/lib/certloom-agent
name: web
acme_ca_file: /m2/pebble.minica.pem
resolvers: ["bind:53"]
dns_solvers:
  - name: main
    provider: rfc2136
    nameserver: bind:53
    tsig_file: /m2/tsig.key
    zones: [m2.test]
    propagation_timeout_seconds: 60
  - name: validation
    provider: rfc2136
    nameserver: bind:53
    tsig_file: /m2/tsig.key
    zones: [validation.test]
    propagation_timeout_seconds: 60
targets:
  - name: www
    type: nginx
    live_link: /etc/certloom/live/www
    test_command: [nginx, -t]
    reload_command: [nginx, -s, reload]
    verify_address: 127.0.0.1:443
    allowed_sans: ["*.m2.test"]
`

func TestDNS01WildcardAndCNAMEDelegation(t *testing.T) {
	if _, err := tryDocker("image", "inspect", bindImage); err != nil {
		if out, err := tryDocker("pull", bindImage); err != nil {
			t.Skipf("cannot pull %s: %v\n%s", bindImage, err, out)
		}
	}
	secret := base64.StdEncoding.EncodeToString([]byte(rnd(32)))[:44]
	s := upWith(t, upOptions{
		agentConfig: dnsAgentConfig,
		pebbleArgs:  []string{"-dnsserver", "bind:53"},
		before: func(run func(string, ...string) string, m2 string) {
			_ = os.WriteFile(filepath.Join(m2, "named.conf"), []byte(strings.ReplaceAll(namedConf, "%SECRET%", secret)), 0o644)
			_ = os.WriteFile(filepath.Join(m2, "tsig.key"),
				[]byte("key \"certloom-e2e\" {\n\talgorithm hmac-sha256;\n\tsecret \""+secret+"\";\n};\n"), 0o644)
			run("bind", "--network-alias", "ns.m2.test", "-v", mount(m2, "/m2"), "--entrypoint", "sh", bindImage, "-c", bindStart)
		},
	})
	s.enrollWeb()

	// The operator's connection check passes before anything is issued.
	out := docker(t, "", "exec", s.nginx, "/certloom/certloom-agent", "dns-test", "--config", "/etc/certloom-agent/config.yaml",
		"--solver", "main", "--name", "www.m2.test")
	if !strings.Contains(out, "PASS  record visible") || !strings.Contains(out, "PASS  record removed") {
		t.Fatalf("dns-test:\n%s", out)
	}

	s.mustCLI("issuer", "create", "pebble", "--directory", "https://pebble:14000/dir", "--agree-tos")
	s.mustCLI("scope", "create", "lab", "--allow-private", "--allow-host", "*.m2.test", "--port", "443")
	var ep struct{ ID string }
	s.jsonCLI(&ep, "endpoint", "add", "www.m2.test", "--scope", "lab")
	s.mustCLI("inventory", "import", filepath.Join(s.tmp, "boot.pem"), "--lineage", "www")
	var dep struct{ ID string }
	s.jsonCLI(&dep, "deployment", "create", "--lineage", "www", "--agent", "web", "--target", "www", "--issuer", "pebble",
		"--endpoint", ep.ID, "--challenge", "dns-01", "--san", "*.m2.test", "--san", "app.m2.test")

	renew := func() (state, issued, errMsg string) {
		t.Helper()
		var r struct {
			ID, State, Error string
			Issued           *string `json:"issued_sha256"`
		}
		s.jsonCLI(&r, "deployment", "renew", dep.ID)
		waitFor(t, 4*time.Minute, "run "+r.ID+" to finish", func() bool {
			s.jsonCLI(&r, "run", "show", r.ID)
			return r.State == "verified" || r.State == "failed" || r.State == "rolled_back" || r.State == "cancelled"
		})
		if r.Issued != nil {
			issued = *r.Issued
		}
		return r.State, issued, r.Error
	}
	for i := range 2 { // first issuance, then a renewal that replaces it
		state, issued, msg := renew()
		if state != "verified" {
			t.Fatalf("run %d: %s %s", i+1, state, msg)
		}
		var cert struct {
			Issuer string   `json:"issuer"`
			DNS    []string `json:"dns_names"`
		}
		s.jsonCLI(&cert, "inventory", "show", issued)
		slices.Sort(cert.DNS)
		if !strings.Contains(strings.ToLower(cert.Issuer), "pebble") || strings.Join(cert.DNS, ",") != "*.m2.test,app.m2.test" {
			t.Fatalf("run %d issued %+v", i+1, cert)
		}
	}
	// Both records were cleaned up after validation.
	logs := docker(t, "", "exec", s.nginx, "sh", "-c", "cat /tmp/agent.log")
	for _, want := range []string{`"record":"_acme-challenge.m2.test."`, `"record":"app.validation.test."`} {
		if !strings.Contains(logs, "dns-01 cleanup") || !strings.Contains(logs, want) {
			t.Fatalf("agent log lacks %s cleanup:\n%s", want, logs)
		}
	}
}

// enrollWeb enrolls the agent in the web container and starts it.
func (s *stack) enrollWeb() {
	t := s.t
	var tok struct {
		Token  string `json:"token"`
		CAHash string `json:"ca_hash"`
	}
	s.jsonCLI(&tok, "agent", "token", "--name", "web")
	docker(t, tok.Token+"\n", "exec", "-i", s.nginx, "/certloom/certloom-agent", "enroll", "--config", "/etc/certloom-agent/config.yaml", "--ca-hash", tok.CAHash)
	docker(t, "", "exec", "-d", s.nginx, "sh", "-c", "/certloom/certloom-agent run --config /etc/certloom-agent/config.yaml > /tmp/agent.log 2>&1")
	waitFor(t, 60*time.Second, "agent heartbeat with target", func() bool {
		o, err := s.cli("agent", "list")
		return err == nil && strings.Contains(o, "active") && strings.Contains(o, "www")
	})
}
