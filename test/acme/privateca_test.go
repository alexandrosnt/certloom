package acme

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

const (
	vaultImage = "hashicorp/vault:1.20"
	stepImage  = "smallstep/step-ca:0.28.4"
)

// Three targets: www is signed by Vault, step by step-ca, and other asks
// Vault for a name its role does not allow.
const pkiAgentConfig = `server: https://certloomd:8444
state_dir: /var/lib/certloom-agent
name: web
targets:
  - name: www
    type: nginx
    live_link: /etc/certloom/live/www
    test_command: [nginx, -t]
    reload_command: [nginx, -s, reload]
    verify_address: 127.0.0.1:443
    allowed_sans: [www.m2.test]
  - name: step
    type: nginx
    live_link: /etc/certloom/live/step
    test_command: [nginx, -t]
    reload_command: [nginx, -s, reload]
    verify_address: 127.0.0.1:443
    allowed_sans: [step.m2.test]
  - name: other
    type: nginx
    live_link: /etc/certloom/live/other
    test_command: [nginx, -t]
    reload_command: [nginx, -s, reload]
    verify_address: 127.0.0.1:443
    allowed_sans: [other.m2.test]
`

const pkiNginxConf = `server {
    listen 443 ssl;
    server_name www.m2.test;
    ssl_certificate     /etc/certloom/live/www/fullchain.pem;
    ssl_certificate_key /etc/certloom/live/www/privkey.pem;
    return 200 "www\n";
}
server {
    listen 443 ssl;
    server_name step.m2.test;
    ssl_certificate     /etc/certloom/live/step/fullchain.pem;
    ssl_certificate_key /etc/certloom/live/step/privkey.pem;
    return 200 "step\n";
}
`

// A dev Vault with TLS (its CA in /tmp/vtls), a root and an intermediate PKI
// mount, a role for www.m2.test only, and an AppRole that may only sign with it.
const vaultSetup = `set -e
export VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/tmp/vtls/vault-ca.pem VAULT_TOKEN=root
vault secrets enable pki >/dev/null
vault secrets tune -max-lease-ttl=87600h pki >/dev/null
vault write -field=certificate pki/root/generate/internal common_name="certloom e2e vault root" ttl=87600h >/dev/null
vault secrets enable -path=pki_int pki >/dev/null
vault write -field=csr pki_int/intermediate/generate/internal common_name="certloom e2e vault intermediate" > /tmp/int.csr
vault write -field=certificate pki/root/sign-intermediate csr=@/tmp/int.csr format=pem_bundle ttl=43800h > /tmp/int.pem
vault write pki_int/intermediate/set-signed certificate=@/tmp/int.pem >/dev/null
vault write pki_int/roles/web allowed_domains=www.m2.test allow_bare_domains=true allow_subdomains=false key_type=ec key_bits=256 max_ttl=72h >/dev/null
vault auth enable approle >/dev/null
printf 'path "pki_int/sign/web" { capabilities = ["update"] }\n' | vault policy write certloom - >/dev/null
vault write auth/approle/role/certloom token_policies=certloom token_ttl=5m >/dev/null
echo "role_id=$(vault read -field=role_id auth/approle/role/certloom/role-id)"
echo "secret_id=$(vault write -f -field=secret_id auth/approle/role/certloom/secret-id)"
`

// TestVaultAndStepCAIssuers issues through the control plane (ADR-0028):
// the agent sends a CSR, certloomd has it signed by a real Vault PKI role
// (AppRole login) and a real step-ca JWK provisioner, and the agent deploys
// and verifies the result. A name the Vault role refuses fails the run.
func TestVaultAndStepCAIssuers(t *testing.T) {
	for _, img := range []string{vaultImage, stepImage} {
		if _, err := tryDocker("image", "inspect", img); err != nil {
			if out, err := tryDocker("pull", img); err != nil {
				t.Skipf("cannot pull %s: %v\n%s", img, err, out)
			}
		}
	}
	var vault, step string
	s := upWith(t, upOptions{
		agentConfig: pkiAgentConfig,
		before: func(run func(string, ...string) string, m2 string) {
			_ = os.WriteFile(filepath.Join(m2, "nginx.conf"), []byte(pkiNginxConf), 0o644)
			vault = run("vault", "--entrypoint", "sh", vaultImage, "-c", "mkdir -p /tmp/vtls && exec vault server -dev -dev-tls "+
				"-dev-tls-san=vault -dev-tls-cert-dir=/tmp/vtls -dev-root-token-id=root -dev-listen-address=0.0.0.0:8200")
			step = run("step", "-e", "DOCKER_STEPCA_INIT_NAME=certloom e2e step", "-e", "DOCKER_STEPCA_INIT_DNS_NAMES=step,localhost",
				"-e", "DOCKER_STEPCA_INIT_PROVISIONER_NAME=certloom", "-e", "DOCKER_STEPCA_INIT_PASSWORD="+rnd(12), stepImage)
		},
	}, pkiWeb)
	s.enrollWeb()

	// Vault: PKI mounts, role and AppRole; the CA certificate for TLS.
	waitFor(t, 60*time.Second, "vault", func() bool {
		_, err := tryDocker("exec", vault, "sh", "-c", "VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/tmp/vtls/vault-ca.pem vault status")
		return err == nil
	})
	out := docker(t, vaultSetup, "exec", "-i", vault, "sh")
	ids := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^(role_id|secret_id)=(\S+)$`).FindAllStringSubmatch(out, -1) {
		ids[m[1]] = m[2]
	}
	if ids["role_id"] == "" || ids["secret_id"] == "" {
		t.Fatalf("vault setup:\n%s", out)
	}
	vaultCA := filepath.Join(s.tmp, "vault-ca.pem")
	docker(t, "", "cp", vault+":/tmp/vtls/vault-ca.pem", vaultCA)
	secretID := filepath.Join(s.tmp, "secret_id")
	_ = os.WriteFile(secretID, []byte(ids["secret_id"]+"\n"), 0o600)

	// step-ca: root certificate and the provisioner key, decrypted.
	waitFor(t, 60*time.Second, "step-ca", func() bool {
		_, err := tryDocker("exec", step, "step", "ca", "health", "--ca-url", "https://localhost:9000", "--root", "/home/step/certs/root_ca.crt")
		return err == nil
	})
	stepRoot := filepath.Join(s.tmp, "step-root.pem")
	docker(t, "", "cp", step+":/home/step/certs/root_ca.crt", stepRoot)
	jwk := docker(t, "", "exec", step, "sh", "-c", `grep -o '"encryptedKey": "[^"]*"' /home/step/config/ca.json | cut -d'"' -f4 | `+
		`step crypto jwe decrypt --password-file /home/step/secrets/password`)
	jwkFile := filepath.Join(s.tmp, "provisioner.jwk")
	_ = os.WriteFile(jwkFile, []byte(jwk), 0o600)

	s.mustCLI("issuer", "create", "vault", "--kind", "vault", "--url", "https://vault:8200", "--ca-file", vaultCA,
		"--mount", "pki_int", "--role", "web", "--auth", "approle", "--role-id", ids["role_id"], "--credential-file", secretID)
	s.mustCLI("issuer", "create", "step", "--kind", "stepca", "--url", "https://step:9000", "--ca-file", stepRoot,
		"--provisioner", "certloom", "--credential-file", jwkFile)
	for _, name := range []string{"vault", "step"} {
		o := s.mustCLI("issuer", "show", name)
		if strings.Contains(o, ids["secret_id"]) || strings.Contains(o, `"d"`) || !strings.Contains(o, `"has_credential": true`) {
			t.Fatalf("issuer %s exposes or lacks its credential:\n%s", name, o)
		}
	}

	s.mustCLI("inventory", "import", filepath.Join(s.tmp, "boot.pem"), "--lineage", "www")
	s.mustCLI("lineage", "create", "step")
	s.mustCLI("lineage", "create", "other")
	issue := func(lineage, target, issuer, san string) (state, issued, msg string) {
		t.Helper()
		var dep struct{ ID, Challenge string }
		s.jsonCLI(&dep, "deployment", "create", "--lineage", lineage, "--agent", "web", "--target", target, "--issuer", issuer, "--san", san)
		if dep.Challenge != "none" {
			t.Fatalf("deployment challenge %q", dep.Challenge)
		}
		var r struct {
			ID, State, Error string
			Issued           *string `json:"issued_sha256"`
		}
		s.jsonCLI(&r, "deployment", "renew", dep.ID)
		waitFor(t, 3*time.Minute, "run "+r.ID+" to finish", func() bool {
			s.jsonCLI(&r, "run", "show", r.ID)
			return r.State == "verified" || r.State == "failed" || r.State == "rolled_back" || r.State == "cancelled"
		})
		if r.Issued != nil {
			issued = *r.Issued
		}
		return r.State, issued, r.Error
	}
	certIssuer := func(sha string) string {
		var c struct {
			Issuer string   `json:"issuer"`
			DNS    []string `json:"dns_names"`
		}
		s.jsonCLI(&c, "inventory", "show", sha)
		return c.Issuer + " " + strings.Join(c.DNS, ",")
	}

	state, sha, msg := issue("www", "www", "vault", "www.m2.test")
	if state != "verified" {
		t.Fatalf("vault: %s %s", state, msg)
	}
	if got := certIssuer(sha); !strings.Contains(got, "certloom e2e vault intermediate") || !strings.HasSuffix(got, " www.m2.test") {
		t.Fatalf("vault issued %s", got)
	}

	state, sha, msg = issue("step", "step", "step", "step.m2.test")
	if state != "verified" {
		t.Fatalf("step-ca: %s %s", state, msg)
	}
	if got := certIssuer(sha); !strings.Contains(got, "certloom e2e step") || !strings.HasSuffix(got, " step.m2.test") {
		t.Fatalf("step-ca issued %s", got)
	}

	// The Vault role only allows www.m2.test: no retry, the run fails.
	state, _, msg = issue("other", "other", "vault", "other.m2.test")
	if state != "failed" || !strings.Contains(msg, "refused to sign") || !strings.Contains(msg, "not allowed") {
		t.Fatalf("vault role refusal: %s %s", state, msg)
	}

	// Every AppRole token was revoked after its signing call.
	tokens := docker(t, "", "exec", vault, "sh", "-c", "VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/tmp/vtls/vault-ca.pem VAULT_TOKEN=root "+
		"vault list -format=json auth/token/accessors")
	if n := strings.Count(tokens, `"`); n != 2 { // only the root token's accessor
		t.Fatalf("AppRole tokens left behind: %s", tokens)
	}
	if o := s.mustCLI("audit", "query", "--limit", "1000"); strings.Count(o, "issuers.credential_used") != 3 {
		t.Fatalf("credential use not audited per signing call:\n%s", o)
	}
}

// pkiWeb is the default nginx + agent container with a bootstrap
// certificate behind every live link nginx reads.
func pkiWeb(s *stack, run func(string, ...string) string, m2, boot string) string {
	return run("www.m2.test", "-v", mount(linuxBin, "/certloom"), "-v", mount(m2, "/m2"), "-v", mount(boot, "/bootstrap"),
		"--entrypoint", "sh", nginxImage, "-c",
		"mkdir -p /etc/certloom/live /etc/certloom-agent && cp /m2/nginx.conf /etc/nginx/conf.d/default.conf && "+
			"cp /m2/agent.yaml /etc/certloom-agent/config.yaml && ln -sfn /bootstrap /etc/certloom/live/www && "+
			"ln -sfn /bootstrap /etc/certloom/live/step && exec nginx -g 'daemon off;'")
}
