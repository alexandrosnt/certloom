package acme

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// pebbleEABConfig makes Pebble require External Account Binding and accept
// the given key ids (kid -> base64url HMAC).
func pebbleEABConfig(keys map[string]string) string {
	var kv []string
	for k, v := range keys {
		kv = append(kv, `"`+k+`": "`+v+`"`)
	}
	return strings.Replace(pebbleConfig, `"externalAccountBindingRequired": false`,
		`"externalAccountBindingRequired": true, "externalAccountMACKeys": {`+strings.Join(kv, ", ")+`}`, 1)
}

func eabKey() string { return base64.RawURLEncoding.EncodeToString([]byte(rnd(32))) }

// wwwDeployment creates the HTTP-01 deployment for www.m2.test on issuer
// pebble and returns a function that runs one renewal.
func (s *stack) wwwDeployment() func() (state, errMsg string) {
	t := s.t
	s.mustCLI("inventory", "import", filepath.Join(s.tmp, "boot.pem"), "--lineage", "www")
	var dep struct{ ID string }
	s.jsonCLI(&dep, "deployment", "create", "--lineage", "www", "--agent", "web", "--target", "www", "--issuer", "pebble",
		"--san", "www.m2.test")
	return func() (string, string) {
		t.Helper()
		var r struct{ ID, State, Error string }
		s.jsonCLI(&r, "deployment", "renew", dep.ID)
		waitFor(t, 3*time.Minute, "run "+r.ID+" to finish", func() bool {
			s.jsonCLI(&r, "run", "show", r.ID)
			return r.State == "verified" || r.State == "failed" || r.State == "rolled_back" || r.State == "cancelled"
		})
		return r.State, r.Error
	}
}

func (s *stack) keyState(kid string) string {
	var keys []struct{ KID, State string }
	s.jsonCLI(&keys, "issuer", "eab-key", "list", "pebble")
	for _, k := range keys {
		if k.KID == kid {
			return k.State
		}
	}
	return ""
}

func TestEABSingleUse(t *testing.T) {
	good := eabKey()
	s := upWith(t, upOptions{pebbleConfig: pebbleEABConfig(map[string]string{"kid-good": good})})
	s.enrollWeb()
	s.mustCLI("issuer", "create", "pebble", "--directory", "https://pebble:14000/dir", "--agree-tos")
	s.mustCLI("issuer", "set-eab", "pebble", "--mode", "single_use")
	renew := s.wwwDeployment()

	// Empty pool: refused before anything reaches the agent.
	if state, msg := renew(); state != "failed" || !strings.Contains(msg, "no unused single-use EAB key") {
		t.Fatalf("empty pool: %s %s", state, msg)
	}
	addKey := func(kid, hmac string) {
		t.Helper()
		f := filepath.Join(s.tmp, kid+".hmac")
		if err := os.WriteFile(f, []byte(hmac+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		s.mustCLI("issuer", "eab-key", "add", "pebble", "--kid", kid, "--hmac-file", f, "--expires-in", "168h")
	}

	// A key Pebble does not know: the CA refuses registration, the run fails
	// without retries and the key is marked failed.
	addKey("kid-unknown", eabKey())
	if state, msg := renew(); state != "failed" || !strings.Contains(msg, "External Account Binding") {
		t.Fatalf("unknown key: %s %s", state, msg)
	}
	if st := s.keyState("kid-unknown"); st != "failed" {
		t.Fatalf("unknown key state %q", st)
	}

	// A valid key registers the account and is used up.
	addKey("kid-good", good)
	if state, msg := renew(); state != "verified" {
		t.Fatalf("valid key: %s %s", state, msg)
	}
	if st := s.keyState("kid-good"); st != "consumed" {
		t.Fatalf("valid key state %q", st)
	}
	logs := docker(t, "", "exec", s.nginx, "cat", "/tmp/agent.log")
	if !strings.Contains(logs, "registered ACME account with EAB") || !strings.Contains(logs, `"source":"central"`) || strings.Contains(logs, good) {
		t.Fatalf("agent log:\n%s", logs)
	}
	// The account is reused: no key left in the pool, still issues.
	if state, msg := renew(); state != "verified" {
		t.Fatalf("renewal with the registered account: %s %s", state, msg)
	}
	if o, err := s.cli("audit", "query", "--limit", "1000"); err != nil || !strings.Contains(o, "issuers.eab_key_consumed") {
		t.Fatalf("consumption not audited: %v\n%s", err, o)
	}
}

func TestEABHostLocalKey(t *testing.T) {
	hmac := eabKey()
	cfg := agentConfig + "acme_eab:\n  - directory_url: https://pebble:14000/dir\n    kid: kid-local\n    hmac_file: /m2/eab.hmac\n"
	s := upWith(t, upOptions{agentConfig: cfg, pebbleConfig: pebbleEABConfig(map[string]string{"kid-local": hmac}),
		before: func(_ func(string, ...string) string, m2 string) {
			_ = os.WriteFile(filepath.Join(m2, "eab.hmac"), []byte(hmac+"\n"), 0o644)
		}})
	s.enrollWeb()
	// The control plane knows nothing about EAB; the host's key is used.
	s.mustCLI("issuer", "create", "pebble", "--directory", "https://pebble:14000/dir", "--agree-tos")
	renew := s.wwwDeployment()
	if state, msg := renew(); state != "verified" {
		t.Fatalf("local key: %s %s", state, msg)
	}
	logs := docker(t, "", "exec", s.nginx, "cat", "/tmp/agent.log")
	if !strings.Contains(logs, `"source":"local"`) || !strings.Contains(logs, `"kid":"kid-local"`) {
		t.Fatalf("agent log:\n%s", logs)
	}
}
