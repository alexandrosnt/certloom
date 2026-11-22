package acme

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestOSTrustStores applies a trust bundle with the agent's debian and rhel
// stores in real containers, with update-ca-certificates and update-ca-trust.
func TestOSTrustStores(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "agent.test")
	build := exec.Command("go", "test", "-c", "-o", bin, "../../internal/agent/")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build agent tests: %v\n%s", err, out)
	}
	cases := []struct{ typ, image, prep string }{
		{"debian", "debian:13", "apt-get update -qq >/dev/null && apt-get install -y -qq ca-certificates >/dev/null && "},
		{"rhel", "rockylinux:9", ""},
	}
	for _, c := range cases {
		t.Run(c.typ, func(t *testing.T) {
			out := docker(t, "", "run", "--rm", "-v", dir+":/t:ro", "-e", "CERTLOOM_OS_TRUST_E2E="+c.typ, c.image,
				"sh", "-c", c.prep+"/t/agent.test -test.run '^TestOSTrustStore$' -test.v")
			if !strings.Contains(out, "--- PASS: TestOSTrustStore") {
				t.Fatalf("test did not run:\n%s", out)
			}
		})
	}
}
