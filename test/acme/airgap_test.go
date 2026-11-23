package acme

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestAirgapRenewal runs the whole stack on a Docker network without a route
// out: PostgreSQL, certloomd, an internal ACME CA (step-ca's ACME provisioner)
// and nginx with the agent. Enrollment, issuance, a renewal that replaces the
// certificate, deployment and verification must all work without the
// internet.
func TestAirgapRenewal(t *testing.T) {
	if _, err := tryDocker("image", "inspect", stepImage); err != nil {
		if out, err := tryDocker("pull", stepImage); err != nil {
			t.Skipf("cannot pull %s: %v\n%s", stepImage, err, out)
		}
	}
	s := upWith(t, upOptions{
		internal: true,
		before: func(run func(string, ...string) string, m2 string) {
			step := run("step", "-e", "DOCKER_STEPCA_INIT_NAME=certloom airgap step", "-e", "DOCKER_STEPCA_INIT_DNS_NAMES=step,localhost",
				"-e", "DOCKER_STEPCA_INIT_PROVISIONER_NAME=admin", "-e", "DOCKER_STEPCA_INIT_PASSWORD="+rnd(12),
				"-e", "DOCKER_STEPCA_INIT_ACME=true", stepImage)
			waitFor(t, 60*time.Second, "step-ca", func() bool {
				_, err := tryDocker("exec", step, "step", "ca", "health", "--ca-url", "https://localhost:9000", "--root", "/home/step/certs/root_ca.crt")
				return err == nil
			})
			// certloomd and the agent trust the ACME CA through the shared bundle.
			root := docker(t, "", "exec", step, "cat", "/home/step/certs/root_ca.crt")
			f, err := os.OpenFile(filepath.Join(m2, "pebble.minica.pem"), os.O_APPEND|os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.WriteString("\n" + root + "\n")
			_ = f.Close()
		},
	})
	s.enrollWeb()

	if out, _ := tryDocker("exec", s.nginx, "sh", "-c", "wget -q -T 5 -O /dev/null http://1.1.1.1/ && echo EGRESS || echo no-egress"); !strings.Contains(out, "no-egress") {
		t.Fatalf("the test network has a route out: %s", out)
	}

	s.mustCLI("issuer", "create", "internal", "--directory", "https://step:9000/acme/acme/directory", "--agree-tos")
	s.mustCLI("scope", "create", "lab", "--allow-private", "--allow-host", "*.m2.test", "--port", "443")
	var ep struct{ ID string }
	s.jsonCLI(&ep, "endpoint", "add", "www.m2.test", "--scope", "lab")
	s.mustCLI("inventory", "import", filepath.Join(s.tmp, "boot.pem"), "--lineage", "www")
	var dep struct{ ID string }
	s.jsonCLI(&dep, "deployment", "create", "--lineage", "www", "--agent", "web", "--target", "www", "--issuer", "internal",
		"--endpoint", ep.ID, "--san", "www.m2.test")

	var last string
	for i := range 2 { // issuance, then a renewal that replaces it
		r := renewAndWait(t, s, dep.ID)
		if r.State != "verified" || r.Issued == nil {
			t.Fatalf("run %d: %s %s", i+1, r.State, r.Error)
		}
		if *r.Issued == last {
			t.Fatalf("run %d did not replace the certificate", i+1)
		}
		last = *r.Issued
		var cert struct {
			Issuer string `json:"issuer"`
		}
		s.jsonCLI(&cert, "inventory", "show", last)
		if !strings.Contains(cert.Issuer, "certloom airgap step") {
			t.Fatalf("run %d issued by %q", i+1, cert.Issuer)
		}
	}
}
