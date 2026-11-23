package acme

import (
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestCertloomdPackage installs the certloomd deb and rpm built from
// .goreleaser.yaml and checks what the package scripts set up. The Debian case
// runs in the systemd image so the unit is checked by systemd-analyze and the
// user comes from systemd-sysusers; Rocky has no systemd in its base image and
// takes the useradd fallback.
func TestCertloomdPackage(t *testing.T) {
	rpmArch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	deb := buildPackages(t, "certloomd_*_"+runtime.GOARCH+".deb")
	rpm := buildPackages(t, "certloomd-*."+rpmArch+".rpm")
	docker(t, "", "build", "-q", "-t", systemdImage, filepath.Join("testdata", "systemd"))

	const checks = ` && getent passwd certloom` +
		` && stat -c '%a %U:%G' /etc/certloom/certloomd.env /etc/certloom/tls` +
		` && certloomd version`
	cases := []struct {
		name, image, pkg, install string
	}{
		{"deb", systemdImage, deb, "dpkg -i /p/pkg" + checks +
			" && systemd-analyze verify /usr/lib/systemd/system/certloomd.service"},
		{"rpm", "rockylinux:9", rpm, "rpm -i /p/pkg" + checks},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := docker(t, "", "run", "--rm", "--entrypoint", "sh",
				"-v", mount(c.pkg, "/p/pkg"), c.image, "-c", "set -e; "+c.install+" 2>&1")
			for _, want := range []string{
				"certloom:x:",
				"640 root:certloom",
				"750 root:certloom",
				"certloomd " + e2eVersion,
			} {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in:\n%s", want, out)
				}
			}
		})
	}
}
