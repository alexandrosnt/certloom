package acme

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestPackageRepo publishes the signed e2e packages with
// deploy/packaging/publish-repo.sh and installs them from the result with apt
// and dnf, both checking repository and package signatures. A changed
// repomd.xml must make dnf refuse the repository.
func TestPackageRepo(t *testing.T) {
	rpmArch := map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	buildPackages(t, "certloomd_*_"+runtime.GOARCH+".deb")
	root, _ := filepath.Abs("../..")
	pkgs := t.TempDir()
	for _, pattern := range []string{"*_" + runtime.GOARCH + ".deb", "*." + rpmArch + ".rpm"} {
		found, _ := filepath.Glob(filepath.Join(root, "dist", pattern))
		for _, f := range found {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(pkgs, filepath.Base(f)), b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	script, _ := filepath.Abs("../../deploy/packaging/publish-repo.sh")
	repo := t.TempDir()
	pkgKeyDir = testPackageKey(t)

	// Sign the rpms the way nFPM does in a release (snapshots are unsigned).
	docker(t, "", "run", "--rm", "-v", pkgs+":/pkgs", "-v", mount(pkgKeyDir, "/key"), "rockylinux:9", "sh", "-c", `set -e
dnf -q -y install rpm-sign >/dev/null
gpg --batch --quiet --import /key/key.asc
name=$(gpg --batch --with-colons --list-secret-keys | awk -F: '/^uid:/ { print $10; exit }')
mkdir /s && cp /pkgs/*.rpm /s/
rpmsign --define "_gpg_name $name" --addsign /s/*.rpm >/dev/null 2>&1
cp /s/*.rpm /pkgs/`)

	// Publish, then install with apt from the same container.
	aptOut := docker(t, "", "run", "--rm", "-v", mount(pkgs, "/pkgs"), "-v", mount(pkgKeyDir, "/key"),
		"-v", mount(script, "/publish-repo.sh"), "-v", repo+":/out", "debian:13", "sh", "-c", `set -e
apt-get update -qq >/dev/null
apt-get install -y -qq gnupg apt-utils createrepo-c >/dev/null 2>&1
mkdir /repo
PACKAGE_GPG_KEY_FILE=/key/key.asc sh /publish-repo.sh /pkgs /repo
gpg --dearmor < /repo/gpg.key > /usr/share/keyrings/certloom.gpg
echo 'deb [signed-by=/usr/share/keyrings/certloom.gpg] file:/repo/deb stable main' > /etc/apt/sources.list.d/certloom.list
apt-get update -qq -o Dir::Etc::sourcelist=/etc/apt/sources.list.d/certloom.list -o Dir::Etc::sourceparts=- 2>&1
apt-get install -y -qq certloom-agent certloomd >/dev/null 2>&1
certloom-agent version
certloomd version
cp -a /repo/. /out/
chmod -R a+rwX /out`)

	// dnf with gpgcheck and repo_gpgcheck, then a tampered repomd.xml.
	out := docker(t, "", "run", "--rm", "-v", mount(repo, "/repo"), "rockylinux:9", "sh", "-c", `set -e
cat > /etc/yum.repos.d/certloom.repo <<EOF
[certloom]
name=certloom
baseurl=file:///repo/rpm/`+rpmArch+`
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///repo/gpg.key
EOF
dnf -q -y --disablerepo='*' --enablerepo=certloom install certloom-agent certloomd
certloom-agent version
certloomd version
cp -a /repo/rpm/`+rpmArch+` /tmp/bad
echo >> /tmp/bad/repodata/repomd.xml
sed -i 's|/repo/rpm/`+rpmArch+`|/tmp/bad|' /etc/yum.repos.d/certloom.repo
dnf clean all >/dev/null
if dnf -q -y --disablerepo='*' --enablerepo=certloom makecache 2>/dev/null; then
  echo TAMPER-ACCEPTED
else
  echo tamper-refused
fi`)
	for _, want := range []string{"certloom-agent " + e2eVersion, "certloomd " + e2eVersion} {
		if !strings.Contains(aptOut, want) {
			t.Errorf("apt: missing %q in:\n%s", want, aptOut)
		}
	}
	for _, want := range []string{"certloom-agent " + e2eVersion, "certloomd " + e2eVersion, "tamper-refused"} {
		if !strings.Contains(out, want) {
			t.Errorf("dnf: missing %q in:\n%s", want, out)
		}
	}
}
