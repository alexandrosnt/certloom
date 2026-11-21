package acme

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	// Keep in sync with deploy/packaging/build.sh.
	nfpmImage = "goreleaser/nfpm:v2.44.0"
	// Built from testdata/systemd (Debian with systemd as PID 1 and nginx).
	systemdImage = "certloom-e2e-systemd:debian13"
)

const systemdAgentConfig = `server: https://certloomd:8444
state_dir: /var/lib/certloom-agent
name: web
acme_ca_file: /m2/pebble.minica.pem
targets:
  - name: www
    type: nginx
    live_link: /etc/certloom/live/www
    webroot: /var/www/acme
    test_command: [nginx, -t]
    reload_command: [systemctl, reload, nginx]
    verify_address: 127.0.0.1:443
    allowed_sans: [www.m2.test]
`

// buildDeb packages the Linux certloom-agent binary built by TestMain with the
// repository's nfpm config and returns the path of the .deb.
func buildDeb(t *testing.T) string {
	t.Helper()
	root, _ := filepath.Abs("../..")
	stage := t.TempDir()
	cp := func(src, dst string) {
		b, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(stage, filepath.FromSlash(dst))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	files := []string{"LICENSE", "deploy/packaging/nfpm.yaml", "deploy/packaging/config.example.yaml", "deploy/systemd/certloom-agent.service"}
	scripts, _ := filepath.Glob(filepath.Join(root, "deploy", "packaging", "scripts", "*.sh"))
	for _, s := range scripts {
		files = append(files, "deploy/packaging/scripts/"+filepath.Base(s))
	}
	for _, f := range files {
		cp(filepath.Join(root, filepath.FromSlash(f)), f)
	}
	cp(filepath.Join(linuxBin, "certloom-agent"), "dist/linux/certloom-agent")

	args := []string{"run", "--rm", "-v", stage + ":/src", "-w", "/src", "-e", "VERSION=0.0.0-e2e", "-e", "GOARCH=" + runtime.GOARCH}
	if uid := os.Getuid(); uid >= 0 {
		args = append(args, "--user", strconv.Itoa(uid)+":"+strconv.Itoa(os.Getgid()))
	}
	args = append(args, nfpmImage, "pkg", "--config", "deploy/packaging/nfpm.yaml", "--packager", "deb", "--target", "dist/")
	docker(t, "", args...)
	debs, _ := filepath.Glob(filepath.Join(stage, "dist", "*.deb"))
	if len(debs) != 1 {
		t.Fatalf("expected one .deb, got %v", debs)
	}
	return debs[0]
}

type sysRun struct {
	ID, State, Error string
	Issued           *string `json:"issued_sha256"`
}

// renewAndWait requests a renewal and waits for the run to reach a final state.
func renewAndWait(t *testing.T, s *stack, depID string) sysRun {
	t.Helper()
	var r sysRun
	s.jsonCLI(&r, "deployment", "renew", depID)
	waitFor(t, 3*time.Minute, "run "+r.ID+" to finish", func() bool {
		s.jsonCLI(&r, "run", "show", r.ID)
		return r.State == "verified" || r.State == "failed" || r.State == "rolled_back" || r.State == "cancelled"
	})
	return r
}

// servedLeaf probes the endpoint from the control plane and returns the
// fingerprint it last observed.
func servedLeaf(s *stack, epID string) string {
	var e struct {
		LastLeaf *string `json:"last_leaf_sha256"`
	}
	s.mustCLI("endpoint", "probe", epID)
	time.Sleep(3 * time.Second)
	s.jsonCLI(&e, "endpoint", "show", epID)
	if e.LastLeaf == nil {
		return ""
	}
	return *e.LastLeaf
}

// TestSystemdPackageRenewal installs the certloom-agent .deb on a Debian host
// running systemd, runs the agent as the packaged service with
// reload_command `systemctl reload nginx`, and renews through Pebble.
func TestSystemdPackageRenewal(t *testing.T) {
	deb := buildDeb(t)
	docker(t, "", "build", "-q", "-t", systemdImage, filepath.Join("testdata", "systemd"))

	s := up(t, func(s *stack, run func(string, ...string) string, m2, boot string) string {
		s.agentLog = []string{"journalctl", "--no-pager", "-n", "150", "-u", "certloom-agent", "-u", "nginx"}
		return run("www.m2.test", "--privileged", "--cgroupns=private", "--tmpfs", "/run", "--tmpfs", "/run/lock",
			"-v", mount(m2, "/m2"), "-v", mount(boot, "/bootstrap"), systemdImage)
	})
	c := s.nginx
	sh := func(cmd string) string {
		t.Helper()
		return docker(t, "", "exec", c, "sh", "-c", cmd)
	}
	unitProp := func(unit, prop string) string {
		t.Helper()
		return sh("systemctl show -p " + prop + " --value " + unit)
	}
	waitFor(t, 90*time.Second, "systemd to finish booting", func() bool {
		o, _ := tryDocker("exec", c, "systemctl", "is-system-running")
		return o == "running" || o == "degraded"
	})

	// --- install: the package must not enable or start the service ---
	docker(t, "", "cp", deb, c+":/root/certloom-agent.deb")
	sh("dpkg -i /root/certloom-agent.deb")
	if o, _ := tryDocker("exec", c, "systemctl", "is-enabled", "certloom-agent"); o != "disabled" {
		t.Fatalf("certloom-agent after install: is-enabled = %q, want disabled", o)
	}
	if o, _ := tryDocker("exec", c, "systemctl", "is-active", "certloom-agent"); o != "inactive" {
		t.Fatalf("certloom-agent after install: is-active = %q, want inactive", o)
	}
	if o := sh("stat -c '%a %U' /var/lib/certloom-agent"); o != "700 root" {
		t.Fatalf("/var/lib/certloom-agent: %q", o)
	}
	if o := sh("dpkg-query -W -f='${Conffiles}' certloom-agent"); !strings.Contains(o, "/etc/certloom-agent/config.yaml") {
		t.Fatalf("config.yaml is not a conffile: %q", o)
	}

	// --- configure nginx and the agent, enroll, enable ---
	docker(t, systemdAgentConfig, "exec", "-i", c, "sh", "-c", "cat > /etc/certloom-agent/config.yaml")
	sh("cp /m2/nginx.conf /etc/nginx/conf.d/certloom.conf && mkdir -p /var/www/acme && ln -sfn /bootstrap /etc/certloom/live/www && " +
		"echo hidden > /root/marker")
	sh("certloom-agent check-config && systemctl enable --now nginx")

	var tok struct {
		Token  string `json:"token"`
		CAHash string `json:"ca_hash"`
	}
	s.jsonCLI(&tok, "agent", "token", "--name", "web")
	docker(t, tok.Token+"\n", "exec", "-i", c, "certloom-agent", "enroll", "--ca-hash", tok.CAHash)
	sh("systemctl enable --now certloom-agent")
	waitFor(t, 60*time.Second, "agent heartbeat with target", func() bool {
		o, err := s.cli("agent", "list")
		return err == nil && strings.Contains(o, "active") && strings.Contains(o, "www")
	})

	// --- the sandbox is in effect for the running agent ---
	agentPID := unitProp("certloom-agent", "MainPID")
	if st := sh("cat /proc/" + agentPID + "/status"); !strings.Contains(st, "NoNewPrivs:\t1") {
		t.Fatalf("agent runs without NoNewPrivs:\n%s", st)
	}
	mi := sh(`awk '$5=="/etc" || $5=="/etc/certloom" {print $5, substr($6, 1, 2)}' /proc/` + agentPID + `/mountinfo`)
	if !strings.Contains(mi, "/etc ro") || !strings.Contains(mi, "/etc/certloom rw") {
		t.Fatalf("expected /etc read-only and /etc/certloom writable in the agent's namespace, mountinfo:\n%s", mi)
	}
	if _, err := tryDocker("exec", c, "test", "-e", "/proc/"+agentPID+"/root/root/marker"); err == nil {
		t.Fatal("/root is visible to the agent despite ProtectHome")
	}
	sec, _ := tryDocker("exec", c, "systemd-analyze", "security", "--no-pager", "certloom-agent")
	if lines := strings.Split(sec, "\n"); len(lines) > 0 {
		t.Logf("systemd-analyze security: %s", lines[len(lines)-1])
	}

	// --- renewal configuration ---
	s.mustCLI("issuer", "create", "pebble", "--directory", "https://pebble:14000/dir", "--agree-tos")
	s.mustCLI("scope", "create", "lab", "--allow-private", "--allow-host", "*.m2.test", "--port", "443")
	var ep struct{ ID string }
	s.jsonCLI(&ep, "endpoint", "add", "www.m2.test", "--scope", "lab")
	s.mustCLI("inventory", "import", filepath.Join(s.tmp, "boot.pem"), "--lineage", "www")
	var dep struct{ ID string }
	s.jsonCLI(&dep, "deployment", "create", "--lineage", "www", "--agent", "web", "--target", "www", "--issuer", "pebble",
		"--endpoint", ep.ID, "--san", "www.m2.test")

	nginxPID := unitProp("nginx", "MainPID")
	nginxJournal := func() string { return sh("journalctl -u nginx --no-pager -o cat") }
	checkReloadedNotRestarted := func(minReloads int) {
		t.Helper()
		if p := unitProp("nginx", "MainPID"); p != nginxPID {
			t.Fatalf("nginx main PID changed from %s to %s: it was restarted, not reloaded", nginxPID, p)
		}
		if n := unitProp("nginx", "NRestarts"); n != "0" {
			t.Fatalf("nginx NRestarts = %s", n)
		}
		j := nginxJournal()
		if n := strings.Count(j, "Reloaded nginx.service"); n < minReloads {
			t.Fatalf("journal shows %d reloads of nginx.service, want >= %d:\n%s", n, minReloads, j)
		}
		if strings.Count(j, "Started nginx.service") != 1 || strings.Contains(j, "Stopping nginx.service") {
			t.Fatalf("nginx.service was started or stopped more than once:\n%s", j)
		}
	}

	// --- 1: renewal through Pebble, deployed by the service, nginx reloaded by systemd ---
	r1 := renewAndWait(t, s, dep.ID)
	if r1.State != "verified" || r1.Issued == nil {
		t.Fatalf("first renewal: %+v", r1)
	}
	waitFor(t, 45*time.Second, "endpoint serving the issued certificate", func() bool { return servedLeaf(s, ep.ID) == *r1.Issued })
	if l := sh("readlink /etc/certloom/live/www"); l != "/var/lib/certloom-agent/certs/www/"+r1.ID {
		t.Fatalf("live link points at %q", l)
	}
	checkReloadedNotRestarted(1)
	if j := sh("journalctl -u certloom-agent --no-pager -o cat"); !strings.Contains(j, "certloom-agent running") {
		t.Fatalf("agent journal lacks the startup line:\n%s", j)
	}

	// --- 2: the service survives a restart and keeps working ---
	sh("systemctl restart certloom-agent")
	waitFor(t, 30*time.Second, "certloom-agent active after restart", func() bool {
		o, _ := tryDocker("exec", c, "systemctl", "is-active", "certloom-agent")
		return o == "active"
	})
	if p := unitProp("certloom-agent", "MainPID"); p == agentPID || p == "0" {
		t.Fatalf("certloom-agent main PID after restart: %s (before %s)", p, agentPID)
	}
	r2 := renewAndWait(t, s, dep.ID)
	if r2.State != "verified" || r2.Issued == nil || *r2.Issued == *r1.Issued {
		t.Fatalf("renewal after restart: %+v", r2)
	}
	waitFor(t, 45*time.Second, "endpoint serving the second certificate", func() bool { return servedLeaf(s, ep.ID) == *r2.Issued })
	checkReloadedNotRestarted(2)
	time.Sleep(2 * time.Second)
	if o, _ := tryDocker("exec", c, "systemctl", "is-active", "certloom-agent"); o != "active" {
		t.Fatalf("certloom-agent is %q at the end of the test", o)
	}
	if n := unitProp("certloom-agent", "NRestarts"); n != "0" {
		t.Fatalf("certloom-agent restarted on failure %s times", n)
	}
}
