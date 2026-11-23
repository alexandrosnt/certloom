package acme

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDRRestoreWithAgent restores a database backup that is older than the
// agent's last tasks (ADR-0033). The control plane comes back with the same
// KEK; the audit chain must verify and the enrolled agent must renew again
// without enrolling anew.
func TestDRRestoreWithAgent(t *testing.T) {
	s := up(t)
	s.enrollWeb()
	s.mustCLI("issuer", "create", "pebble", "--directory", "https://pebble:14000/dir", "--agree-tos")
	s.mustCLI("scope", "create", "lab", "--allow-private", "--allow-host", "*.m2.test", "--port", "443")
	var ep struct{ ID string }
	s.jsonCLI(&ep, "endpoint", "add", "www.m2.test", "--scope", "lab")
	s.mustCLI("inventory", "import", filepath.Join(s.tmp, "boot.pem"), "--lineage", "www")
	var dep struct{ ID string }
	s.jsonCLI(&dep, "deployment", "create", "--lineage", "www", "--agent", "web", "--target", "www", "--issuer", "pebble",
		"--endpoint", ep.ID, "--san", "www.m2.test")

	if r := renewAndWait(t, s, dep.ID); r.State != "verified" {
		t.Fatalf("renewal before the backup: %s %s", r.State, r.Error)
	}
	docker(t, "", "exec", s.pg, "pg_dump", "-U", "certloom_owner", "-d", "certloom", "-Fc", "-f", "/tmp/backup.dump")
	backupSeq := s.psql(`SELECT target_seq FROM deployments WHERE id = '` + dep.ID + `'`)
	if r := renewAndWait(t, s, dep.ID); r.State != "verified" {
		t.Fatalf("renewal after the backup: %s %s", r.State, r.Error)
	}

	// Disaster: restore the older backup into a new, empty database.
	docker(t, "", "stop", s.certloomd)
	docker(t, "", "exec", s.pg, "dropdb", "-U", "certloom_owner", "--force", "certloom")
	docker(t, "", "exec", s.pg, "createdb", "-U", "certloom_owner", "certloom")
	docker(t, "", "exec", s.pg, "pg_restore", "-U", "certloom_owner", "-d", "certloom", "--no-owner",
		"--role=certloom_owner", "--exit-on-error", "/tmp/backup.dump")
	if got := s.psql(`SELECT target_seq FROM deployments WHERE id = '` + dep.ID + `'`); got != backupSeq {
		t.Fatalf("restored target_seq = %s, want %s", got, backupSeq)
	}
	docker(t, "", "start", s.certloomd)
	// The container gets a new host port when it starts again.
	s.apiURL = "http://" + strings.Split(docker(t, "", "port", s.certloomd, "8443/tcp"), "\n")[0]
	waitFor(t, 60*time.Second, "certloomd after the restore", func() bool {
		_, err := s.cli("status")
		return err == nil
	})
	if out, err := s.cli("audit", "verify"); err != nil {
		t.Fatalf("audit chain after the restore: %v\n%s", err, out)
	}
	waitFor(t, 60*time.Second, "the agent to catch up the task sequence", func() bool {
		return s.psql(`SELECT target_seq FROM deployments WHERE id = '`+dep.ID+`'`) != backupSeq
	})
	if r := renewAndWait(t, s, dep.ID); r.State != "verified" {
		t.Fatalf("renewal after the restore: %s %s", r.State, r.Error)
	}
	if logs, _ := tryDocker("logs", s.certloomd); !strings.Contains(logs, "raised task sequences") {
		t.Error("certloomd did not log the sequence catch-up")
	}
}
