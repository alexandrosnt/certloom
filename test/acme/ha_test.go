package acme

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// psql runs a query as the schema owner and returns the trimmed output.
func (s *stack) psql(query string) string {
	return strings.TrimSpace(docker(s.t, "", "exec", s.pg, "psql", "-U", "certloom_owner", "-d", "certloom", "-tAc", query))
}

// leaderContainer returns the replica holding the scheduler lease, or "".
// Worker ids are "<hostname>-<pid>" and a container's hostname is its short id.
func (s *stack) leaderContainer() string {
	holder := s.psql(`SELECT holder FROM leader WHERE name = 'scheduler' AND expires_at > now()`)
	for _, c := range s.replicas {
		if holder != "" && strings.HasPrefix(holder, c[:12]+"-") {
			return c
		}
	}
	return ""
}

// TestHAReplicas runs two certloomd replicas behind a TCP load balancer
// (ADR-0033). It kills the scheduler leader with SIGKILL in the middle of a
// renewal, checks that the other replica takes over and finishes the run
// with every agent task sent once, then restarts PostgreSQL under both.
func TestHAReplicas(t *testing.T) {
	s := upWith(t, upOptions{replicas: 2})
	s.enrollWeb()
	s.mustCLI("issuer", "create", "pebble", "--directory", "https://pebble:14000/dir", "--agree-tos")
	s.mustCLI("scope", "create", "lab", "--allow-private", "--allow-host", "*.m2.test", "--port", "443")
	var ep struct{ ID string }
	s.jsonCLI(&ep, "endpoint", "add", "www.m2.test", "--scope", "lab")
	s.mustCLI("inventory", "import", filepath.Join(s.tmp, "boot.pem"), "--lineage", "www")
	var dep struct{ ID string }
	s.jsonCLI(&dep, "deployment", "create", "--lineage", "www", "--agent", "web", "--target", "www", "--issuer", "pebble",
		"--endpoint", ep.ID, "--san", "www.m2.test")

	var first string
	waitFor(t, 30*time.Second, "a scheduler leader", func() bool { first = s.leaderContainer(); return first != "" })
	if r := renewAndWait(t, s, dep.ID); r.State != "verified" {
		t.Fatalf("renewal with both replicas: %s %s", r.State, r.Error)
	}

	// Freeze the agent so the renewal is certainly in flight, then kill the
	// leader while the run waits for its first task.
	docker(t, "", "pause", s.nginx)
	var r sysRun
	s.jsonCLI(&r, "deployment", "renew", dep.ID)
	waitFor(t, 60*time.Second, "the first task of run "+r.ID, func() bool {
		return s.psql(`SELECT count(*) FROM agent_tasks WHERE run_id = '`+r.ID+`'`) != "0"
	})
	docker(t, "", "kill", "--signal", "KILL", first)
	docker(t, "", "unpause", s.nginx)

	var next string
	waitFor(t, 60*time.Second, "another replica to take the lease", func() bool {
		next = s.leaderContainer()
		return next != "" && next != first
	})
	// Jobs the dead replica held come back when their lease (2m) expires.
	waitFor(t, 5*time.Minute, "run "+r.ID+" to finish", func() bool {
		s.jsonCLI(&r, "run", "show", r.ID)
		return r.State == "verified" || r.State == "failed" || r.State == "rolled_back" || r.State == "cancelled"
	})
	if r.State != "verified" {
		t.Fatalf("run after killing the leader: %s %s", r.State, r.Error)
	}
	if dup := s.psql(`SELECT string_agg(type || '=' || n, ',') FROM (SELECT type, count(*) n FROM agent_tasks
		WHERE run_id = '` + r.ID + `' AND state = 'succeeded' GROUP BY type HAVING count(*) > 1) d`); dup != "" {
		t.Fatalf("tasks executed more than once: %s", dup)
	}

	// Both the API and the scheduler survive a database restart.
	docker(t, "", "restart", s.pg)
	waitFor(t, 60*time.Second, "postgres after restart", func() bool {
		_, err := tryDocker("exec", s.pg, "psql", "-U", "certloom_owner", "-d", "certloom", "-c", "select 1")
		return err == nil
	})
	waitFor(t, 60*time.Second, "a leader after the restart", func() bool { return s.leaderContainer() == next })
	waitFor(t, 60*time.Second, "the API after the restart", func() bool {
		_, err := s.cli("deployment", "list")
		return err == nil
	})
	if r := renewAndWait(t, s, dep.ID); r.State != "verified" {
		t.Fatalf("renewal after the database restart: %s %s", r.State, r.Error)
	}
}
