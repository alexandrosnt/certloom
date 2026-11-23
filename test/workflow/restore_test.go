package workflow

import (
	"testing"

	"github.com/alexandrosnt/certloom/internal/store"
)

// After a database restore the control plane's task sequence for a target can
// be behind what the agent has already executed. The agent reports its fence
// in the heartbeat and the control plane catches up, so the next renewal is
// not rejected as stale (ADR-0033).
func TestRestoredSequenceCatchesUp(t *testing.T) {
	e := newEnv(t)
	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified {
		t.Fatalf("first renewal: %s %q", r.State, r.Error)
	}
	var before int64
	if err := e.db.Owner.QueryRow(ctx, `SELECT target_seq FROM deployments WHERE id = $1`, e.dep.ID).Scan(&before); err != nil || before == 0 {
		t.Fatalf("target_seq = %d, %v", before, err)
	}

	// Simulate restoring a backup taken before the first renewal.
	if _, err := e.db.Owner.Exec(ctx, `UPDATE deployments SET target_seq = 0 WHERE id = $1`, e.dep.ID); err != nil {
		t.Fatal(err)
	}
	if err := e.agent.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	var after int64
	if err := e.db.Owner.QueryRow(ctx, `SELECT target_seq FROM deployments WHERE id = $1`, e.dep.ID).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("target_seq after heartbeat = %d, want %d", after, before)
	}
	if r := e.renewOnce(e.dep.ID); r.State != store.RunVerified || r.Attempt != 1 {
		t.Fatalf("renewal after restore: %s attempt %d %q", r.State, r.Attempt, r.Error)
	}

	// A heartbeat never lowers the sequence.
	if err := e.agent.Heartbeat(ctx); err != nil {
		t.Fatal(err)
	}
	var last int64
	_ = e.db.Owner.QueryRow(ctx, `SELECT target_seq FROM deployments WHERE id = $1`, e.dep.ID).Scan(&last)
	if last <= before {
		t.Fatalf("target_seq = %d after second renewal, want > %d", last, before)
	}
}
