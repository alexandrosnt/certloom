package jobs_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
	"github.com/jackc/pgx/v5"
)

var ctx = context.Background()

func enqueue(t *testing.T, db *storetest.DB, org, key string) bool {
	t.Helper()
	var ok bool
	err := db.WithoutOrg(ctx, func(tx pgx.Tx) (err error) {
		ok, err = jobs.Enqueue(ctx, tx, org, "test", key, map[string]string{"k": key}, time.Time{})
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return ok
}

func TestDedupeClaimCompleteAndFencing(t *testing.T) {
	db := storetest.New(t)
	org, _ := db.CreateOrg(ctx, "jobs")
	if !enqueue(t, db, org.ID, "a") || enqueue(t, db, org.ID, "a") {
		t.Fatal("second enqueue of an active job must be deduplicated")
	}
	w1 := &jobs.Queue{Pool: db.Pool, WorkerID: "w1", LeaseTTL: 300 * time.Millisecond}
	w2 := &jobs.Queue{Pool: db.Pool, WorkerID: "w2", LeaseTTL: time.Minute}

	got, err := w1.Claim(ctx, []string{"test"}, 10)
	if err != nil || len(got) != 1 {
		t.Fatalf("claim: %v %v", got, err)
	}
	j1 := got[0]
	if again, _ := w2.Claim(ctx, []string{"test"}, 10); len(again) != 0 {
		t.Fatal("a leased job must not be claimable by another worker")
	}

	// w1 stalls past its lease; w2 takes over with a higher epoch.
	time.Sleep(500 * time.Millisecond)
	got, err = w2.Claim(ctx, []string{"test"}, 10)
	if err != nil || len(got) != 1 || got[0].Epoch <= j1.Epoch {
		t.Fatalf("reclaim after lease expiry: %+v %v", got, err)
	}
	j2 := got[0]

	// The stale worker is fenced out.
	err = db.WithoutOrg(ctx, func(tx pgx.Tx) error { return jobs.Complete(ctx, tx, j1) })
	if !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatalf("stale complete: want ErrLeaseLost, got %v", err)
	}
	if err := w1.Fail(ctx, j1, errors.New("x"), false, 0); !errors.Is(err, jobs.ErrLeaseLost) {
		t.Fatalf("stale fail: want ErrLeaseLost, got %v", err)
	}
	if err := db.WithoutOrg(ctx, func(tx pgx.Tx) error { return jobs.Complete(ctx, tx, j2) }); err != nil {
		t.Fatalf("current lease complete: %v", err)
	}
	// Completed jobs no longer block a new job with the same key.
	if !enqueue(t, db, org.ID, "a") {
		t.Fatal("enqueue after completion should succeed")
	}
}

func TestFailRetriesThenFails(t *testing.T) {
	db := storetest.New(t)
	org, _ := db.CreateOrg(ctx, "retry")
	enqueue(t, db, org.ID, "r")
	if _, err := db.Pool.Exec(ctx, `UPDATE jobs SET max_attempts = 2`); err != nil {
		t.Fatal(err)
	}
	q := &jobs.Queue{Pool: db.Pool, WorkerID: "w"}
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := db.Pool.Exec(ctx, `UPDATE jobs SET run_at = now() WHERE state = 'pending'`); err != nil {
			t.Fatal(err)
		}
		got, err := q.Claim(ctx, []string{"test"}, 1)
		if err != nil || len(got) != 1 || got[0].Attempts != attempt {
			t.Fatalf("attempt %d: %+v %v", attempt, got, err)
		}
		if err := q.Fail(ctx, got[0], errors.New("boom"), false, 0); err != nil {
			t.Fatal(err)
		}
	}
	var state, lastErr string
	if err := db.Pool.QueryRow(ctx, `SELECT state, last_error FROM jobs`).Scan(&state, &lastErr); err != nil {
		t.Fatal(err)
	}
	if state != "failed" || lastErr != "boom" {
		t.Fatalf("state=%s err=%s", state, lastErr)
	}
}

func TestPauseSwitches(t *testing.T) {
	db := storetest.New(t)
	a, _ := db.CreateOrg(ctx, "pa")
	b, _ := db.CreateOrg(ctx, "pb")
	enqueue(t, db, a.ID, "x")
	enqueue(t, db, b.ID, "y")
	q := &jobs.Queue{Pool: db.Pool, WorkerID: "w"}

	if err := jobs.SetPaused(ctx, db.Pool, "org:"+a.ID, true, "test"); err != nil {
		t.Fatal(err)
	}
	got, _ := q.Claim(ctx, []string{"test"}, 10)
	if len(got) != 1 || got[0].OrgID != b.ID {
		t.Fatalf("paused org's job was claimed: %+v", got)
	}
	_ = jobs.SetPaused(ctx, db.Pool, "global", true, "test")
	_ = jobs.SetPaused(ctx, db.Pool, "org:"+a.ID, false, "")
	if got, _ := q.Claim(ctx, []string{"test"}, 10); len(got) != 0 {
		t.Fatalf("global pause ignored: %+v", got)
	}
}

func TestBackoffBounds(t *testing.T) {
	for attempt := 1; attempt < 20; attempt++ {
		d := jobs.Backoff(attempt, time.Minute, 6*time.Hour)
		if d < 30*time.Second || d > 6*time.Hour {
			t.Fatalf("attempt %d: %v out of bounds", attempt, d)
		}
	}
}
