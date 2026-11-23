package leader_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/leader"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
)

func elector(db *storetest.DB, holder string, ttl time.Duration) *leader.Elector {
	return &leader.Elector{Pool: db.Pool, Name: "scheduler", Holder: holder, TTL: ttl,
		Every: ttl / 5, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestOneLeaderAndHandover(t *testing.T) {
	db := storetest.New(t)
	ctxA, stopA := context.WithCancel(context.Background())
	ctxB, stopB := context.WithCancel(context.Background())
	defer stopB()
	a, b := elector(db, "a", time.Second), elector(db, "b", time.Second)
	doneA := make(chan struct{})
	go func() { a.Run(ctxA); close(doneA) }()
	waitFor(t, "a to lead", a.IsLeader)
	go b.Run(ctxB)

	// b keeps trying for several TTLs while a renews; a must keep the lease.
	for range 30 {
		if b.IsLeader() {
			t.Fatal("two leaders at once")
		}
		if !a.IsLeader() {
			t.Fatal("a lost the lease while renewing it")
		}
		time.Sleep(100 * time.Millisecond)
	}

	// A clean shutdown releases the row, so b takes over well before the TTL.
	stopA()
	<-doneA
	if a.IsLeader() {
		t.Fatal("a still leads after stopping")
	}
	start := time.Now()
	waitFor(t, "b to lead", b.IsLeader)
	if d := time.Since(start); d > 900*time.Millisecond {
		t.Errorf("handover after release took %v", d)
	}
}

// A leader that dies without releasing is replaced once its lease expires.
func TestTakeoverAfterExpiry(t *testing.T) {
	db := storetest.New(t)
	ctx := context.Background()
	if _, err := db.Owner.Exec(ctx, `INSERT INTO leader (name, holder, expires_at) VALUES ('scheduler', 'dead', now() + interval '1 second')`); err != nil {
		t.Fatal(err)
	}
	bctx, stop := context.WithCancel(ctx)
	defer stop()
	b := elector(db, "b", time.Second)
	go b.Run(bctx)
	time.Sleep(500 * time.Millisecond)
	if b.IsLeader() {
		t.Fatal("took the lease before it expired")
	}
	waitFor(t, "b to take over", b.IsLeader)
	var holder string
	if err := db.Owner.QueryRow(ctx, `SELECT holder FROM leader WHERE name = 'scheduler'`).Scan(&holder); err != nil || holder != "b" {
		t.Fatalf("holder = %q, %v", holder, err)
	}
}
