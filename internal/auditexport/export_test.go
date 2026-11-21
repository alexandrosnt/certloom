package auditexport_test

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/audit"
	"github.com/alexandrosnt/certloom/internal/auditexport"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
)

var ctx = context.Background()

func writeEvents(t *testing.T, db *storetest.DB, org string, n int) {
	t.Helper()
	for i := range n {
		err := db.WithOrg(ctx, org, func(tx *store.Tx) error {
			return audit.Write(ctx, tx, &audit.Event{OrgID: org, Actor: "user:test", Action: "test.action",
				ResourceType: "thing", ResourceID: "t", Detail: map[string]any{"i": i, "note": "ok"}})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestExportVerifyAndDetectConsistentRewrite(t *testing.T) {
	db := storetest.New(t)
	a, _ := db.CreateOrg(ctx, "a")
	b, _ := db.CreateOrg(ctx, "b")
	writeEvents(t, db, a.ID, 7)
	writeEvents(t, db, b.ID, 3)

	path := filepath.Join(t.TempDir(), "audit.jsonl")
	x := &auditexport.Exporter{DB: db.DB, Sink: &auditexport.FileSink{Path: path}, Batch: 4}
	n, err := x.RunOnce(ctx)
	if err != nil || n != 10 {
		t.Fatalf("export: n=%d err=%v", n, err)
	}
	// Idempotent: nothing new to export.
	if n, _ := x.RunOnce(ctx); n != 0 {
		t.Fatalf("second export sent %d events", n)
	}
	writeEvents(t, db, a.ID, 2)
	if n, _ := x.RunOnce(ctx); n != 2 {
		t.Fatalf("incremental export sent %d, want 2", n)
	}

	raw, _ := os.ReadFile(path)
	rep, err := auditexport.VerifyStream(bytes.NewReader(raw))
	if err != nil || !rep.OK || rep.Orgs[a.ID].LastSeq != 9 || rep.Orgs[b.ID].LastSeq != 3 {
		t.Fatalf("verify stream: %+v %v", rep, err)
	}

	// At-least-once redelivery (identical lines) is tolerated.
	dup := append(append([]byte{}, raw...), raw...)
	if rep, _ := auditexport.VerifyStream(bytes.NewReader(dup)); !rep.OK || rep.Duplicates != 12 {
		t.Fatalf("duplicates: %+v", rep)
	}

	// Status reports zero lag.
	_ = db.WithOrg(ctx, a.ID, func(tx *store.Tx) error {
		st, err := auditexport.GetStatus(ctx, tx)
		if err != nil || len(st) != 1 || st[0].Lag != 0 || st[0].LastSeq != 9 {
			t.Fatalf("status: %+v %v", st, err)
		}
		return nil
	})

	// Attack: a DB owner rewrites event 4 AND recomputes the whole chain so the
	// in-database verification still passes.
	rewriteChain(t, db, a.ID, 4)
	err = db.WithOrg(ctx, a.ID, func(tx *store.Tx) error {
		v, err := audit.Verify(ctx, tx, a.ID)
		if err != nil {
			return err
		}
		if !v.OK {
			t.Fatalf("precondition: rewritten chain should be internally consistent: %+v", v)
		}
		exported, err := auditexport.ReadStream(bytes.NewReader(raw), a.ID)
		if err != nil {
			return err
		}
		mm, err := auditexport.CompareWithDB(ctx, tx, exported)
		if err != nil {
			return err
		}
		if len(mm) == 0 || mm[0].Seq != 4 {
			t.Fatalf("consistent rewrite not detected: %+v", mm)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestVerifyStreamDetectsTampering(t *testing.T) {
	db := storetest.New(t)
	o, _ := db.CreateOrg(ctx, "t")
	writeEvents(t, db, o.ID, 3)
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if _, err := (&auditexport.Exporter{DB: db.DB, Sink: &auditexport.FileSink{Path: path}}).RunOnce(ctx); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(path)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")

	edited := strings.Replace(string(raw), `"user:test"`, `"user:mallory"`, 1)
	if rep, _ := auditexport.VerifyStream(strings.NewReader(edited)); rep.OK {
		t.Fatal("edited export line not detected")
	}
	dropped := lines[0] + "\n" + lines[2] + "\n"
	if rep, _ := auditexport.VerifyStream(strings.NewReader(dropped)); rep.OK {
		t.Fatal("dropped export line not detected")
	}
}

// rewriteChain changes the actor of event seq and recomputes hashes from
// there on, exactly as an attacker with table-owner access could.
func rewriteChain(t *testing.T, db *storetest.DB, org string, from int64) {
	t.Helper()
	tx, err := db.Owner.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", org); err != nil {
		t.Fatal(err)
	}
	events, err := audit.Query(ctx, tx, org, 0, 1000)
	if err != nil {
		t.Fatal(err)
	}
	prev := make([]byte, 32)
	for i := range events {
		e := &events[i]
		if e.Seq == from {
			e.Actor = "user:mallory"
		}
		e.PrevHash = prev
		h, _ := audit.ComputeHash(e)
		e.Hash = h
		if _, err := tx.Exec(ctx, `UPDATE audit_events SET actor=$3, prev_hash=$4, hash=$5 WHERE org_id=$1 AND seq=$2`,
			org, e.Seq, e.Actor, e.PrevHash, e.Hash); err != nil {
			t.Fatal(err)
		}
		prev = e.Hash
	}
	if _, err := tx.Exec(ctx, `UPDATE audit_heads SET hash=$2 WHERE org_id=$1`, org, prev); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
}
