package e2e

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/audit"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
	"github.com/jackc/pgx/v5"
)

// TestBackupRestoreDrill runs the restore procedure from the compose README:
// pg_dump a populated database, restore it into a fresh database, and check
// data, audit chain, row-level security and least-privilege grants survive.
func TestBackupRestoreDrill(t *testing.T) {
	ensureImage(t, pgClientImage)
	ctx := context.Background()
	src := storetest.New(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &app.Service{DB: src.DB, Log: log}

	org, err := src.CreateOrg(ctx, "drill")
	if err != nil {
		t.Fatal(err)
	}
	owner := authz.Principal{OrgID: org.ID, Actor: "user:drill", Role: store.RoleOwner}
	if _, err := svc.CreateTeam(ctx, owner, "sre", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.CreateScope(ctx, owner, "internet", store.ScopeConfig{AllowHosts: []string{"*.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.AddEndpoint(ctx, owner, app.AddEndpointInput{Host: "www.example.com", Scope: "internet"}); err != nil {
		t.Fatal(err)
	}

	dump := dockerPG(t, nil, src.OwnerURL, "pg_dump", "-Fc")
	if len(dump) < 1000 {
		t.Fatalf("dump suspiciously small: %d bytes", len(dump))
	}

	// Fresh, empty database (as a new server would have).
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "certloom_restore_" + hex.EncodeToString(b)
	admin, err := pgx.Connect(ctx, os.Getenv(storetest.EnvURL))
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close(ctx)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)") })

	ownerURL := swapDB(t, src.OwnerURL, name)
	dockerPG(t, dump, ownerURL, "pg_restore", "--no-owner", "--exit-on-error")
	// Re-running migrations on a restored database must be a no-op.
	if err := store.Migrate(ctx, ownerURL); err != nil {
		t.Fatalf("migrate after restore: %v", err)
	}

	restored, err := store.Open(ctx, swapDB(t, src.AppURL, name))
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	rsvc := &app.Service{DB: restored, Log: log}

	eps, err := rsvc.ListEndpoints(ctx, owner)
	if err != nil || len(eps) != 1 || eps[0].Host != "www.example.com" {
		t.Fatalf("endpoints after restore: %+v %v", eps, err)
	}
	v, err := rsvc.AuditVerify(ctx, owner)
	if err != nil || !v.OK || v.Checked != 3 {
		t.Fatalf("audit chain after restore: %+v %v", v, err)
	}
	// RLS still enforced: without an org, tenant rows are invisible.
	var n int
	if err := restored.Pool.QueryRow(ctx, `SELECT count(*) FROM endpoints`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("RLS lost after restore: saw %d rows (err %v)", n, err)
	}
	// Grants still least-privilege: the app role cannot rewrite audit.
	err = restored.WithOrg(ctx, org.ID, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE audit_events SET actor = 'x'`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("app role can modify audit after restore: %v", err)
	}
	// And the restored instance keeps working: new audited writes extend the chain.
	if _, err := rsvc.CreateTeam(ctx, owner, "after-restore", ""); err != nil {
		t.Fatal(err)
	}
	var evs []audit.Event
	_ = restored.WithOrg(ctx, org.ID, func(tx *store.Tx) (err error) { evs, err = audit.Query(ctx, tx, org.ID, 0, 100); return err })
	if len(evs) != 4 {
		t.Fatalf("audit events after new write: %d", len(evs))
	}
}

func swapDB(t *testing.T, raw, db string) string {
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + db
	return u.String()
}
