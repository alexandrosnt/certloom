// Package storetest provisions a throwaway, migrated database for tests.
//
// Set CERTLOOM_TEST_DATABASE_URL to an owner/superuser connection URL, e.g.
// postgres://certloom_owner:devonly-not-secret@127.0.0.1:55432/certloom?sslmode=disable
// Tests are skipped when it is unset.
package storetest

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EnvURL is the environment variable holding the owner connection URL.
const EnvURL = "CERTLOOM_TEST_DATABASE_URL"

// appPassword is used only for throwaway test databases.
const appPassword = "certloom-app-test-only"

// DB is a test database with both the runtime (RLS-restricted) handle and an
// owner pool for setup and tamper tests.
type DB struct {
	*store.DB
	Owner    *pgxpool.Pool
	OwnerURL string
	AppURL   string
}

// New creates a fresh database, migrates it, and connects as certloom_app.
func New(t testing.TB) *DB {
	t.Helper()
	ctx := context.Background()
	base, ownerURL, admin := empty(t)
	defer admin.Close(ctx)

	if err := store.Migrate(ctx, ownerURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	// certloom_app is cluster-wide; allow login for tests only.
	if _, err := admin.Exec(ctx, "ALTER ROLE certloom_app LOGIN PASSWORD '"+appPassword+"'"); err != nil {
		t.Fatalf("enable certloom_app login: %v", err)
	}
	appURL := withDB(t, base, dbName(t, ownerURL), url.UserPassword("certloom_app", appPassword))
	db, err := store.Open(ctx, appURL)
	if err != nil {
		t.Fatalf("open as certloom_app: %v", err)
	}
	t.Cleanup(db.Close)
	owner, err := pgxpool.New(ctx, ownerURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(owner.Close)
	return &DB{DB: db, Owner: owner, OwnerURL: ownerURL, AppURL: appURL}
}

// Empty creates a fresh database without running migrations and returns its
// owner URL. The setup lock shared with other test packages is held until the
// test ends, because migrations create the cluster-wide certloom_app role.
func Empty(t testing.TB) string {
	t.Helper()
	_, ownerURL, admin := empty(t)
	t.Cleanup(func() { _ = admin.Close(context.Background()) })
	return ownerURL
}

// empty creates the database and takes the setup lock on the returned
// connection; closing the connection releases it.
func empty(t testing.TB) (base, ownerURL string, admin *pgx.Conn) {
	t.Helper()
	base = os.Getenv(EnvURL)
	if base == "" {
		t.Skipf("%s not set; skipping database test", EnvURL)
	}
	ctx := context.Background()
	admin, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect admin: %v", err)
	}

	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "certloom_test_" + hex.EncodeToString(b)
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		c, err := pgx.Connect(context.Background(), base)
		if err != nil {
			return
		}
		defer c.Close(context.Background())
		_, _ = c.Exec(context.Background(), "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})

	// Test packages run in parallel and share the cluster-wide certloom_app role;
	// serialize migration and role setup across processes.
	if _, err := admin.Exec(ctx, "SELECT pg_advisory_lock(7231001)"); err != nil {
		t.Fatalf("advisory lock: %v", err)
	}
	return base, withDB(t, base, name, nil), admin
}

func dbName(t testing.TB, rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Path[1:]
}

func withDB(t testing.TB, base, db string, user *url.Userinfo) string {
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + db
	if user != nil {
		u.User = user
	}
	return u.String()
}
