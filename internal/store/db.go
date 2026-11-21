// Package store owns PostgreSQL access: pooling, migrations and the
// org-scoped transaction helper that makes row-level security effective.
package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var migrations embed.FS

// ErrNotFound is returned when a row does not exist or is not visible to the org.
var ErrNotFound = errors.New("not found")

// DB wraps a pgx pool.
type DB struct{ Pool *pgxpool.Pool }

// Open connects to Postgres. The URL should use the runtime (certloom_app) role.
func Open(ctx context.Context, url string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return &DB{Pool: pool}, nil
}

// Close releases the pool.
func (db *DB) Close() { db.Pool.Close() }

// Migrate applies all pending migrations. ownerURL must use the schema owner role.
func Migrate(ctx context.Context, ownerURL string) error {
	cfg, err := pgx.ParseConfig(ownerURL)
	if err != nil {
		return fmt.Errorf("parse database url: %w", err)
	}
	sqldb := stdlib.OpenDB(*cfg)
	defer sqldb.Close()
	return migrate(ctx, sqldb)
}

func migrate(ctx context.Context, sqldb *sql.DB) error {
	p, err := goose.NewProvider(goose.DialectPostgres, sqldb, migrationsFS())
	if err != nil {
		return err
	}
	_, err = p.Up(ctx)
	return err
}

func migrationsFS() fs.FS {
	sub, err := fs.Sub(migrations, "migrations")
	if err != nil {
		panic(err) // embedded path is fixed at compile time
	}
	return sub
}

// Tx is an org-scoped transaction. All tenant queries go through it.
type Tx struct {
	pgx.Tx
	OrgID string
}

// WithOrg runs fn in a transaction with app.org_id set, so RLS restricts every
// query to orgID. The transaction commits if fn returns nil.
func (db *DB) WithOrg(ctx context.Context, orgID string, fn func(tx *Tx) error) error {
	if orgID == "" {
		return errors.New("store: empty org id")
	}
	return pgx.BeginFunc(ctx, db.Pool, func(t pgx.Tx) error {
		if _, err := t.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", orgID); err != nil {
			return err
		}
		return fn(&Tx{Tx: t, OrgID: orgID})
	})
}

// WithoutOrg runs fn in a transaction with no org set. Only cross-org
// system tables (jobs, outbox, organizations, switches) are visible.
func (db *DB) WithoutOrg(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return pgx.BeginFunc(ctx, db.Pool, fn)
}

func notFound(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
