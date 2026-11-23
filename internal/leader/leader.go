// Package leader elects one certloomd replica to run the periodic schedulers
// (ADR-0033). The leader holds a row in the leader table and renews it; when
// it stops renewing, another replica takes the row after it expires.
package leader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Elector takes and renews the lease for one name.
type Elector struct {
	Pool   *pgxpool.Pool
	Name   string        // role, e.g. "scheduler"
	Holder string        // this replica's id
	TTL    time.Duration // lease length, default 15s
	Every  time.Duration // renewal interval, default TTL/3
	Log    *slog.Logger

	mu    sync.Mutex
	until time.Time // local deadline; carries a monotonic reading
}

func (e *Elector) ttl() time.Duration {
	if e.TTL <= 0 {
		return 15 * time.Second
	}
	return e.TTL
}

// IsLeader reports whether this replica holds the lease right now.
func (e *Elector) IsLeader() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return time.Now().Before(e.until)
}

// Run renews the lease until ctx ends, then gives it up so another replica
// can take over without waiting for it to expire.
func (e *Elector) Run(ctx context.Context) {
	every := e.Every
	if every <= 0 {
		every = e.ttl() / 3
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		e.attempt(ctx)
		select {
		case <-ctx.Done():
			e.release()
			return
		case <-t.C:
		}
	}
}

// attempt takes or renews the lease. The local deadline is counted from
// before the query, so this replica stops acting as leader no later than the
// database lets another one take over.
func (e *Elector) attempt(ctx context.Context) {
	start := time.Now()
	var holder string
	err := e.Pool.QueryRow(ctx, `
		INSERT INTO leader (name, holder, expires_at) VALUES ($1, $2, now() + $3::interval)
		ON CONFLICT (name) DO UPDATE SET holder = EXCLUDED.holder, expires_at = EXCLUDED.expires_at
		WHERE leader.holder = EXCLUDED.holder OR leader.expires_at < now()
		RETURNING holder`,
		e.Name, e.Holder, fmt.Sprintf("%d milliseconds", e.ttl().Milliseconds())).Scan(&holder)
	won := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) && ctx.Err() == nil {
		e.Log.Warn("leader lease", "name", e.Name, "error", err)
	}
	e.mu.Lock()
	was := time.Now().Before(e.until)
	if won {
		e.until = start.Add(e.ttl())
	} else {
		e.until = time.Time{}
	}
	e.mu.Unlock()
	if won != was {
		e.Log.Info("leadership changed", "name", e.Name, "leader", won)
	}
}

func (e *Elector) release() {
	e.mu.Lock()
	e.until = time.Time{}
	e.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = e.Pool.Exec(ctx, `DELETE FROM leader WHERE name = $1 AND holder = $2`, e.Name, e.Holder)
}
