// Package worker runs the scheduler, job workers and notification delivery.
// All durable state lives in Postgres; these loops only poll it,
// so any number of replicas can run them concurrently.
package worker

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/auditexport"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/notify"
)

// Config tunes the loops.
type Config struct {
	WorkerID      string
	Concurrency   int           // parallel jobs, default 16
	PollInterval  time.Duration // job claim poll, default 1s
	ScheduleEvery time.Duration // due-probe scan, default 10s
	SweepEvery    time.Duration // certificate sweep, default 1h
	DeliverEvery  time.Duration // outbox drain, default 2s
	// AuditExporter, if set, runs every 5s.
	AuditExporter *auditexport.Exporter
}

func (c *Config) defaults() {
	if c.Concurrency <= 0 {
		c.Concurrency = 16
	}
	if c.PollInterval <= 0 {
		c.PollInterval = time.Second
	}
	if c.ScheduleEvery <= 0 {
		c.ScheduleEvery = 10 * time.Second
	}
	if c.SweepEvery <= 0 {
		c.SweepEvery = time.Hour
	}
	if c.DeliverEvery <= 0 {
		c.DeliverEvery = 2 * time.Second
	}
}

// Run blocks until ctx is cancelled, then waits for in-flight jobs.
func Run(ctx context.Context, svc *app.Service, d *notify.Deliverer, cfg Config, log *slog.Logger) {
	cfg.defaults()
	q := &jobs.Queue{Pool: svc.DB.Pool, WorkerID: cfg.WorkerID}
	var wg sync.WaitGroup
	loop := func(name string, every time.Duration, fn func(context.Context) error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			t := time.NewTicker(every)
			defer t.Stop()
			for {
				if err := fn(ctx); err != nil && !errors.Is(err, context.Canceled) {
					log.Error("loop error", "loop", name, "error", err)
				}
				select {
				case <-ctx.Done():
					return
				case <-t.C:
				}
			}
		}()
	}
	loop("schedule", cfg.ScheduleEvery, func(ctx context.Context) error {
		n, err := svc.ScheduleDueProbes(ctx)
		if n > 0 {
			log.Debug("scheduled probes", "count", n)
		}
		return err
	})
	loop("sweep", cfg.SweepEvery, svc.ScheduleCertSweeps)
	loop("deliver", cfg.DeliverEvery, func(ctx context.Context) error {
		_, err := d.RunOnce(ctx, 20)
		return err
	})

	loop("escalate", time.Minute, func(ctx context.Context) error {
		n, err := svc.EscalateAlerts(ctx)
		if n > 0 {
			log.Info("escalated alerts", "count", n)
		}
		return err
	})
	loop("prune", time.Hour, func(ctx context.Context) error {
		r, err := svc.Prune(ctx)
		if r.Observations+r.IdempotencyKeys+r.Sessions > 0 {
			log.Info("pruned", "observations", r.Observations, "idempotency_keys", r.IdempotencyKeys, "sessions", r.Sessions)
		}
		return err
	})
	if cfg.AuditExporter != nil {
		loop("audit-export", 5*time.Second, func(ctx context.Context) error {
			_, err := cfg.AuditExporter.RunOnce(ctx)
			return err
		})
	}

	kinds := []string{app.JobKindProbe, app.JobKindCertSweep}
	if svc.PKI != nil {
		kinds = append(kinds, app.JobKindAdvance, app.JobKindARICheck)
		loop("renewals", cfg.ScheduleEvery, func(ctx context.Context) error {
			n, err := svc.ScheduleRenewals(ctx)
			if n > 0 {
				log.Info("started renewal runs", "count", n)
			}
			return err
		})
	}
	sem := make(chan struct{}, cfg.Concurrency)
	loop("jobs", cfg.PollInterval, func(ctx context.Context) error {
		for {
			free := cap(sem) - len(sem)
			if free == 0 || ctx.Err() != nil {
				return nil
			}
			claimed, err := q.Claim(ctx, kinds, free)
			if err != nil || len(claimed) == 0 {
				return err
			}
			for _, j := range claimed {
				sem <- struct{}{}
				wg.Add(1)
				go func(j jobs.Job) {
					defer wg.Done()
					defer func() { <-sem }()
					// Jobs get their own context so shutdown lets them finish (bounded by the lease).
					jctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
					defer cancel()
					var err error
					switch j.Kind {
					case app.JobKindProbe:
						err = svc.RunProbeJob(jctx, j)
					case app.JobKindCertSweep:
						err = svc.RunCertSweep(jctx, j)
					case app.JobKindAdvance:
						err = svc.RunAdvance(jctx, j)
					case app.JobKindARICheck:
						err = svc.RunARICheck(jctx, j)
					}
					if err != nil {
						if errors.Is(err, jobs.ErrLeaseLost) {
							log.Warn("job lease lost; another worker owns it", "job", j.ID, "kind", j.Kind)
							return
						}
						log.Error("job failed", "job", j.ID, "kind", j.Kind, "attempt", j.Attempts, "error", err)
						if ferr := q.Fail(jctx, j, err, false, 0); ferr != nil && !errors.Is(ferr, jobs.ErrLeaseLost) {
							log.Error("record job failure", "job", j.ID, "error", ferr)
						}
					}
				}(j)
			}
		}
	})
	<-ctx.Done()
	wg.Wait()
}
