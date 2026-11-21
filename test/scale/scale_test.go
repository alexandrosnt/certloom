// Package scale measures single-node throughput
// and records numbers rather than asserting tight budgets, which would
// be flaky across machines; only gross regressions fail.
//
// Run: CERTLOOM_TEST_DATABASE_URL=... CERTLOOM_SCALE=1 go test -v -timeout 30m ./test/scale/
package scale

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/notify"
	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
	"github.com/alexandrosnt/certloom/internal/testpki"
	"github.com/alexandrosnt/certloom/internal/worker"
)

func envInt(k string, def int) int {
	if v, err := strconv.Atoi(os.Getenv(k)); err == nil && v > 0 {
		return v
	}
	return def
}

func TestScaleSingleNode(t *testing.T) {
	if os.Getenv("CERTLOOM_SCALE") == "" {
		t.Skip("set CERTLOOM_SCALE=1 to run the scale test")
	}
	nCerts := envInt("CERTLOOM_SCALE_CERTS", 10000)
	nEndpoints := envInt("CERTLOOM_SCALE_ENDPOINTS", 2000)
	concurrency := envInt("CERTLOOM_SCALE_CONCURRENCY", 64)
	ctx := context.Background()
	db := storetest.New(t)
	org, _ := db.CreateOrg(ctx, "scale")
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := &app.Service{DB: db.DB, Prober: probe.New(), Log: log}
	owner := authz.Principal{OrgID: org.ID, Actor: "user:scale", Role: store.RoleOwner}
	report := map[string]string{}

	// 1. Inventory: nCerts leaf certificates.
	ca := testpki.Issue(t, nil, testpki.Options{CommonName: "scale ca", IsCA: true})
	start := time.Now()
	certs := make([]*certparse.Certificate, nCerts)
	for i := range nCerts {
		c := testpki.Issue(t, ca, testpki.Options{CommonName: fmt.Sprintf("c%05d.scale.test", i), DNSNames: []string{fmt.Sprintf("c%05d.scale.test", i)},
			NotBefore: time.Now().Add(-time.Duration(i%300) * 24 * time.Hour), NotAfter: time.Now().Add(time.Duration(i%120+1) * 24 * time.Hour)})
		certs[i], _ = certparse.FromX509(c.Cert)
	}
	report["generate_certs"] = time.Since(start).Round(time.Millisecond).String()
	start = time.Now()
	for i := 0; i < nCerts; i += 500 {
		end := min(i+500, nCerts)
		if err := db.WithOrg(ctx, org.ID, func(tx *store.Tx) error {
			for _, c := range certs[i:end] {
				if _, err := tx.UpsertCertificate(ctx, c, "import"); err != nil {
					return err
				}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	report["insert_certs"] = time.Since(start).Round(time.Millisecond).String()

	// 2. Sweep: intrinsic checks for every certificate.
	if err := svc.ScheduleCertSweeps(ctx); err != nil {
		t.Fatal(err)
	}
	q := &jobs.Queue{Pool: db.Pool, WorkerID: "scale"}
	js, err := q.Claim(ctx, []string{app.JobKindCertSweep}, 1)
	if err != nil || len(js) != 1 {
		t.Fatalf("claim sweep: %v %d", err, len(js))
	}
	start = time.Now()
	if err := svc.RunCertSweep(ctx, js[0]); err != nil {
		t.Fatal(err)
	}
	sweep := time.Since(start)
	report["cert_sweep"] = sweep.Round(time.Millisecond).String()

	// 3. Read paths.
	start = time.Now()
	if _, err := svc.Overview(ctx, owner); err != nil {
		t.Fatal(err)
	}
	report["overview_query"] = time.Since(start).Round(time.Millisecond).String()
	start = time.Now()
	if _, err := svc.ListCertificates(ctx, owner, store.CertFilter{ExpiresBefore: time.Now().Add(30 * 24 * time.Hour), Limit: 100}); err != nil {
		t.Fatal(err)
	}
	report["list_expiring_30d"] = time.Since(start).Round(time.Millisecond).String()

	// 4. Probing: nEndpoints distinct SNI names on one local TLS server.
	port := sniServer(t, ca, nEndpoints)
	if _, err := svc.CreateScope(ctx, owner, "lab", store.ScopeConfig{AllowLoopback: true, Ports: []int{port}}); err != nil {
		t.Fatal(err)
	}
	for i := range nEndpoints {
		if _, err := svc.AddEndpoint(ctx, owner, app.AddEndpointInput{Host: "127.0.0.1", Port: port,
			SNI: fmt.Sprintf("e%05d.scale.test", i), Scope: "lab"}); err != nil {
			t.Fatal(err)
		}
	}
	wctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	start = time.Now()
	go func() {
		worker.Run(wctx, svc, &notify.Deliverer{DB: db.DB, Log: log}, worker.Config{WorkerID: "scale", Concurrency: concurrency,
			ScheduleEvery: time.Second, PollInterval: 100 * time.Millisecond}, log)
		close(done)
	}()
	deadline := time.Now().Add(15 * time.Minute)
	for {
		var observed int
		_ = db.WithOrg(ctx, org.ID, func(tx *store.Tx) error {
			return tx.QueryRow(ctx, `SELECT count(*) FROM endpoints WHERE last_observed_at IS NOT NULL`).Scan(&observed)
		})
		if observed == nEndpoints {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("probe sweep incomplete after 15m: %d/%d", observed, nEndpoints)
		}
		time.Sleep(500 * time.Millisecond)
	}
	probeSweep := time.Since(start)
	cancel()
	<-done
	report["probe_sweep"] = probeSweep.Round(time.Millisecond).String()
	report["probe_rate_per_s"] = fmt.Sprintf("%.0f", float64(nEndpoints)/probeSweep.Seconds())

	var failed int
	_ = db.WithOrg(ctx, org.ID, func(tx *store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM endpoints WHERE consecutive_failures > 0`).Scan(&failed)
	})
	report["probe_failures"] = strconv.Itoa(failed)

	t.Logf("SCALE RESULTS certs=%d endpoints=%d concurrency=%d", nCerts, nEndpoints, concurrency)
	for _, k := range []string{"generate_certs", "insert_certs", "cert_sweep", "overview_query", "list_expiring_30d", "probe_sweep", "probe_rate_per_s", "probe_failures"} {
		t.Logf("  %-18s %s", k, report[k])
	}
	// Gross-regression guards only.
	if sweep > 5*time.Minute {
		t.Errorf("certificate sweep took %s (> 5m)", sweep)
	}
	if failed > 0 {
		t.Errorf("%d endpoints failed to probe", failed)
	}
}

// sniServer serves a distinct certificate per SNI name eNNNNN.scale.test.
func sniServer(t *testing.T, ca *testpki.Cert, n int) int {
	certs := make(map[string]*tls.Certificate, n)
	var mu sync.Mutex
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		mu.Lock()
		defer mu.Unlock()
		if c, ok := certs[h.ServerName]; ok {
			return c, nil
		}
		leaf := testpki.Issue(t, ca, testpki.Options{CommonName: h.ServerName, DNSNames: []string{h.ServerName}})
		c := &tls.Certificate{Certificate: [][]byte{leaf.DER, ca.DER}, PrivateKey: leaf.Key}
		certs[h.ServerName] = c
		return c, nil
	}}
	tl := tls.NewListener(ln, cfg)
	t.Cleanup(func() { _ = tl.Close() })
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			go func() {
				_ = c.(*tls.Conn).Handshake()
				_ = c.Close()
			}()
		}
	}()
	return ln.Addr().(*net.TCPAddr).Port
}
