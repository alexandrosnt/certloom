// Command certloomd is the certloom control plane: API, UI, scheduler and workers.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentapi"
	"github.com/alexandrosnt/certloom/internal/agentpki"
	"github.com/alexandrosnt/certloom/internal/api"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/ari"
	"github.com/alexandrosnt/certloom/internal/audit"
	"github.com/alexandrosnt/certloom/internal/auditexport"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/kek"
	"github.com/alexandrosnt/certloom/internal/notify"
	"github.com/alexandrosnt/certloom/internal/oidcauth"
	"github.com/alexandrosnt/certloom/internal/probe"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/version"
	"github.com/alexandrosnt/certloom/internal/web"
	"github.com/alexandrosnt/certloom/internal/worker"
)

const usage = `certloomd: certificate lifecycle management control plane

Usage:
  certloomd setup       configure a package install on this host (root): database,
                   key, TLS certificate, settings, service, first organization
  certloomd serve       run API, UI, scheduler and workers
  certloomd migrate     apply database migrations (uses CERTLOOM_MIGRATE_DATABASE_URL)
  certloomd bootstrap   create an organization and print a one-time owner token
  certloomd audit-verify-export FILE [--compare]
                   verify an exported audit stream; with --compare, also check
                   that every exported event is unchanged in the database
  certloomd gen-kek     print a new random key-encryption key (for CERTLOOM_KEK_FILE)
  certloomd version     print version

Environment:
  CERTLOOM_DATABASE_URL           runtime connection (role certloom_app or a member of it)
  CERTLOOM_MIGRATE_DATABASE_URL   schema-owner connection, used only by "migrate"
  CERTLOOM_LISTEN                 listen address (default 127.0.0.1:8443)
  CERTLOOM_TLS_CERT, CERTLOOM_TLS_KEY  server certificate and key files
  CERTLOOM_TRUST_BUNDLE           PEM file of extra trust anchors for checks (optional)
  CERTLOOM_AUDIT_EXPORT           external audit sink: file:/path or webhook:https://...
  CERTLOOM_AUDIT_EXPORT_KEY_REF   HMAC key reference for the webhook sink, e.g. env:NAME
  CERTLOOM_OIDC_ISSUER            OIDC issuer URL (enables single sign-on)
  CERTLOOM_OIDC_CLIENT_ID         confidential web client id
  CERTLOOM_OIDC_CLIENT_SECRET_REF its secret, e.g. env:CERTLOOM_OIDC_CLIENT_SECRET or file:/run/secrets/oidc
  CERTLOOM_OIDC_REDIRECT_URL      https://<host>/auth/oidc/callback
  CERTLOOM_OIDC_CLI_CLIENT_ID     public client id for "certloom login --oidc" (device flow; optional)
  CERTLOOM_AGENT_LISTEN           agent mTLS listener, e.g. 0.0.0.0:8444 (enables agents and renewals)
  CERTLOOM_KEK_FILE / CERTLOOM_KEK     key-encryption key (base64, 32 bytes) protecting the agent CA and task key
  CERTLOOM_AGENT_SERVER_NAMES     comma-separated names/IPs for the agent listener certificate
  CERTLOOM_AGENT_PUBLIC_URL       URL agents use to reach the listener (shown in enrollment commands)
  CERTLOOM_ACME_CA_FILE           extra trust anchors for private ACME directories (ARI polling)
  CERTLOOM_LOG_LEVEL              debug, info (default), warn, error
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel()}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var err error
	switch os.Args[1] {
	case "serve":
		err = serve(ctx, log, os.Args[2:])
	case "migrate":
		err = migrate(ctx)
	case "setup":
		err = setup(ctx, os.Args[2:])
	case "bootstrap":
		err = bootstrap(ctx, os.Args[2:])
	case "audit-verify-export":
		err = verifyExport(ctx, os.Args[2:])
	case "gen-kek":
		fmt.Println(kek.Generate())
		fmt.Fprintln(os.Stderr, "Store this key-encryption key in a file readable only by certloomd (CERTLOOM_KEK_FILE) and back it up separately from the database.")
	case "version", "--version":
		fmt.Println("certloomd", version.String())
	case "help", "-h", "--help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
	if err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func logLevel() slog.Level {
	switch strings.ToLower(os.Getenv("CERTLOOM_LOG_LEVEL")) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	}
	return slog.LevelInfo
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func migrate(ctx context.Context) error {
	url := os.Getenv("CERTLOOM_MIGRATE_DATABASE_URL")
	if url == "" {
		return errors.New("CERTLOOM_MIGRATE_DATABASE_URL is required")
	}
	if err := store.Migrate(ctx, url); err != nil {
		return err
	}
	fmt.Println("migrations applied")
	return nil
}

func openDB(ctx context.Context) (*store.DB, error) {
	url := os.Getenv("CERTLOOM_DATABASE_URL")
	if url == "" {
		return nil, errors.New("CERTLOOM_DATABASE_URL is required")
	}
	return store.Open(ctx, url)
}

func bootstrap(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("bootstrap", flag.ExitOnError)
	org := fs.String("org", "", "organization name (required)")
	ttl := fs.Duration("ttl", 24*time.Hour, "owner token lifetime; create longer-lived tokens later with least privilege")
	_ = fs.Parse(args)
	if *org == "" {
		return errors.New("--org is required")
	}
	db, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer db.Close()
	id, plain, err := createOrg(ctx, db, *org, *ttl)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Created organization %q (%s).\nOwner token (shown once, expires in %s):\n", *org, id, *ttl)
	fmt.Println(plain)
	return nil
}

// createOrg creates an organization and a one-time owner token for it.
func createOrg(ctx context.Context, db *store.DB, name string, ttl time.Duration) (id, token string, err error) {
	o, err := db.CreateOrg(ctx, name)
	if err != nil {
		return "", "", fmt.Errorf("create org: %w", err)
	}
	err = db.WithOrg(ctx, o.ID, func(tx *store.Tx) error {
		t, v, err := tx.CreateToken(ctx, "bootstrap", store.RoleOwner, "system:bootstrap", ttl)
		if err != nil {
			return err
		}
		token = v.RevealString()
		return audit.Write(ctx, tx, &audit.Event{OrgID: o.ID, Actor: "system:bootstrap", Action: "org.bootstrap",
			ResourceType: "org", ResourceID: o.ID, Detail: map[string]any{"name": name, "token_id": t.ID, "ttl_seconds": int(ttl.Seconds())}})
	})
	return o.ID, token, err
}

func serve(ctx context.Context, log *slog.Logger, args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	insecure := fs.Bool("insecure-http", false, "allow plain HTTP on a non-loopback address (development only)")
	workers := fs.Int("concurrency", 16, "parallel probe jobs")
	_ = fs.Parse(args)

	db, err := openDB(ctx)
	if err != nil {
		return err
	}
	defer db.Close()

	var roots *x509.CertPool
	if f := os.Getenv("CERTLOOM_TRUST_BUNDLE"); f != "" {
		sys, err := x509.SystemCertPool()
		if err != nil || sys == nil {
			sys = x509.NewCertPool()
		}
		b, err := os.ReadFile(f)
		if err != nil {
			return fmt.Errorf("read CERTLOOM_TRUST_BUNDLE: %w", err)
		}
		if !sys.AppendCertsFromPEM(b) {
			return errors.New("CERTLOOM_TRUST_BUNDLE contains no certificates")
		}
		roots = sys
	}

	svc := &app.Service{DB: db, Prober: probe.New(), Roots: roots, Log: log}
	if iss := os.Getenv("CERTLOOM_OIDC_ISSUER"); iss != "" {
		var cs secret.Value
		if ref := os.Getenv("CERTLOOM_OIDC_CLIENT_SECRET_REF"); ref != "" {
			if cs, err = secret.Resolve(ref); err != nil {
				return fmt.Errorf("CERTLOOM_OIDC_CLIENT_SECRET_REF: %w", err)
			}
		}
		svc.OIDC, err = oidcauth.New(ctx, oidcauth.Config{Issuer: iss, ClientID: os.Getenv("CERTLOOM_OIDC_CLIENT_ID"), ClientSecret: cs,
			RedirectURL: os.Getenv("CERTLOOM_OIDC_REDIRECT_URL"), CLIClientID: os.Getenv("CERTLOOM_OIDC_CLI_CLIENT_ID")})
		if err != nil {
			return err
		}
		log.Info("oidc sign-in enabled", "issuer", iss, "cli_device_flow", os.Getenv("CERTLOOM_OIDC_CLI_CLIENT_ID") != "")
	}
	host, _ := os.Hostname()
	wid := fmt.Sprintf("%s-%d", host, os.Getpid())
	wcfg := worker.Config{WorkerID: wid, Concurrency: *workers}
	if spec := os.Getenv("CERTLOOM_AUDIT_EXPORT"); spec != "" {
		sink, err := auditexport.ParseSink(spec, os.Getenv("CERTLOOM_AUDIT_EXPORT_KEY_REF"))
		if err != nil {
			return fmt.Errorf("CERTLOOM_AUDIT_EXPORT: %w", err)
		}
		wcfg.AuditExporter = &auditexport.Exporter{DB: db, Sink: sink, Log: log}
		log.Info("audit export enabled", "sink", sink.ID())
	} else {
		log.Warn("audit export is not configured (CERTLOOM_AUDIT_EXPORT); the audit trail is only internally consistent and a database owner could rewrite it undetectably")
	}
	agentAddr := os.Getenv("CERTLOOM_AGENT_LISTEN")
	// A configured KEK is loaded even without the agent listener: webhooks,
	// EAB, DNS and CA credentials and the CSRF key depend on it too.
	switch k, err := kek.FromEnv(); {
	case err == nil:
		if svc.PKI, err = agentpki.LoadOrCreate(ctx, db.Pool, k); err != nil {
			return fmt.Errorf("agent PKI: %w", err)
		}
	case errors.Is(err, kek.ErrMissing) && agentAddr == "":
	case errors.Is(err, kek.ErrMissing):
		return fmt.Errorf("agent support needs a KEK: %w", err)
	default:
		return err
	}
	if agentAddr != "" {
		// Extra trust for private ACME directories (ARI polling), e.g. step-ca, Vault, Pebble.
		if f := os.Getenv("CERTLOOM_ACME_CA_FILE"); f != "" {
			pool, perr := x509.SystemCertPool()
			if perr != nil || pool == nil {
				pool = x509.NewCertPool()
			}
			b, rerr := os.ReadFile(f)
			if rerr != nil || !pool.AppendCertsFromPEM(b) {
				return fmt.Errorf("CERTLOOM_ACME_CA_FILE: cannot load certificates from %s", f)
			}
			svc.ARI = &ari.Client{HTTP: &http.Client{Timeout: 15 * time.Second,
				Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}}
		}
		svc.AgentServerURL = os.Getenv("CERTLOOM_AGENT_PUBLIC_URL")
		names := strings.Split(env("CERTLOOM_AGENT_SERVER_NAMES", host+",localhost,127.0.0.1"), ",")
		if svc.AgentServerURL == "" {
			_, port, _ := net.SplitHostPort(agentAddr)
			svc.AgentServerURL = "https://" + net.JoinHostPort(names[0], port)
		}
		as := &agentapi.Server{Svc: svc, Log: log}
		tcfg, err := as.TLSConfig(names)
		if err != nil {
			return err
		}
		asrv := &http.Server{Addr: agentAddr, Handler: as.Handler(), TLSConfig: tcfg, ReadHeaderTimeout: 10 * time.Second,
			WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second}
		go func() {
			log.Info("agent listener", "addr", agentAddr, "ca_hash", svc.PKI.CAFingerprint(), "server_names", names)
			if err := asrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("agent listener stopped", "error", err)
			}
		}()
		defer asrv.Close()
	}
	go worker.Run(ctx, svc, &notify.Deliverer{DB: db, Log: log}, wcfg, log)

	a := &api.Server{Svc: svc, Log: log}
	mux := http.NewServeMux()
	apiHandler := a.Handler()
	mux.Handle("/api/", apiHandler)
	mux.Handle("/healthz", apiHandler)
	mux.Handle("/readyz", apiHandler)
	addr := env("CERTLOOM_LISTEN", "127.0.0.1:8443")
	certFile, keyFile := os.Getenv("CERTLOOM_TLS_CERT"), os.Getenv("CERTLOOM_TLS_KEY")
	useTLS := certFile != "" && keyFile != ""
	ui := web.New(svc, log)
	// Behind a TLS-terminating proxy this process sees plain HTTP; set
	// CERTLOOM_SECURE_COOKIES=true there so session cookies stay Secure.
	ui.SecureCookies = useTLS || os.Getenv("CERTLOOM_SECURE_COOKIES") == "true"
	mux.Handle("/", api.RequestIDs(ui.Handler()))
	if !useTLS && !*insecure && !isLoopback(addr) {
		return fmt.Errorf("refusing plain HTTP on non-loopback address %s: set CERTLOOM_TLS_CERT/CERTLOOM_TLS_KEY or pass --insecure-http", addr)
	}
	srv := &http.Server{Addr: addr, Handler: securityHeaders(mux, useTLS), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 60 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 120 * time.Second,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	errc := make(chan error, 1)
	go func() {
		log.Info("listening", "addr", addr, "tls", useTLS, "version", version.Version, "worker_id", wid,
			"roles", authz.Roles())
		if useTLS {
			errc <- srv.ListenAndServeTLS(certFile, keyFile)
		} else {
			errc <- srv.ListenAndServe()
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(sctx)
}

func isLoopback(addr string) bool {
	h, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}

func securityHeaders(next http.Handler, hsts bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
		if hsts {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

// verifyExport checks an exported audit stream offline and, with --compare,
// against the database. Exit status is non-zero on any problem.
func verifyExport(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("audit-verify-export", flag.ExitOnError)
	compare := fs.Bool("compare", false, "also compare with the database (needs CERTLOOM_DATABASE_URL)")
	// Accept flags before or after FILE (Go's flag package stops at the first
	// positional argument, so parse the remainder again).
	_ = fs.Parse(args)
	var files []string
	for fs.NArg() > 0 {
		files = append(files, fs.Arg(0))
		_ = fs.Parse(fs.Args()[1:])
	}
	if len(files) != 1 {
		return errors.New("usage: certloomd audit-verify-export FILE [--compare]")
	}
	raw, err := os.ReadFile(files[0])
	if err != nil {
		return err
	}
	rep, err := auditexport.VerifyStream(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	for org, o := range rep.Orgs {
		fmt.Printf("org %s: %d events, last seq %d\n", org, o.Events, o.LastSeq)
	}
	if rep.Duplicates > 0 {
		fmt.Printf("%d duplicate deliveries (expected with at-least-once export)\n", rep.Duplicates)
	}
	for _, p := range rep.Problems {
		fmt.Println("PROBLEM:", p)
	}
	failed := !rep.OK
	if *compare {
		db, err := openDB(ctx)
		if err != nil {
			return err
		}
		defer db.Close()
		for org := range rep.Orgs {
			events, err := auditexport.ReadStream(bytes.NewReader(raw), org)
			if err != nil {
				return err
			}
			err = db.WithOrg(ctx, org, func(tx *store.Tx) error {
				mm, err := auditexport.CompareWithDB(ctx, tx, events)
				if err != nil {
					return err
				}
				for _, m := range mm {
					failed = true
					fmt.Printf("MISMATCH org %s seq %d: %s\n", org, m.Seq, m.Reason)
				}
				if len(mm) == 0 {
					fmt.Printf("org %s: database matches export (%d events)\n", org, len(events))
				}
				return nil
			})
			if err != nil {
				return err
			}
		}
	}
	if failed {
		return errors.New("audit export verification failed")
	}
	fmt.Println("OK")
	return nil
}
