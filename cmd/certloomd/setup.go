package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/kek"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Paths of a package install (deploy/packaging).
type setupPaths struct {
	dir     string // /etc/certloom
	env     string // settings read by certloomd.service
	migrate string // owner-role URL, root only; used by setup and package upgrades
	kek     string
	cert    string
	key     string
	pgCA    string // CA that signed the local PostgreSQL certificate; its key is discarded
	pgCert  string
	pgKey   string
}

func defaultSetupPaths(dir string) setupPaths {
	return setupPaths{
		dir:     dir,
		env:     filepath.Join(dir, "certloomd.env"),
		migrate: filepath.Join(dir, "migrate.env"),
		kek:     filepath.Join(dir, "kek"),
		cert:    filepath.Join(dir, "tls", "server.crt"),
		key:     filepath.Join(dir, "tls", "server.key"),
		pgCA:    filepath.Join(dir, "postgres-ca.crt"),
		pgCert:  filepath.Join(dir, "postgres-tls", "server.crt"),
		pgKey:   filepath.Join(dir, "postgres-tls", "server.key"),
	}
}

const minPostgres = 160000

// setup turns a fresh package install into a running control plane. Every
// step checks what is already there, so running it again only migrates the
// database and restarts the service.
func setup(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	org := fs.String("org", "default", "name of the first organization")
	host := fs.String("hostname", "", "name agents and browsers use to reach this host (default: the host name)")
	ownerURL := fs.String("owner-database-url", "", "use an existing PostgreSQL: URL of a role with CREATEROLE that owns the database (default: create one in the local PostgreSQL)")
	_ = fs.Parse(args)
	if os.Geteuid() != 0 {
		return errors.New("setup must run as root (sudo certloomd setup)")
	}
	if *host == "" {
		h, err := os.Hostname()
		if err != nil {
			return err
		}
		*host = h
	}
	gid, err := certloomGroup()
	if err != nil {
		return err
	}
	p := defaultSetupPaths("/etc/certloom")
	env, err := readEnvFile(p.env)
	if err != nil {
		return err
	}

	fresh := !configured(env.get("CERTLOOM_DATABASE_URL"))
	owner := *ownerURL
	if owner == "" {
		if m, err := readEnvFile(p.migrate); err == nil {
			owner = m.get("CERTLOOM_MIGRATE_DATABASE_URL")
		}
	}
	switch {
	case owner == "" && fresh:
		step("Creating the database in the local PostgreSQL")
		if owner, err = createLocalDatabase(ctx, p); err != nil {
			return err
		}
	case owner == "":
		return fmt.Errorf("the database is configured but %s is missing; pass --owner-database-url to migrate", p.migrate)
	}
	if err := checkDatabaseURL(owner); err != nil {
		return err
	}
	step("Applying database migrations")
	if err := store.Migrate(ctx, owner); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	m := &envFile{}
	m.set("CERTLOOM_MIGRATE_DATABASE_URL", owner)
	if err := writeFile(p.migrate, m.bytes(), 0o600, 0); err != nil {
		return err
	}
	if fresh {
		step("Setting the password of the runtime role certloom_app")
		appURL, err := setAppPassword(ctx, owner)
		if err != nil {
			return err
		}
		env.set("CERTLOOM_DATABASE_URL", appURL)
	}

	if _, err := os.Stat(p.kek); errors.Is(err, os.ErrNotExist) {
		step("Creating the key-encryption key " + p.kek)
		if err := writeFile(p.kek, []byte(kek.Generate()+"\n"), 0o640, gid); err != nil {
			return err
		}
	}
	env.setDefault("CERTLOOM_KEK_FILE", p.kek)

	if _, err := os.Stat(p.cert); errors.Is(err, os.ErrNotExist) {
		step("Creating a self-signed TLS certificate for " + *host)
		if err := selfSigned(p.cert, p.key, *host, gid); err != nil {
			return err
		}
	}
	env.setDefault("CERTLOOM_TLS_CERT", p.cert)
	env.setDefault("CERTLOOM_TLS_KEY", p.key)
	env.setDefault("CERTLOOM_LISTEN", "0.0.0.0:8443")
	env.setDefault("CERTLOOM_AGENT_LISTEN", "0.0.0.0:8444")
	if v := env.get("CERTLOOM_AGENT_SERVER_NAMES"); v == "" || strings.Contains(v, "example.internal") {
		env.set("CERTLOOM_AGENT_SERVER_NAMES", *host+",localhost")
	}
	if v := env.get("CERTLOOM_AGENT_PUBLIC_URL"); v == "" || strings.Contains(v, "example.internal") {
		env.set("CERTLOOM_AGENT_PUBLIC_URL", "https://"+net.JoinHostPort(*host, "8444"))
	}
	if err := writeFile(p.env, env.bytes(), 0o640, gid); err != nil {
		return err
	}

	step("Starting certloomd.service")
	for _, a := range [][]string{{"enable", "certloomd.service"}, {"restart", "certloomd.service"}} {
		if out, err := exec.CommandContext(ctx, "systemctl", a...).CombinedOutput(); err != nil {
			return fmt.Errorf("systemctl %s: %v: %s", a[0], err, out)
		}
	}

	ui := "https://" + net.JoinHostPort(*host, "8443") + "/"
	fmt.Printf("\ncertloom is running.\n  Web UI and API: %s\n", ui)
	if fp, err := certFingerprint(p.cert); err == nil {
		fmt.Printf("  TLS certificate SHA-256: %s\n", fp)
	}
	if fresh {
		db, err := store.Open(ctx, env.get("CERTLOOM_DATABASE_URL"))
		if err != nil {
			return err
		}
		defer db.Close()
		_, token, err := createOrg(ctx, db, *org, 24*time.Hour)
		if err != nil {
			return err
		}
		fmt.Printf("\nSign in with this owner token (shown once, valid 24 hours):\n\n  %s\n\n", token)
		fmt.Println("Then create a lasting token: certloom token create admin --role owner --ttl 2160h")
	}
	fmt.Printf("\nBack up %s apart from the database: a restore needs it.\n", p.kek)
	return nil
}

func step(s string) { fmt.Println("- " + s) }

// configured reports whether a database URL has been filled in.
func configured(dbURL string) bool {
	return dbURL != "" && !strings.Contains(dbURL, "CHANGE-ME")
}

// checkDatabaseURL refuses any TCP connection that is not verified TLS, also
// on loopback: another local user or process must not be able to read or
// redirect the database traffic. Unix sockets are exempt (file permissions).
func checkDatabaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("database url: %w", err)
	}
	q := u.Query()
	if strings.HasPrefix(q.Get("host"), "/") || strings.HasPrefix(u.Hostname(), "/") {
		return nil
	}
	if m := q.Get("sslmode"); m != "verify-full" {
		return fmt.Errorf("database url must use sslmode=verify-full (not %q)", m)
	}
	return nil
}

// createLocalDatabase creates certloom_owner and the certloom database in the
// local PostgreSQL through the postgres superuser's socket, and makes the
// certloom roles reachable over verified TLS only. It returns the owner URL.
func createLocalDatabase(ctx context.Context, p setupPaths) (string, error) {
	out, err := psql(ctx, "SHOW server_version_num")
	if err != nil {
		return "", fmt.Errorf("no local PostgreSQL found (%v). Install PostgreSQL 16 or later and start it "+
			"(Debian/Ubuntu: apt install postgresql), or pass --owner-database-url", err)
	}
	v, _ := strconv.Atoi(strings.TrimSpace(out))
	if v < minPostgres {
		return "", fmt.Errorf("local PostgreSQL is version %d; certloom needs 16 or later", v/10000)
	}
	pw := randomPassword()
	sql := fmt.Sprintf(`DO $$ BEGIN
  IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'certloom_owner') THEN
    ALTER ROLE certloom_owner LOGIN CREATEROLE PASSWORD '%[1]s';
  ELSE
    CREATE ROLE certloom_owner LOGIN CREATEROLE PASSWORD '%[1]s';
  END IF;
END $$;
SELECT 'CREATE DATABASE certloom OWNER certloom_owner'
  WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'certloom')\gexec
`, pw)
	if _, err := psql(ctx, sql); err != nil {
		return "", err
	}
	if err := postgresTLS(ctx, p); err != nil {
		return "", err
	}
	port := "5432"
	if out, err := psql(ctx, "SHOW port"); err == nil {
		port = strings.TrimSpace(out)
	}
	q := url.Values{"sslmode": {"verify-full"}, "sslrootcert": {p.pgCA}}
	return "postgres://certloom_owner:" + pw + "@" + net.JoinHostPort("127.0.0.1", port) + "/certloom?" + q.Encode(), nil
}

// hbaRules come first in pg_hba.conf (first match wins): the certloom roles
// get in over TLS with a SCRAM password, and are refused without TLS.
const hbaMarker = "# certloom: TLS only (added by certloomd setup)"

const hbaRules = hbaMarker + `
hostssl   certloom  certloom_owner,certloom_app  127.0.0.1/32  scram-sha-256
hostssl   certloom  certloom_owner,certloom_app  ::1/128       scram-sha-256
hostnossl all       certloom_owner,certloom_app  all           reject
`

// postgresTLS gives the local PostgreSQL a server certificate from a CA whose
// private key is thrown away right after signing, so no other certificate
// can ever pass certloomd's verification, then requires TLS for the certloom
// roles. The certificate replaces the server's default (e.g. Debian's
// snakeoil) for every client of this PostgreSQL.
func postgresTLS(ctx context.Context, p setupPaths) error {
	if _, err := os.Stat(p.pgCA); err == nil {
		return nil
	}
	step("Requiring verified TLS for the certloom roles in PostgreSQL")
	pg, err := user.Lookup("postgres")
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(pg.Uid)
	gid, _ := strconv.Atoi(pg.Gid)

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	ca := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "certloom local PostgreSQL CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, _ = x509.ParseCertificate(caDER)
	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	srv := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	// caKey is never written anywhere and goes out of scope with this function.
	srvDER, err := x509.CreateCertificate(rand.Reader, srv, ca, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(srvKey)
	if err != nil {
		return err
	}
	pemOf := func(typ string, b []byte) []byte { return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: b}) }
	dir := filepath.Dir(p.pgCert)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeFileOwned(p.pgKey, pemOf("PRIVATE KEY", kb), 0o600, uid, gid); err != nil {
		return err
	}
	if err := writeFileOwned(p.pgCert, pemOf("CERTIFICATE", srvDER), 0o644, uid, gid); err != nil {
		return err
	}

	hba, err := psql(ctx, "SHOW hba_file")
	if err != nil {
		return err
	}
	hbaPath := strings.TrimSpace(hba)
	cur, err := os.ReadFile(hbaPath)
	if err != nil {
		return err
	}
	if !strings.Contains(string(cur), hbaMarker) {
		fi, err := os.Stat(hbaPath)
		if err != nil {
			return err
		}
		if err := os.WriteFile(hbaPath, append([]byte(hbaRules+"\n"), cur...), fi.Mode().Perm()); err != nil {
			return err
		}
	}
	if _, err := psql(ctx, fmt.Sprintf("ALTER SYSTEM SET ssl = on;\nALTER SYSTEM SET ssl_cert_file = '%s';\n"+
		"ALTER SYSTEM SET ssl_key_file = '%s';\nALTER SYSTEM SET ssl_min_protocol_version = 'TLSv1.3';\nSELECT pg_reload_conf();\n",
		p.pgCert, p.pgKey)); err != nil {
		return err
	}
	// Written last: its presence means the steps above are done.
	return writeFile(p.pgCA, pemOf("CERTIFICATE", caDER), 0o644, 0)
}

func randomSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// psql runs SQL as the postgres OS user. The SQL goes in on stdin so that
// passwords never appear in a process list.
func psql(ctx context.Context, sql string) (string, error) {
	cmd := exec.CommandContext(ctx, "runuser", "-u", "postgres", "--", "psql", "-X", "-q", "-A", "-t", "-v", "ON_ERROR_STOP=1")
	cmd.Stdin = strings.NewReader(sql)
	cmd.Dir = "/"
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("psql: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

// setAppPassword gives the runtime role a new password and returns its URL:
// the owner URL with the user and password replaced.
func setAppPassword(ctx context.Context, ownerURL string) (string, error) {
	db, err := store.Open(ctx, ownerURL)
	if err != nil {
		return "", err
	}
	defer db.Close()
	pw := randomPassword()
	// Passwords cannot be bound as parameters; randomPassword uses only URL-safe base64.
	if _, err := db.Pool.Exec(ctx, "ALTER ROLE certloom_app LOGIN PASSWORD '"+pw+"'"); err != nil {
		return "", fmt.Errorf("set certloom_app password: %w", err)
	}
	u, err := url.Parse(ownerURL)
	if err != nil {
		return "", err
	}
	u.User = url.UserPassword("certloom_app", pw)
	return u.String(), nil
}

func randomPassword() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func certloomGroup() (int, error) {
	g, err := user.LookupGroup("certloom")
	if err != nil {
		return 0, fmt.Errorf("group certloom not found; is the certloomd package installed? %w", err)
	}
	return strconv.Atoi(g.Gid)
}

// writeFile writes atomically, owned by root and the given group.
func writeFile(path string, data []byte, mode os.FileMode, gid int) error {
	return writeFileOwned(path, data, mode, 0, gid)
}

func writeFileOwned(path string, data []byte, mode os.FileMode, uid, gid int) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".setup-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}
	if err := os.Chown(tmp.Name(), uid, gid); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// selfSigned writes a P-256 certificate for host, localhost and the loopback
// addresses. Replace it with one from a trusted CA for production.
func selfSigned(certPath, keyPath, host string, gid int) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     uniq([]string{host, "localhost"}),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if ip := net.ParseIP(host); ip != nil {
		tmpl.DNSNames = []string{"localhost"}
		tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	kb, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := writeFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kb}), 0o640, gid); err != nil {
		return err
	}
	return writeFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644, gid)
}

func uniq(s []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range s {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func certFingerprint(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "", errors.New("no PEM block")
	}
	sum := sha256.Sum256(blk.Bytes)
	return fmt.Sprintf("%X", sum), nil
}

// envFile edits a systemd EnvironmentFile and keeps comments and order.
type envFile struct{ lines []string }

func readEnvFile(path string) (*envFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	e := &envFile{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		e.lines = append(e.lines, sc.Text())
	}
	return e, sc.Err()
}

func (e *envFile) index(k string) int {
	for i, l := range e.lines {
		if strings.HasPrefix(l, k+"=") {
			return i
		}
	}
	return -1
}

func (e *envFile) get(k string) string {
	if i := e.index(k); i >= 0 {
		v := strings.TrimPrefix(e.lines[i], k+"=")
		if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
			v = v[1 : len(v)-1]
		}
		return v
	}
	return ""
}

func (e *envFile) set(k, v string) {
	// Quoted when needed: systemd and sh both strip the quotes, and sh would
	// otherwise treat the & in a database URL as a command separator.
	if strings.ContainsAny(v, "&;|<>() \t") {
		v = `"` + v + `"`
	}
	if i := e.index(k); i >= 0 {
		e.lines[i] = k + "=" + v
		return
	}
	e.lines = append(e.lines, k+"="+v)
}

// setDefault sets k only when the file has no value for it.
func (e *envFile) setDefault(k, v string) {
	if e.get(k) == "" {
		e.set(k, v)
	}
}

func (e *envFile) bytes() []byte {
	return []byte(strings.Join(e.lines, "\n") + "\n")
}
