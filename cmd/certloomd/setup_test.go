package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDatabaseURL(t *testing.T) {
	for url, ok := range map[string]bool{
		"postgres://u:p@db.example.com/certloom?sslmode=verify-full":               true,
		"postgres://u:p@127.0.0.1/certloom?sslmode=verify-full&sslrootcert=/x.crt": true,
		"postgres://u:p@127.0.0.1/certloom?sslmode=disable":                        false,
		"postgres://u:p@localhost/certloom?sslmode=require":                        false,
		"postgres://u:p@db.example.com/certloom":                                   false,
		"postgres://u:p@/certloom?host=/var/run/postgresql":                        true,
	} {
		if err := checkDatabaseURL(url); (err == nil) != ok {
			t.Errorf("%s: err = %v, want ok = %v", url, err, ok)
		}
	}
}

func TestEnvFileKeepsCommentsAndOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "certloomd.env")
	in := "# settings\nCERTLOOM_DATABASE_URL=postgres://certloom_app:CHANGE-ME@127.0.0.1/certloom\n\nCERTLOOM_LISTEN=0.0.0.0:9443\n"
	if err := os.WriteFile(path, []byte(in), 0o600); err != nil {
		t.Fatal(err)
	}
	e, err := readEnvFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if configured(e.get("CERTLOOM_DATABASE_URL")) {
		t.Error("placeholder URL counted as configured")
	}
	e.set("CERTLOOM_DATABASE_URL", "postgres://x")
	e.setDefault("CERTLOOM_LISTEN", "0.0.0.0:8443") // kept: already set
	e.setDefault("CERTLOOM_KEK_FILE", "/etc/certloom/kek")
	want := "# settings\nCERTLOOM_DATABASE_URL=postgres://x\n\nCERTLOOM_LISTEN=0.0.0.0:9443\nCERTLOOM_KEK_FILE=/etc/certloom/kek\n"
	if got := string(e.bytes()); got != want {
		t.Errorf("got\n%s\nwant\n%s", got, want)
	}

	url := "postgres://u:p@127.0.0.1/certloom?sslmode=verify-full&sslrootcert=%2Fetc%2Fcertloom%2Fpostgres-ca.crt"
	e.set("CERTLOOM_DATABASE_URL", url)
	if l := e.lines[1]; l != `CERTLOOM_DATABASE_URL="`+url+`"` {
		t.Errorf("URL with & not quoted: %s", l)
	}
	if got := e.get("CERTLOOM_DATABASE_URL"); got != url {
		t.Errorf("get = %s, want the unquoted URL", got)
	}
}
