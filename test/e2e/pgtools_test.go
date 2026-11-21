package e2e

import (
	"bytes"
	"context"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/store/storetest"
	"github.com/jackc/pgx/v5"
)

// pgClientImage returns a postgres image whose pg_dump/pg_restore match the
// test server's major version. A newer pg_dump writes settings an older
// server rejects on restore (e.g. transaction_timeout, added in 17), so
// backups must always be taken and restored with the server's own version.
func pgClientImage(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	c, err := pgx.Connect(ctx, os.Getenv(storetest.EnvURL))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close(ctx) }()
	var num int
	if err := c.QueryRow(ctx, "SELECT current_setting('server_version_num')::int").Scan(&num); err != nil {
		t.Fatal(err)
	}
	image := fmt.Sprintf("postgres:%d-alpine", num/10000)
	ensureImage(t, image)
	return image
}

// dockerPG runs a PostgreSQL client tool from image in a container against
// dbURL. Linux uses host networking; Docker Desktop (Windows/macOS) reaches
// the host via host.docker.internal.
func dockerPG(t *testing.T, image string, stdin []byte, dbURL string, tool string, args ...string) []byte {
	t.Helper()
	u, err := url.Parse(dbURL)
	if err != nil {
		t.Fatal(err)
	}
	dargs := []string{"run", "--rm", "-i"}
	if runtime.GOOS == "linux" {
		dargs = append(dargs, "--network", "host")
	} else if h := u.Hostname(); h == "127.0.0.1" || h == "localhost" {
		u.Host = strings.Replace(u.Host, h, "host.docker.internal", 1)
	}
	dargs = append(dargs, image, tool, "--dbname="+u.String())
	dargs = append(dargs, args...)
	cmd := exec.CommandContext(t.Context(), "docker", dargs...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("%s failed: %v\n%s", tool, err, errb.String())
	}
	return out.Bytes()
}

func ensureImage(t *testing.T, image string) {
	t.Helper()
	if exec.CommandContext(t.Context(), "docker", "image", "inspect", image).Run() == nil {
		return
	}
	if out, err := exec.CommandContext(t.Context(), "docker", "pull", image).CombinedOutput(); err != nil {
		t.Skipf("cannot pull %s: %v\n%s", image, err, out)
	}
}
