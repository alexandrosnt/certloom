package e2e

import (
	"bytes"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

// pgClientImage provides pg_dump/pg_restore. A newer client can dump older servers.
const pgClientImage = "postgres:18-alpine"

// dockerPG runs a PostgreSQL client tool in a container against dbURL.
// Linux uses host networking; Docker Desktop (Windows/macOS) reaches the host
// via host.docker.internal.
func dockerPG(t *testing.T, stdin []byte, dbURL string, tool string, args ...string) []byte {
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
	dargs = append(dargs, pgClientImage, tool, "--dbname="+u.String())
	dargs = append(dargs, args...)
	cmd := exec.Command("docker", dargs...)
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
	if exec.Command("docker", "image", "inspect", image).Run() == nil {
		return
	}
	if out, err := exec.Command("docker", "pull", image).CombinedOutput(); err != nil {
		t.Skipf("cannot pull %s: %v\n%s", image, err, out)
	}
}
