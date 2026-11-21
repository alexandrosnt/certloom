package acme

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/webhook"
)

// TestEventWebhookDelivery checks that certloomd's worker delivers signed
// events of a real renewal to a receiver.
func TestEventWebhookDelivery(t *testing.T) {
	hooks := t.TempDir()
	s := upWith(t, upOptions{before: func(run func(string, ...string) string, _ string) {
		run("hookrecv", "-v", mount(linuxBin, "/certloom"), "-v", hooks+":/hooks", "--user", "0", runImage,
			"/certloom/hookrecv", "/hooks/received.jsonl")
	}})
	s.enrollWeb()
	s.mustCLI("issuer", "create", "pebble", "--directory", "https://pebble:14000/dir", "--agree-tos")
	out := s.mustCLI("webhook", "create", "ops", "--url", "http://hookrecv:8080/", "--event", "renewal.*",
		"--event", "certificate.issued", "--allow-private")
	lines := strings.Fields(out) // the secret is the last thing printed
	secret := lines[len(lines)-1]
	if !strings.HasPrefix(secret, webhook.SecretPrefix) {
		t.Fatalf("webhook create printed %q", out)
	}
	renew := s.wwwDeployment()
	if state, msg := renew(); state != "verified" {
		t.Fatalf("renewal: %s %s", state, msg)
	}

	type line struct {
		Headers map[string]string
		Body    string
	}
	seen := map[string]bool{}
	waitFor(t, 60*time.Second, "renewal.verified and certificate.issued at the receiver", func() bool {
		f, err := os.Open(filepath.Join(hooks, "received.jsonl"))
		if err != nil {
			return false
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			var l line
			if json.Unmarshal(sc.Bytes(), &l) != nil {
				continue
			}
			if err := webhook.Verify(secret, l.Headers, []byte(l.Body), time.Now(), 5*time.Minute); err != nil {
				t.Fatalf("signature: %v\n%s", err, sc.Text())
			}
			var b struct{ Type string }
			_ = json.Unmarshal([]byte(l.Body), &b)
			seen[b.Type] = true
		}
		return seen["renewal.verified"] && seen["certificate.issued"]
	})
}
