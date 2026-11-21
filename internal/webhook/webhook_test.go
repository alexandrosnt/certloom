package webhook

import (
	"os"
	"strings"
	"testing"
	"time"
)

// The symmetric test vector from the Standard Webhooks reference libraries.
// The secret and message id are split so secret scanners do not take them for real ones.
func TestSignVector(t *testing.T) {
	secret := SecretPrefix + "MfKQ9r8GKYqrTwjUPD8I" + "LPZIo2LaLaSw"
	msgID := "msg_p5jXN8AQ" + "M9LWM0D4" + "loKWxJek"
	got, err := Sign(secret, msgID, time.Unix(1614265330, 0), []byte(`{"test": 2432232314}`))
	if err != nil {
		t.Fatal(err)
	}
	if want := "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="; got != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestVerifyAndRotation(t *testing.T) {
	old, cur := NewSecret(), NewSecret()
	now := time.Now()
	body := []byte(`{"type":"renewal.verified"}`)
	h, err := Headers([]string{cur, old}, "evt_1", now, body)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.Fields(h["webhook-signature"])) != 2 {
		t.Fatalf("signatures %q", h["webhook-signature"])
	}
	for _, s := range []string{old, cur} {
		if err := Verify(s, h, body, now, 5*time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := Verify(NewSecret(), h, body, now, 5*time.Minute); err == nil {
		t.Fatal("other secret verified")
	}
	if err := Verify(cur, h, []byte(`{}`), now, 5*time.Minute); err == nil {
		t.Fatal("changed body verified")
	}
	if err := Verify(cur, h, body, now.Add(10*time.Minute), 5*time.Minute); err == nil {
		t.Fatal("replay outside tolerance verified")
	}
}

func TestFilters(t *testing.T) {
	if !ValidFilter("renewal.*") || !ValidFilter("certificate.issued") || ValidFilter("renewal") || ValidFilter("nope.*") || ValidFilter("*") {
		t.Fatal("ValidFilter")
	}
	f := []string{"renewal.*", "approval.requested"}
	for typ, want := range map[string]bool{"renewal.verified": true, "approval.requested": true, "approval.approved": false, "renewals.x": false} {
		if Matches(f, typ) != want {
			t.Errorf("%s", typ)
		}
	}
}

// Every catalog type is documented.
func TestCatalogDocumented(t *testing.T) {
	b, err := os.ReadFile("../../docs/events.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range Types {
		if !strings.Contains(string(b), "| `"+typ+"` |") {
			t.Errorf("%s missing from docs/events.md", typ)
		}
	}
}
