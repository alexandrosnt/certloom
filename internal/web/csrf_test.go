package web

import (
	"bytes"
	"io"
	"log/slog"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agentpki"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/kek"
)

// Two replicas with the same KEK must accept each other's CSRF tokens.
func TestCSRFKeySharedAcrossReplicas(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	replica := func() *UI {
		k, err := kek.New(bytes.Repeat([]byte{1}, 32))
		if err != nil {
			t.Fatal(err)
		}
		return &UI{csrfKey: csrfKey(&app.Service{PKI: &agentpki.PKI{KEK: k}}, log)}
	}
	a, b := replica(), replica()
	if a.csrf("session") != b.csrf("session") {
		t.Fatal("CSRF token from one replica does not verify on the other")
	}
	if a.csrf("session") == a.csrf("other") {
		t.Fatal("CSRF token must depend on the session")
	}
	lone := &UI{csrfKey: csrfKey(&app.Service{}, log)}
	if lone.csrf("session") == a.csrf("session") {
		t.Fatal("without a KEK the key must be random")
	}
}
