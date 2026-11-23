package agent

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/privateca"
	"github.com/go-acme/lego/v5/acme"
)

func TestIssueFailure(t *testing.T) {
	rl := &acme.RateLimitedError{ProblemDetails: &acme.ProblemDetails{Type: acme.RateLimitedErrorType, HTTPStatus: 429},
		RetryAfter: 90 * time.Minute}
	got := issueFailure(fmt.Errorf("obtain: %w", rl))
	if got.ProblemType != acme.RateLimitedErrorType || got.RetryAfterSeconds != 5400 {
		t.Fatalf("rate limited: %+v", got)
	}
	got = issueFailure(&acme.ProblemDetails{Type: acme.CaaErrorType})
	if got.ProblemType != acme.CaaErrorType || got.RetryAfterSeconds != 0 {
		t.Fatalf("caa: %+v", got)
	}
	if out := issueFailure(errors.New("dial tcp: timeout")); out != (agentproto.IssueOutput{}) {
		t.Fatalf("plain error should carry no problem, got %#v", out)
	}
}

func TestReplacesRejected(t *testing.T) {
	pd := func(typ string) *acme.ProblemDetails { return &acme.ProblemDetails{Type: typ} }
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"already replaced", fmt.Errorf("obtain: %w", &acme.AlreadyReplacedError{ProblemDetails: pd(acme.AlreadyReplacedErrorType)}), true},
		// Let's Encrypt production for a predecessor from staging or another CA.
		{"unknown issuer", fmt.Errorf("obtain: %w", pd(acme.MalformedErrorType)), true},
		{"other account", pd(acme.UnauthorizedErrorType), true},
		{"rate limited", &acme.RateLimitedError{ProblemDetails: pd(acme.RateLimitedErrorType)}, false},
		{"caa", pd(acme.CaaErrorType), false},
		{"network", errors.New("connection refused"), false},
	} {
		if got := replacesRejected(tc.err); got != tc.want {
			t.Errorf("%s: got %v, want %v", tc.name, got, tc.want)
		}
	}
}

// The agent generates only the key algorithm it knows; anything else in a
// task is refused before a key is created or the CA is contacted.
func TestIssueRefusesUnknownKeyAlgorithm(t *testing.T) {
	a, _, _ := testAgent(t)
	a.cfg.Targets[0].AllowedSANs = []string{"www.example.test"}
	tk := task("i1", agentproto.TaskIssue, 1)
	tk.Payload = json.RawMessage(`{"run_id":"run_1","directory_url":"https://acme.invalid/dir","sans":["www.example.test"],"key_algorithm":"rsa-1024"}`)
	_, err := a.handleIssue(context.Background(), &tk)
	if err == nil || !strings.Contains(err.Error(), "unsupported key algorithm") {
		t.Fatalf("want key algorithm refusal, got %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(a.cfg.StateDir, "certs")); len(entries) != 0 {
		t.Fatalf("a key was generated: %v", entries)
	}
}

// A CSR is made only for names the host's own allowlist covers, and the key
// it is made with stays in the run directory for the deploy step.
func TestCSRTask(t *testing.T) {
	a, _, _ := testAgent(t)
	a.cfg.Targets[0].AllowedSANs = []string{"www.example.test", "*.example.test"}
	tk := task("c1", agentproto.TaskCSR, 1)
	tk.Payload = json.RawMessage(`{"run_id":"run_1","sans":["www.example.test","bank.example"]}`)
	if _, err := a.handleCSR(context.Background(), &tk); err == nil || !strings.Contains(err.Error(), "allowed_sans") {
		t.Fatalf("want allowlist refusal, got %v", err)
	}
	if entries, _ := os.ReadDir(filepath.Join(a.cfg.StateDir, "certs")); len(entries) != 0 {
		t.Fatalf("a key was generated: %v", entries)
	}

	tk.Payload = json.RawMessage(`{"run_id":"run_1","sans":["www.example.test","*.example.test"]}`)
	out, err := a.handleCSR(context.Background(), &tk)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := privateca.CheckCSR(out.(agentproto.CSROutput).CSRPEM, []string{"www.example.test", "*.example.test"}, agentproto.KeyECDSAP256)
	if err != nil {
		t.Fatalf("agent CSR fails the control plane's check: %v", err)
	}
	key, err := loadOrCreateKey(filepath.Join(a.runDir(a.cfg.Targets[0].Name, "run_1"), "privkey.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !csr.PublicKey.(*ecdsa.PublicKey).Equal(key.Public()) {
		t.Fatal("CSR is not signed by the run key")
	}
}

func TestSaveIssuedCreatesRunDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs", "shop", "run_1")
	if err := saveIssued(dir, []byte("chain")); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "issued.pem")); err != nil || string(b) != "chain" {
		t.Fatalf("issued.pem: %q %v", b, err)
	}
}
