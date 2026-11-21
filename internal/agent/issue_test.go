package agent

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/go-acme/lego/v5/acme"
)

func TestIssueFailure(t *testing.T) {
	rl := &acme.RateLimitedError{ProblemDetails: &acme.ProblemDetails{Type: acme.RateLimitedErrorType, HTTPStatus: 429},
		RetryAfter: 90 * time.Minute}
	got, ok := issueFailure(fmt.Errorf("obtain: %w", rl)).(agentproto.IssueOutput)
	if !ok || got.ProblemType != acme.RateLimitedErrorType || got.RetryAfterSeconds != 5400 {
		t.Fatalf("rate limited: %+v", got)
	}
	got, ok = issueFailure(&acme.ProblemDetails{Type: acme.CaaErrorType}).(agentproto.IssueOutput)
	if !ok || got.ProblemType != acme.CaaErrorType || got.RetryAfterSeconds != 0 {
		t.Fatalf("caa: %+v", got)
	}
	if out := issueFailure(errors.New("dial tcp: timeout")); out != nil {
		t.Fatalf("plain error should carry no output, got %#v", out)
	}
}
