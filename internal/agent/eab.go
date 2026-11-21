package agent

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/lego"
	"github.com/go-acme/lego/v5/registration"
)

// eabKey is an External Account Binding key ready for registration.
type eabKey struct {
	kid, hmac string
	source    string // "local" or "central", for logs and errors
}

// eabFor picks the EAB key for a registration (ADR-0019): the host's own key
// for the directory first, then one sealed to this agent for this task.
func (a *Agent) eabFor(t *agentproto.Task, p agentproto.IssuePayload) (*eabKey, error) {
	if l := a.cfg.localEAB(p.DirectoryURL); l != nil {
		b, err := os.ReadFile(l.HMACFile)
		if err != nil {
			return nil, fmt.Errorf("acme_eab hmac_file: %w", err)
		}
		return &eabKey{kid: l.KID, hmac: strings.TrimSpace(string(b)), source: "local"}, nil
	}
	if p.EAB == nil {
		return nil, nil
	}
	if !a.cfg.centralEABAllowed() {
		a.log.Warn("ignoring EAB key sent by the control plane (central_eab: false)", "directory", p.DirectoryURL)
		return nil, nil
	}
	issuer, ok := strings.CutPrefix(p.AccountSlot, "issuer:")
	if !ok {
		return nil, errors.New("EAB key sent without an issuer account slot")
	}
	b, err := a.openSecret(agentproto.SealEABInfo(a.id.AgentID, t.ID, issuer), p.EAB.Sealed)
	if err != nil {
		return nil, errors.New("cannot open the sealed EAB key (sealed for another agent, task or key)")
	}
	defer clear(b)
	return &eabKey{kid: p.EAB.KID, hmac: string(b), source: "central"}, nil
}

// register creates the ACME account, with EAB when a key is available.
func (a *Agent) register(ctx context.Context, client *lego.Client, t *agentproto.Task, p agentproto.IssuePayload) (*acme.ExtendedAccount, error) {
	eab, err := a.eabFor(t, p)
	if err != nil {
		return nil, err
	}
	var reg *acme.ExtendedAccount
	if eab == nil {
		reg, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: p.AgreeTOS})
	} else {
		if _, derr := base64.RawURLEncoding.DecodeString(strings.TrimRight(eab.hmac, "=")); derr != nil {
			return nil, &registrationError{err: fmt.Errorf("%s EAB HMAC key is not base64url", eab.source), eab: true, badKey: true}
		}
		reg, err = client.Registration.RegisterWithExternalAccountBinding(ctx, registration.RegisterEABOptions{
			TermsOfServiceAgreed: p.AgreeTOS, Kid: eab.kid, HmacEncoded: eab.hmac})
	}
	if err != nil {
		return nil, &registrationError{err: err, eab: eab != nil}
	}
	if reg == nil || reg.Location == "" {
		return nil, &registrationError{err: errors.New("the CA returned no account URL"), eab: eab != nil}
	}
	if eab != nil {
		a.log.Info("registered ACME account with EAB", "directory", p.DirectoryURL, "slot", p.AccountSlot, "kid", eab.kid, "source", eab.source)
	}
	return reg, nil
}

// registrationError is a failed account registration. Its output tells the
// control plane when an EAB key was refused, so it does not retry with it.
type registrationError struct {
	err    error
	eab    bool
	badKey bool
}

func (e *registrationError) Error() string { return "acme account registration: " + e.err.Error() }
func (e *registrationError) Unwrap() error { return e.err }

func (e *registrationError) output() agentproto.IssueOutput {
	out := issueFailure(e.err)
	if !e.eab {
		return out
	}
	var pd *acme.ProblemDetails
	if e.badKey {
		out.EABRejected = true
	} else if errors.As(e.err, &pd) {
		switch pd.Type {
		case acme.UnauthorizedErrorType, acme.MalformedErrorType, acme.ExternalAccountRequiredErrorType:
			out.EABRejected = true
		}
	}
	return out
}

// accountSlots lists the account slots registered on this host.
func (a *Agent) accountSlots() []string {
	dirs, _ := filepath.Glob(filepath.Join(a.cfg.StateDir, "acme", "*", "account.json"))
	var out []string
	for _, f := range dirs {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var acct acmeAccount
		if json.Unmarshal(b, &acct) != nil || acct.Slot == "" || acct.Registration == nil {
			continue
		}
		out = append(out, acct.Slot)
	}
	slices.Sort(out)
	return slices.Compact(out)
}
