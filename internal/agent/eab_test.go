package agent

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/go-acme/lego/v5/acme"
)

func sealEAB(t *testing.T, a *Agent, info []byte, hmac string) *agentproto.SealedEAB {
	t.Helper()
	b, err := agentproto.SealSecret(a.sealPub, info, []byte(hmac))
	if err != nil {
		t.Fatal(err)
	}
	return &agentproto.SealedEAB{KID: "kid-c", Sealed: b}
}

func TestEABKeySelection(t *testing.T) {
	a, _, _ := testAgent(t)
	if err := a.loadSealKey(); err != nil {
		t.Fatal(err)
	}
	const dir = "https://ca.test/directory"
	hmac := base64.RawURLEncoding.EncodeToString([]byte("central eab hmac for the agent test"))
	tk := &agentproto.Task{ID: "tsk_1"}
	p := agentproto.IssuePayload{DirectoryURL: dir, AccountSlot: agentproto.AccountSlot("iss_1"),
		EAB: sealEAB(t, a, agentproto.SealEABInfo(a.id.AgentID, "tsk_1", "iss_1"), hmac)}

	k, err := a.eabFor(tk, p)
	if err != nil || k == nil || k.kid != "kid-c" || k.hmac != hmac || k.source != "central" {
		t.Fatalf("central: %+v %v", k, err)
	}
	// Bound to task and issuer, and a DNS secret never opens as an EAB key.
	for name, bad := range map[string]agentproto.IssuePayload{
		"other issuer": {DirectoryURL: dir, AccountSlot: agentproto.AccountSlot("iss_2"), EAB: p.EAB},
		"dns label": {DirectoryURL: dir, AccountSlot: p.AccountSlot,
			EAB: sealEAB(t, a, agentproto.SealInfo(a.id.AgentID, "tsk_1", "iss_1"), hmac)},
		"no slot": {DirectoryURL: dir, EAB: p.EAB},
	} {
		if _, err := a.eabFor(tk, bad); err == nil {
			t.Errorf("%s: opened", name)
		}
	}
	if _, err := a.eabFor(&agentproto.Task{ID: "tsk_2"}, p); err == nil {
		t.Error("opened for another task")
	}

	// A host-local key for the directory wins over the central one.
	f := filepath.Join(t.TempDir(), "hmac")
	if err := os.WriteFile(f, []byte(base64.RawURLEncoding.EncodeToString([]byte("local key for the test"))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a.cfg.ACMEEAB = []EABConfig{{DirectoryURL: dir, KID: "kid-l", HMACFile: f}}
	if k, err := a.eabFor(tk, p); err != nil || k.kid != "kid-l" || k.source != "local" || strings.ContainsAny(k.hmac, "\n ") {
		t.Fatalf("local: %+v %v", k, err)
	}

	// The host can refuse central keys.
	a.cfg.ACMEEAB = nil
	off := false
	a.cfg.CentralEAB = &off
	if k, err := a.eabFor(tk, p); err != nil || k != nil {
		t.Fatalf("opt-out: %+v %v", k, err)
	}
}

func TestEABConfigValidation(t *testing.T) {
	abs := filepath.Join(t.TempDir(), "eab")
	for _, c := range []struct {
		e    []EABConfig
		want string
	}{
		{[]EABConfig{{DirectoryURL: "https://ca.test/d", KID: "k", HMACFile: abs}}, ""},
		{[]EABConfig{{DirectoryURL: "http://ca.test/d", KID: "k", HMACFile: abs}}, "https"},
		{[]EABConfig{{DirectoryURL: "https://ca.test/d", HMACFile: abs}}, "kid"},
		{[]EABConfig{{DirectoryURL: "https://ca.test/d", KID: "k", HMACFile: "rel"}}, "absolute"},
		{[]EABConfig{{DirectoryURL: "https://ca.test/d", KID: "k", HMACFile: abs}, {DirectoryURL: "https://ca.test/d", KID: "j", HMACFile: abs}}, "duplicate"},
	} {
		got := strings.Join((&Config{ACMEEAB: c.e}).validateEAB(), "; ")
		if (c.want == "") != (got == "") || !strings.Contains(got, c.want) {
			t.Errorf("%+v: %q", c.e, got)
		}
	}
}

func TestRegistrationErrorOutput(t *testing.T) {
	pd := func(typ string) error { return &acme.ProblemDetails{Type: typ} }
	for _, c := range []struct {
		err    error
		eab    bool
		badKey bool
		want   bool
	}{
		{pd(acme.UnauthorizedErrorType), true, false, true},
		{pd(acme.MalformedErrorType), true, false, true},
		{pd(acme.ExternalAccountRequiredErrorType), true, false, true},
		{pd(acme.ServerInternalErrorType), true, false, false},
		{errors.New("dial tcp: i/o timeout"), true, false, false},
		{errors.New("not base64url"), true, true, true},
		{pd(acme.UnauthorizedErrorType), false, false, false},
	} {
		out := (&registrationError{err: c.err, eab: c.eab, badKey: c.badKey}).output()
		if out.EABRejected != c.want {
			t.Errorf("%v eab=%v: rejected=%v", c.err, c.eab, out.EABRejected)
		}
	}
	// Without EAB, the problem type still reaches the control plane.
	if out := (&registrationError{err: pd(acme.ExternalAccountRequiredErrorType)}).output(); out.ProblemType != acme.ExternalAccountRequiredErrorType {
		t.Fatalf("%+v", out)
	}
}

func TestAccountSlots(t *testing.T) {
	a, _, _ := testAgent(t)
	const dir = "https://ca.test/directory"
	// Accounts without a slot keep the path they had before slots existed.
	h := sha256.Sum256([]byte(dir))
	if got := a.accountDir(dir, ""); got != filepath.Join(a.cfg.StateDir, "acme", hex.EncodeToString(h[:8])) {
		t.Fatalf("legacy path moved: %s", got)
	}
	if a.accountDir(dir, "issuer:iss_1") == a.accountDir(dir, "") || a.accountDir(dir, "issuer:iss_1") == a.accountDir(dir, "issuer:iss_2") {
		t.Fatal("slots share an account")
	}
	write := func(slot string, registered bool) {
		t.Helper()
		acct := acmeAccount{Slot: slot}
		if registered {
			acct.Registration = &acme.ExtendedAccount{Location: "https://ca.test/acct/1"}
		}
		b, _ := json.Marshal(acct)
		d := a.accountDir(dir, slot)
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "account.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("", true)
	write("issuer:iss_1", true)
	write("issuer:iss_2", false)
	if got := a.accountSlots(); !slices.Equal(got, []string{"issuer:iss_1"}) {
		t.Fatalf("slots %v", got)
	}
}
