package workflow

import (
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/oidcauth"
	"github.com/alexandrosnt/certloom/internal/oidcauth/oidctest"
	"github.com/alexandrosnt/certloom/internal/store"
)

// memberLogin signs in a member as if they came back from the IdP and
// returns a browser session for them.
func (e *env) memberLogin(base, email string) *uiClient {
	e.t.Helper()
	tok, _, err := e.svc.SignIn(ctx, &oidcauth.Identity{Issuer: e.svc.OIDC.Issuer(), Subject: email, Email: email}, "", "test")
	if err != nil {
		e.t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	u := &uiClient{t: e.t, base: base, c: &http.Client{Jar: jar}}
	if resp, _ := u.post("/login", url.Values{"token": {tok.RevealString()}}); resp.Request.URL.Path != "/" {
		e.t.Fatalf("member login ended at %s", resp.Request.URL)
	}
	return u
}

func TestWebSettingsPages(t *testing.T) {
	e := newEnv(t)
	idp := oidctest.New(t)
	p, err := oidcauth.New(ctx, oidcauth.Config{Issuer: idp.URL, ClientID: "certloom-web", RedirectURL: "https://ui.test/auth/oidc/callback"})
	if err != nil {
		t.Fatal(err)
	}
	e.svc.OIDC = p
	base := e.uiServer()
	owner := e.uiLogin(base, store.RoleOwner)
	viewer := e.uiLogin(base, store.RoleViewer)
	// Emails are unique per test run so sign-in finds exactly one membership.
	tag := strings.ToLower(strings.TrimPrefix(e.owner.OrgID, "org_"))
	alice, bob := "alice-"+tag+"@example.test", "bob-"+tag+"@example.test"

	t.Run("members page is for owners only", func(t *testing.T) {
		resp, body := owner.get("/members")
		wantPage(t, resp, body, 200, `aria-current="page">Members<`, "Add member", `<option value="owner">`)
		resp, body = viewer.get("/members")
		wantPage(t, resp, body, 403, "Your role does not allow this action.")
		if _, body = viewer.get("/runs"); strings.Contains(body, `href="/members"`) {
			t.Fatal("viewer sees the Members link")
		}
	})

	t.Run("add member", func(t *testing.T) {
		resp, body := owner.post("/members", url.Values{"csrf": {owner.csrf()}, "email": {alice}, "role": {"owner"}})
		wantPage(t, resp, body, 200, alice+" added as owner", alice)
		resp, body = owner.post("/members", url.Values{"csrf": {owner.csrf()}, "email": {bob}, "role": {"approver"}})
		wantPage(t, resp, body, 200, bob+" added as approver")
		resp, body = owner.post("/members", url.Values{"csrf": {owner.csrf()}, "email": {"not an email"}, "role": {"viewer"}})
		wantPage(t, resp, body, 400, "invalid email")
		resp, _ = owner.post("/members", url.Values{"email": {"eve@example.test"}, "role": {"owner"}})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("add without CSRF: %d", resp.StatusCode)
		}
	})

	t.Run("signed-in member cannot remove themselves from the page", func(t *testing.T) {
		a := e.memberLogin(base, alice)
		resp, body := a.get("/members")
		wantPage(t, resp, body, 200, alice+` <span class="muted">(you)</span>`)
		ms, err := e.svc.ListMembers(ctx, e.owner)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range ms {
			has := strings.Contains(body, `href="/members/`+m.ID+`/remove"`)
			if (m.Email == alice) == has {
				t.Fatalf("%s: remove link shown=%v", m.Email, has)
			}
		}
	})

	t.Run("remove member goes through a confirmation page", func(t *testing.T) {
		ms, _ := e.svc.ListMembers(ctx, e.owner)
		var id string
		for _, m := range ms {
			if m.Email == bob {
				id = m.ID
			}
		}
		resp, body := owner.get("/members/" + id + "/remove")
		wantPage(t, resp, body, 200, "Remove "+bob+" (approver)?", `action="/members/`+id+`/remove"`)
		if ms2, _ := e.svc.ListMembers(ctx, e.owner); len(ms2) != len(ms) {
			t.Fatal("GET removed the member")
		}
		resp, body = owner.post("/members/"+id+"/remove", url.Values{"csrf": {owner.csrf()}})
		wantPage(t, resp, body, 200, "Member removed")
		if strings.Contains(body, bob) {
			t.Fatal("removed member still listed")
		}
		resp, body = owner.get("/members/" + id + "/remove")
		wantPage(t, resp, body, 404, "Not found.")
	})

	t.Run("viewer reads the policy but gets no editor", func(t *testing.T) {
		resp, body := viewer.get("/policy")
		wantPage(t, resp, body, 200, "built-in defaults", `<pre class="source">`, "expiry")
		if strings.Contains(body, "<textarea") {
			t.Fatal("viewer is offered the editor")
		}
		resp, body = viewer.post("/policy/plan", url.Values{"csrf": {viewer.csrf()}, "base": {"0"}, "source": {"apiVersion: x"}})
		wantPage(t, resp, body, 403, "Your role does not allow this action.")
	})

	const pol = "apiVersion: certloom/v1\r\nkind: MonitoringPolicy\r\nspec:\r\n  expiry:\r\n    warning: 45d\r\n    critical: 10d\r\n"
	t.Run("invalid policy keeps the edits", func(t *testing.T) {
		resp, body := owner.post("/policy/plan", url.Values{"csrf": {owner.csrf()}, "base": {"0"}, "source": {"spec: [unclosed"}})
		wantPage(t, resp, body, 400, `class="error"`, "spec: [unclosed</textarea>")
	})

	t.Run("plan does not apply, apply creates a version", func(t *testing.T) {
		resp, body := owner.post("/policy/plan", url.Values{"csrf": {owner.csrf()}, "base": {"0"}, "source": {pol}})
		wantPage(t, resp, body, 200, "Review policy change", "Apply version 1", `name="base" value="0"`)
		if pv, _ := e.svc.GetPolicy(ctx, e.owner); pv.Version != 0 {
			t.Fatalf("plan applied version %d", pv.Version)
		}
		resp, body = owner.post("/policy/apply", url.Values{"csrf": {owner.csrf()}, "base": {"0"}, "source": {pol}})
		wantPage(t, resp, body, 200, "Policy version 1 applied", "warning: 45d")
		pv, err := e.svc.GetPolicy(ctx, e.owner)
		if err != nil {
			t.Fatal(err)
		}
		if pv.Version != 1 || strings.Contains(pv.Source, "\r") || !strings.HasPrefix(pv.CreatedBy, "token:") {
			t.Fatalf("stored policy: version %d by %s, CR in source: %v", pv.Version, pv.CreatedBy, strings.Contains(pv.Source, "\r"))
		}
	})

	t.Run("apply against an outdated version is refused", func(t *testing.T) {
		resp, body := owner.post("/policy/apply", url.Values{"csrf": {owner.csrf()}, "base": {"0"}, "source": {pol}})
		wantPage(t, resp, body, 400, "the active policy is now version 1, not 0")
		if pv, _ := e.svc.GetPolicy(ctx, e.owner); pv.Version != 1 {
			t.Fatalf("outdated apply created version %d", pv.Version)
		}
	})

	t.Run("channels: create, list, test", func(t *testing.T) {
		resp, body := viewer.get("/channels")
		wantPage(t, resp, body, 200, `aria-current="page">Channels<`, "No channels yet")
		if strings.Contains(body, "Add webhook channel") {
			t.Fatal("viewer is offered channel forms")
		}
		resp, body = owner.post("/channels", url.Values{"csrf": {owner.csrf()}, "kind": {"webhook"}, "name": {"oncall"},
			"url": {"https://hooks.example.test/x"}, "credential_ref": {"env:HOOK_SECRET"}, "min_severity": {"critical"}})
		wantPage(t, resp, body, 200, "Channel oncall created", "https://hooks.example.test/x", "env:HOOK_SECRET", `class="sev critical"`)
		resp, body = owner.post("/channels", url.Values{"csrf": {owner.csrf()}, "kind": {"email"}, "name": {"pki"},
			"host": {"smtp.example.test"}, "port": {"587"}, "tls": {"starttls"}, "from": {"certloom@example.test"},
			"to": {"a@example.test, b@example.test"}, "min_severity": {"warning"}})
		wantPage(t, resp, body, 200, "Channel pki created", "a@example.test, b@example.test via smtp.example.test")
		// A literal secret is not a reference and is refused.
		resp, body = owner.post("/channels", url.Values{"csrf": {owner.csrf()}, "kind": {"webhook"}, "name": {"bad"},
			"url": {"https://hooks.example.test/y"}, "credential_ref": {"hunter2"}})
		wantPage(t, resp, body, 400, "invalid credential reference")
		resp, body = owner.post("/channels", url.Values{"csrf": {owner.csrf()}, "kind": {"webhook"}, "name": {"plain"},
			"url": {"http://hooks.example.test/z"}})
		wantPage(t, resp, body, 400, "must be https")

		cs, err := e.svc.ListChannels(ctx, e.owner)
		if err != nil || len(cs) != 2 {
			t.Fatalf("channels: %v %d", err, len(cs))
		}
		resp, body = owner.post("/channels/"+cs[0].ID+"/test", url.Values{"csrf": {owner.csrf()}})
		wantPage(t, resp, body, 200, "Test notification queued")
		resp, body = viewer.post("/channels/"+cs[0].ID+"/test", url.Values{"csrf": {viewer.csrf()}})
		wantPage(t, resp, body, 403, "Your role does not allow this action.")
		ev, err := e.svc.AuditQuery(ctx, e.owner, 0, 500)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, a := range ev {
			seen[a.Action] = true
		}
		for _, a := range []string{"members.create", "members.delete", "policy.apply", "channels.create", "channels.test"} {
			if !seen[a] {
				t.Errorf("no %s audit event", a)
			}
		}
	})
}
