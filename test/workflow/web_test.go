package workflow

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/web"
)

// uiClient is a signed-in browser session against the dashboard.
type uiClient struct {
	t    *testing.T
	base string
	c    *http.Client
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([0-9a-f]+)"`)

func (e *env) uiServer() string {
	ui := web.New(e.svc, slog.New(slog.NewTextHandler(io.Discard, nil)))
	s := httptest.NewServer(ui.Handler())
	e.t.Cleanup(s.Close)
	return s.URL
}

func (e *env) uiLogin(base, role string) *uiClient {
	e.t.Helper()
	_, tok, err := e.svc.CreateToken(ctx, e.owner, "ui-"+role, role, time.Hour)
	if err != nil {
		e.t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	u := &uiClient{t: e.t, base: base, c: &http.Client{Jar: jar}}
	resp, body := u.post("/login", url.Values{"token": {tok.RevealString()}})
	if resp.Request.URL.Path != "/" || !strings.Contains(body, ">"+role+"<") {
		e.t.Fatalf("login as %s: ended at %s (%d)", role, resp.Request.URL, resp.StatusCode)
	}
	return u
}

func (u *uiClient) get(path string) (*http.Response, string) {
	u.t.Helper()
	resp, err := u.c.Get(u.base + path)
	if err != nil {
		u.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func (u *uiClient) post(path string, form url.Values) (*http.Response, string) {
	u.t.Helper()
	resp, err := u.c.PostForm(u.base+path, form)
	if err != nil {
		u.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

// csrf reads the form token from any signed-in page.
func (u *uiClient) csrf() string {
	u.t.Helper()
	_, body := u.get("/runs")
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		u.t.Fatal("no csrf token on page")
	}
	return m[1]
}

func wantPage(t *testing.T, resp *http.Response, body string, status int, contains ...string) {
	t.Helper()
	if resp.StatusCode != status {
		t.Fatalf("%s: status %d, want %d\n%s", resp.Request.URL.Path, resp.StatusCode, status, body)
	}
	for _, s := range contains {
		if !strings.Contains(body, s) {
			t.Fatalf("%s: missing %q\n%s", resp.Request.URL.Path, s, body)
		}
	}
}

func (e *env) runCount() int {
	runs, err := e.svc.ListRuns(ctx, e.owner)
	if err != nil {
		e.t.Fatal(err)
	}
	return len(runs)
}

func TestWebAutomationPages(t *testing.T) {
	e := newEnv(t)
	base := e.uiServer()
	owner := e.uiLogin(base, store.RoleOwner)

	t.Run("pages require a session", func(t *testing.T) {
		anon := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		for _, p := range []string{"/agents", "/deployments", "/runs"} {
			resp, err := anon.Get(base + p)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusSeeOther || resp.Header.Get("Location") != "/login" {
				t.Fatalf("%s without session: %d %s", p, resp.StatusCode, resp.Header.Get("Location"))
			}
		}
	})

	t.Run("agents list and detail", func(t *testing.T) {
		resp, body := owner.get("/agents")
		wantPage(t, resp, body, 200, `href="/agents"`, `aria-current="page">Agents<`, "web-01", ">active<", ">www<")
		resp, body = owner.get("/agents/" + e.dep.AgentID)
		wantPage(t, resp, body, 200, "web-01", "www.wf.test, *.wf.test", "nginx", "fake")
		resp, body = owner.get("/agents/agt_does_not_exist")
		wantPage(t, resp, body, 404, "Not found.")
	})

	t.Run("deployments list shows names and renew action", func(t *testing.T) {
		resp, body := owner.get("/deployments")
		wantPage(t, resp, body, 200, ">www<", "web-01", "fake", "www.wf.test", "Renew now",
			`action="/deployments/`+e.dep.ID+`/renew"`)
	})

	var runID string
	t.Run("renew without CSRF token is refused", func(t *testing.T) {
		n := e.runCount()
		resp, _ := owner.post("/deployments/"+e.dep.ID+"/renew", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
		resp, _ = owner.post("/deployments/"+e.dep.ID+"/renew", url.Values{"csrf": {strings.Repeat("0", 64)}})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("forged token: status %d, want 403", resp.StatusCode)
		}
		if e.runCount() != n {
			t.Fatal("a run was started without a valid CSRF token")
		}
	})

	t.Run("renew now starts a run and shows it", func(t *testing.T) {
		resp, body := owner.post("/deployments/"+e.dep.ID+"/renew", url.Values{"csrf": {owner.csrf()}})
		wantPage(t, resp, body, 200, "Renewal started", ">planned<", "Cancel run", "manual")
		if !strings.HasPrefix(resp.Request.URL.Path, "/runs/run") {
			t.Fatalf("not redirected to the run page: %s", resp.Request.URL)
		}
		runID = strings.TrimPrefix(resp.Request.URL.Path, "/runs/")
		resp, body = owner.get("/runs")
		wantPage(t, resp, body, 200, `href="/runs/`+runID+`"`, ">planned<", "web-01")
		// A second request while the run is active is a conflict, shown as an error page.
		resp, body = owner.post("/deployments/"+e.dep.ID+"/renew", url.Values{"csrf": {owner.csrf()}})
		wantPage(t, resp, body, 400, "active renewal run")
	})

	viewer := e.uiLogin(base, store.RoleViewer)
	t.Run("viewer sees pages but cannot renew or cancel", func(t *testing.T) {
		resp, body := viewer.get("/deployments")
		wantPage(t, resp, body, 200, "web-01")
		if strings.Contains(body, "Renew now") {
			t.Fatal("viewer is offered Renew now")
		}
		resp, body = viewer.get("/runs/" + runID)
		wantPage(t, resp, body, 200, ">planned<")
		if strings.Contains(body, "Cancel run") {
			t.Fatal("viewer is offered Cancel")
		}
		tok := viewer.csrf()
		resp, body = viewer.post("/runs/"+runID+"/cancel", url.Values{"csrf": {tok}})
		wantPage(t, resp, body, 403, "Your role does not allow this action.")
		resp, body = viewer.post("/deployments/"+e.dep.ID+"/renew", url.Values{"csrf": {tok}})
		wantPage(t, resp, body, 403, "Your role does not allow this action.")
		// Another session's CSRF token is not accepted.
		resp, _ = viewer.post("/runs/"+runID+"/cancel", url.Values{"csrf": {owner.csrf()}})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("cross-session csrf: %d", resp.StatusCode)
		}
	})

	t.Run("cancel requires CSRF and then cancels", func(t *testing.T) {
		resp, _ := owner.post("/runs/"+runID+"/cancel", nil)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d, want 403", resp.StatusCode)
		}
		if r, _ := e.svc.GetRun(ctx, e.owner, runID); r.State != store.RunPlanned {
			t.Fatalf("run changed without CSRF: %s", r.State)
		}
		resp, body := owner.post("/runs/"+runID+"/cancel", url.Values{"csrf": {owner.csrf()}})
		wantPage(t, resp, body, 200, "Run cancelled", ">cancelled<", "cancelled by token:")
		if strings.Contains(body, "Cancel run") {
			t.Fatal("cancelled run still offers Cancel")
		}
		// Cancelling again is refused by the service.
		resp, body = owner.post("/runs/"+runID+"/cancel", url.Values{"csrf": {owner.csrf()}})
		wantPage(t, resp, body, 400, "cannot cancel")
	})

	t.Run("completed run shows timeline and issued certificate", func(t *testing.T) {
		run, err := e.svc.RequestRenewal(ctx, e.owner, e.dep.ID)
		if err != nil {
			t.Fatal(err)
		}
		r := e.pump(run.ID)
		if r.IssuedSHA256 == nil {
			t.Fatalf("no issued certificate: %s", r.State)
		}
		resp, body := owner.get("/runs/" + run.ID)
		wantPage(t, resp, body, 200, ">verified<", ">issuing<", ">deploying<", `href="/certificates/`+*r.IssuedSHA256+`"`)
		if strings.Contains(body, "Cancel run") {
			t.Fatal("verified run offers Cancel")
		}
		resp, body = owner.get("/runs/run_does_not_exist")
		wantPage(t, resp, body, 404, "Not found.")
	})
}
