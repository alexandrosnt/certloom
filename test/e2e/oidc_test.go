package e2e

import (
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexandrosnt/certloom/internal/oidcauth/oidctest"
)

// browser follows the full redirect chain like a user agent would.
func browser(t *testing.T) *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar}
}

func get(t *testing.T, c *http.Client, url string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

func TestOIDCSignIn(t *testing.T) {
	idp := oidctest.New(t)
	e := startServerFn(t, func(server string) []string {
		return []string{"CERTLOOM_OIDC_ISSUER=" + idp.URL, "CERTLOOM_OIDC_CLIENT_ID=certloom-web",
			"CERTLOOM_OIDC_CLIENT_SECRET_REF=env:E2E_OIDC_SECRET", "E2E_OIDC_SECRET=web-secret",
			"CERTLOOM_OIDC_REDIRECT_URL=" + server + "/auth/oidc/callback", "CERTLOOM_OIDC_CLI_CLIENT_ID=certloom-cli"}
	})

	t.Run("non-member is refused", func(t *testing.T) {
		b := browser(t)
		resp, _ := get(t, b, e.server+"/auth/oidc/login")
		if !strings.Contains(resp.Request.URL.String(), "/login?error=") || !strings.Contains(resp.Request.URL.RawQuery, "member") {
			t.Fatalf("want error redirect about membership, ended at %s", resp.Request.URL)
		}
	})

	var memberID struct{ ID string }
	e.jsonCLI(&memberID, "member", "add", "alice@example.test", "--role", "operator")

	t.Run("browser sign-in creates a session with the member's role", func(t *testing.T) {
		b := browser(t)
		resp, body := get(t, b, e.server+"/auth/oidc/login")
		if resp.StatusCode != 200 || !strings.Contains(body, `url=/`) {
			t.Fatalf("callback: %d %s\n%s", resp.StatusCode, resp.Request.URL, body)
		}
		resp, body = get(t, b, e.server+"/")
		if resp.Request.URL.Path != "/" || !strings.Contains(body, ">operator<") {
			t.Fatalf("expected overview as operator, got %s", resp.Request.URL)
		}
		// Logout revokes the session server-side: replaying the cookie fails.
		var sess *http.Cookie
		for _, c := range b.Jar.Cookies(resp.Request.URL) {
			if c.Name == "certloom_session" {
				sess = c
			}
		}
		req, _ := http.NewRequest("GET", e.server+"/api/v1/whoami", nil)
		req.Header.Set("Authorization", "Bearer "+sess.Value)
		if r, _ := http.DefaultClient.Do(req); r.StatusCode != 200 {
			t.Fatalf("session token should work as bearer: %d", r.StatusCode)
		}
		lr, _ := b.PostForm(e.server+"/logout", nil)
		lr.Body.Close()
		if r, _ := http.DefaultClient.Do(req); r.StatusCode != 401 {
			t.Fatalf("revoked session still accepted: %d", r.StatusCode)
		}
	})

	t.Run("tampered state is rejected", func(t *testing.T) {
		b := browser(t)
		// Start a real login (gets the state cookie) but stop before the IdP.
		b.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		resp, _ := get(t, b, e.server+"/auth/oidc/login")
		if resp.StatusCode != http.StatusFound {
			t.Fatalf("login should redirect to the IdP, got %d", resp.StatusCode)
		}
		b.CheckRedirect = nil
		// Present a forged state with a real-looking code.
		resp, _ = get(t, b, e.server+"/auth/oidc/callback?state=forged&code=x")
		if !strings.Contains(resp.Request.URL.RawQuery, "mismatch") {
			t.Fatalf("forged state not rejected as mismatch: %s", resp.Request.URL)
		}
	})

	t.Run("unverified email is refused", func(t *testing.T) {
		idp.SetUser(oidctest.User{Subject: "u-1", Email: "alice@example.test", EmailVerified: false})
		defer idp.SetUser(oidctest.User{Subject: "u-1", Email: "alice@example.test", EmailVerified: true})
		b := browser(t)
		resp, _ := get(t, b, e.server+"/auth/oidc/login")
		if !strings.Contains(resp.Request.URL.RawQuery, "verified") {
			t.Fatalf("unverified email accepted: %s", resp.Request.URL)
		}
	})

	t.Run("CLI device flow sign-in, then member removal ends the session", func(t *testing.T) {
		cfg := filepath.Join(t.TempDir(), "cli.json")
		run := func(args ...string) (string, int) {
			cmd := exec.Command(bin("certloom"), args...)
			cmd.Env = append(os.Environ(), "CERTLOOM_CONFIG="+cfg)
			out, _ := cmd.CombinedOutput()
			return string(out), cmd.ProcessState.ExitCode()
		}
		if out, code := run("login", "--server", e.server, "--oidc"); code != 0 || !strings.Contains(out, "user:alice@example.test") {
			t.Fatalf("device login: %d\n%s", code, out)
		}
		if out, code := run("whoami"); code != 0 || !strings.Contains(out, "operator") {
			t.Fatalf("whoami: %d %s", code, out)
		}
		e.mustCLI("member", "remove", memberID.ID)
		if out, code := run("whoami"); code != 3 {
			t.Fatalf("removed member still authenticated: %d %s", code, out)
		}
	})

	t.Run("sign-ins are audited", func(t *testing.T) {
		var events []struct{ Action, Actor string }
		e.jsonCLI(&events, "audit", "query", "--limit", "1000")
		n := 0
		for _, ev := range events {
			if ev.Action == "auth.sign_in" && ev.Actor == "user:alice@example.test" {
				n++
			}
		}
		if n < 2 {
			t.Fatalf("want >=2 audited sign-ins (web + cli), got %d", n)
		}
	})
}
