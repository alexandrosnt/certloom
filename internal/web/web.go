// Package web serves the server-rendered dashboard. It uses the
// same service layer as the API, so authorization and audit are identical.
// No JavaScript: forms post back, which keeps the CSP strict (script-src 'self'
// with nothing to load).
package web

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/api"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/oidcauth"
	"github.com/alexandrosnt/certloom/internal/store"
)

//go:embed templates/*.html static/*
var assets embed.FS

const cookieName = "certloom_session"

// UI is the dashboard handler.
type UI struct {
	svc     *app.Service
	log     *slog.Logger
	tmpl    map[string]*template.Template
	csrfKey []byte
	// loginLimit throttles failed token sign-ins per client IP.
	loginLimit *api.Limiter
	// SecureCookies marks session cookies Secure. Set it whenever browsers reach
	// the UI over HTTPS, including through a TLS-terminating proxy.
	SecureCookies bool
}

// New parses templates and returns the UI.
func New(svc *app.Service, log *slog.Logger) *UI {
	u := &UI{svc: svc, log: log, tmpl: map[string]*template.Template{}, csrfKey: csrfKey(svc, log),
		loginLimit: api.NewLimiter(0.2, 10)}
	funcs := template.FuncMap{
		"ts": func(t any) string {
			switch v := t.(type) {
			case time.Time:
				return v.UTC().Format("2006-01-02 15:04 UTC")
			case *time.Time:
				if v == nil {
					return "-"
				}
				return v.UTC().Format("2006-01-02 15:04 UTC")
			}
			return ""
		},
		"left": func(t time.Time) string {
			d := time.Until(t)
			switch {
			case d < 0:
				return fmt.Sprintf("expired %dd ago", int(-d.Hours()/24))
			case d < 48*time.Hour:
				return fmt.Sprintf("%dh", int(d.Hours()))
			}
			return fmt.Sprintf("%dd", int(d.Hours()/24))
		},
		"urgency": func(t time.Time) string {
			d := time.Until(t)
			switch {
			case d < 7*24*time.Hour:
				return "critical"
			case d < 30*24*time.Hour:
				return "warning"
			}
			return "ok"
		},
		"short": func(s any) string {
			var v string
			switch x := s.(type) {
			case string:
				v = x
			case *string:
				if x == nil {
					return "-"
				}
				v = *x
			}
			if len(v) > 16 {
				return v[:16]
			}
			return v
		},
		"join": strings.Join,
		"can":  func(p authz.Principal, perm string) bool { return p.Can(authz.Permission(perm)) },
		"deref": func(s *string) string {
			if s == nil {
				return ""
			}
			return *s
		},
		"add1":        func(n int) int { return n + 1 },
		"runClass":    runClass,
		"healthClass": healthClass,
	}
	pages, _ := fs.Glob(assets, "templates/*.html")
	for _, p := range pages {
		name := strings.TrimSuffix(strings.TrimPrefix(p, "templates/"), ".html")
		if name == "layout" {
			continue
		}
		u.tmpl[name] = template.Must(template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", p))
	}
	return u
}

// Handler returns the UI routes.
func (u *UI) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /login", u.loginForm)
	mux.HandleFunc("POST /login", u.login)
	mux.HandleFunc("POST /logout", u.logout)
	mux.HandleFunc("GET /auth/oidc/login", u.oidcLogin)
	mux.HandleFunc("GET /auth/oidc/callback", u.oidcCallback)
	page := func(pattern string, fn func(w http.ResponseWriter, r *http.Request, p authz.Principal) error) {
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			p, tok, ok := u.session(r)
			if !ok {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
				return
			}
			if r.Method == http.MethodPost {
				r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
				if !hmac.Equal([]byte(r.FormValue("csrf")), []byte(u.csrf(tok))) {
					http.Error(w, "invalid CSRF token; reload the page", http.StatusForbidden)
					return
				}
			}
			r = r.WithContext(withToken(r.Context(), tok))
			if err := fn(w, r, p); err != nil {
				u.fail(w, r, p, err)
			}
		})
	}
	page("GET /{$}", u.overview)
	page("GET /certificates", u.certificates)
	page("GET /certificates/{fp}", u.certificate)
	page("GET /endpoints", u.endpoints)
	page("POST /endpoints", u.addEndpoint)
	page("GET /endpoints/{id}", u.endpoint)
	page("POST /endpoints/{id}/probe", u.probe)
	page("GET /findings", u.findings)
	page("GET /alerts", u.alerts)
	page("POST /alerts/{id}/ack", u.ack)
	page("GET /lineages", u.lineages)
	page("GET /agents", u.agents)
	page("GET /agents/{id}", u.agent)
	page("GET /deployments", u.deployments)
	page("POST /deployments/{id}/renew", u.renew)
	page("GET /authorities", u.authorities)
	page("GET /authorities/{key}", u.authority)
	page("POST /authorities/{key}/renew-affected", u.renewAffected)
	page("GET /runs", u.runs)
	page("GET /runs/{id}", u.run)
	page("POST /runs/{id}/cancel", u.cancelRun)
	page("GET /members", u.members)
	page("POST /members", u.addMember)
	page("GET /members/{id}/remove", u.confirmRemoveMember)
	page("POST /members/{id}/remove", u.removeMember)
	page("GET /policy", u.policy)
	page("POST /policy/plan", u.planPolicy)
	page("POST /policy/apply", u.applyPolicy)
	page("GET /channels", u.channels)
	page("POST /channels", u.addChannel)
	page("POST /channels/{id}/test", u.testChannel)
	page("GET /audit", u.audit)
	return mux
}

func (u *UI) csrf(token string) string {
	m := hmac.New(sha256.New, u.csrfKey)
	m.Write([]byte(token))
	return hex.EncodeToString(m.Sum(nil))
}

func (u *UI) session(r *http.Request) (authz.Principal, string, bool) {
	c, err := r.Cookie(cookieName)
	if err != nil || c.Value == "" {
		return authz.Principal{}, "", false
	}
	p, err := u.svc.Authenticate(r.Context(), c.Value)
	if err != nil {
		return authz.Principal{}, "", false
	}
	return p, c.Value, true
}

type data struct {
	Title     string
	Nav       string
	Principal authz.Principal
	CSRF      string
	Flash     string
	Error     string
	D         any
}

func (u *UI) render(w http.ResponseWriter, r *http.Request, name string, p authz.Principal, title, nav string, d any) error {
	t, ok := u.tmpl[name]
	if !ok {
		return fmt.Errorf("unknown template %s", name)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	return t.Execute(w, data{Title: title, Nav: nav, Principal: p, CSRF: u.csrf(tokenFrom(r.Context())),
		Flash: r.URL.Query().Get("flash"), D: d})
}

func (u *UI) fail(w http.ResponseWriter, r *http.Request, p authz.Principal, err error) {
	status, msg := 500, "Something went wrong. The request id is in the X-Request-Id response header."
	switch {
	case errors.Is(err, authz.ErrForbidden):
		status, msg = 403, "Your role does not allow this action."
	case errors.Is(err, store.ErrNotFound):
		status, msg = 404, "Not found."
	case errors.Is(err, app.ErrInvalid), errors.Is(err, store.ErrConflict):
		status, msg = 400, err.Error()
	default:
		u.log.Error("ui request failed", "path", r.URL.Path, "error", err)
	}
	w.WriteHeader(status)
	_ = u.tmpl["error"].Execute(w, data{Title: http.StatusText(status), Principal: p, Error: msg})
}

func (u *UI) loginForm(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = u.tmpl["login"].Execute(w, data{Title: "Sign in", Error: r.URL.Query().Get("error"),
		D: map[string]any{"OIDC": u.svc.OIDC != nil, "Org": r.URL.Query().Get("org")}})
}

const oidcCookie = "certloom_oidc"

// oidcLogin starts the authorization-code flow with state, nonce and PKCE.
// The three values are kept in one short-lived HttpOnly cookie; SameSite=Lax
// is required because the IdP redirects back with a cross-site top-level GET.
func (u *UI) oidcLogin(w http.ResponseWriter, r *http.Request) {
	if u.svc.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	state, nonce, verifier := oidcauth.Random(), oidcauth.Random(), oidcauth.Random()
	org := r.URL.Query().Get("org")
	if len(org) > 200 || strings.ContainsAny(org, "|\r\n") {
		org = ""
	}
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: strings.Join([]string{state, nonce, verifier, url.QueryEscape(org)}, "|"),
		Path: "/auth/oidc/", HttpOnly: true, Secure: u.SecureCookies, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, u.svc.OIDC.AuthCodeURL(state, nonce, verifier), http.StatusFound)
}

func (u *UI) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if u.svc.OIDC == nil {
		http.NotFound(w, r)
		return
	}
	fail := func(msg string) {
		http.Redirect(w, r, "/login?error="+url.QueryEscape(msg), http.StatusSeeOther)
	}
	c, err := r.Cookie(oidcCookie)
	http.SetCookie(w, &http.Cookie{Name: oidcCookie, Value: "", Path: "/auth/oidc/", MaxAge: -1, HttpOnly: true, Secure: u.SecureCookies,
		SameSite: http.SameSiteLaxMode})
	if err != nil {
		fail("Sign-in expired; please try again.")
		return
	}
	parts := strings.Split(c.Value, "|")
	if len(parts) != 4 || r.URL.Query().Get("state") == "" ||
		!hmac.Equal([]byte(parts[0]), []byte(r.URL.Query().Get("state"))) {
		fail("Sign-in state mismatch; please try again.")
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		fail("Identity provider returned: " + e)
		return
	}
	id, err := u.svc.OIDC.Exchange(r.Context(), r.URL.Query().Get("code"), parts[2], parts[1])
	if err != nil {
		u.log.Warn("oidc sign-in failed", "error", err)
		if errors.Is(err, oidcauth.ErrUnverifiedEmail) {
			fail("Your identity provider did not confirm a verified email address.")
			return
		}
		fail("Sign-in failed.")
		return
	}
	org, _ := url.QueryUnescape(parts[3])
	tok, _, err := u.svc.SignIn(r.Context(), id, org, "web-oidc")
	if err != nil {
		var choose *app.ErrChooseOrg
		switch {
		case errors.As(err, &choose):
			fail(err.Error() + ". Use the organization field.")
		case errors.Is(err, app.ErrNoMembership):
			fail(id.Email + " is not a member of this organization. Ask an owner to add you (certloom member add).")
		default:
			u.log.Error("oidc session", "error", err)
			fail("Sign-in failed.")
		}
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok.RevealString(), Path: "/", HttpOnly: true, Secure: u.SecureCookies,
		SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	// Redirect via a same-site page: a SameSite=Strict cookie is not sent on the
	// cross-site navigation that brought us here, so link to / from our own page.
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`<!doctype html><meta http-equiv="refresh" content="0;url=/"><a href="/">Continue</a>`))
}

func (u *UI) login(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 8<<10)
	tok := strings.TrimSpace(r.FormValue("token"))
	if _, err := u.svc.Authenticate(r.Context(), tok); err != nil {
		// Failed attempts consume a per-IP budget (brute-force throttle).
		if ok, _, _ := u.loginLimit.Allow("ip:" + remoteIP(r)); !ok {
			http.Error(w, "Too many failed sign-in attempts from this address; try again later.", http.StatusTooManyRequests)
			return
		}
		http.Redirect(w, r, "/login?error=Invalid+or+expired+token", http.StatusSeeOther)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: u.SecureCookies,
		SameSite: http.SameSiteStrictMode, MaxAge: 12 * 3600})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (u *UI) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		if err := u.svc.SignOut(r.Context(), c.Value); err != nil {
			u.log.Warn("sign out", "error", err)
		}
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: u.SecureCookies,
		SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ---- pages ----

func (u *UI) overview(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	m, err := u.svc.Overview(r.Context(), p)
	if err != nil {
		return err
	}
	alerts, err := u.svc.ListAlerts(r.Context(), p, []string{"open"})
	if err != nil {
		return err
	}
	if len(alerts) > 10 {
		alerts = alerts[:10]
	}
	return u.render(w, r, "overview", p, "Overview", "overview", map[string]any{"Metrics": m, "Alerts": alerts})
}

func (u *UI) certificates(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	q := r.URL.Query()
	f := store.CertFilter{Search: q.Get("search"), IncludeCA: q.Get("include_ca") == "on", Limit: 200}
	if v := q.Get("expiring"); v != "" {
		if d, err := strconv.Atoi(strings.TrimSuffix(v, "d")); err == nil {
			f.ExpiresBefore = time.Now().Add(time.Duration(d) * 24 * time.Hour)
		}
	}
	certs, err := u.svc.ListCertificates(r.Context(), p, f)
	if err != nil {
		return err
	}
	return u.render(w, r, "certificates", p, "Certificates", "certificates", map[string]any{"Certs": certs, "Q": q})
}

func (u *UI) certificate(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	d, err := u.svc.GetCertificate(r.Context(), p, r.PathValue("fp"))
	if err != nil {
		return err
	}
	return u.render(w, r, "certificate", p, d.CommonName, "certificates", d)
}

func (u *UI) endpoints(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	eps, err := u.svc.ListEndpoints(r.Context(), p)
	if err != nil {
		return err
	}
	scopes, err := u.svc.ListScopes(r.Context(), p)
	if err != nil {
		return err
	}
	if r.URL.Query().Get("failing") == "1" {
		f := eps[:0]
		for _, e := range eps {
			if e.ConsecutiveFailures > 0 {
				f = append(f, e)
			}
		}
		eps = f
	}
	return u.render(w, r, "endpoints", p, "Endpoints", "endpoints", map[string]any{"Endpoints": eps, "Scopes": scopes,
		"CanManage": p.Can(authz.ManageEndpoints)})
}

func (u *UI) addEndpoint(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	port, _ := strconv.Atoi(r.FormValue("port"))
	e, err := u.svc.AddEndpoint(r.Context(), p, app.AddEndpointInput{Host: r.FormValue("host"), Port: port,
		SNI: r.FormValue("sni"), Scope: r.FormValue("scope")})
	if err != nil {
		return err
	}
	http.Redirect(w, r, "/endpoints/"+e.ID+"?flash="+url.QueryEscape("Endpoint added. The first probe runs within seconds."), http.StatusSeeOther)
	return nil
}

func (u *UI) endpoint(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	d, err := u.svc.GetEndpoint(r.Context(), p, r.PathValue("id"))
	if err != nil {
		return err
	}
	return u.render(w, r, "endpoint", p, d.Host, "endpoints", map[string]any{"E": d, "CanManage": p.Can(authz.ManageEndpoints)})
}

func (u *UI) probe(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	id := r.PathValue("id")
	if err := u.svc.RequestProbe(r.Context(), p, id); err != nil {
		return err
	}
	http.Redirect(w, r, "/endpoints/"+id+"?flash=Probe+scheduled", http.StatusSeeOther)
	return nil
}

func (u *UI) findings(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	q := r.URL.Query()
	fs, err := u.svc.ListFindings(r.Context(), p, store.FindingFilter{MinSeverity: q.Get("severity")})
	if err != nil {
		return err
	}
	if c := q.Get("check"); c != "" {
		out := fs[:0]
		for _, f := range fs {
			if f.Check == c {
				out = append(out, f)
			}
		}
		fs = out
	}
	return u.render(w, r, "findings", p, "Findings", "findings", fs)
}

func (u *UI) alerts(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	a, err := u.svc.ListAlerts(r.Context(), p, []string{"open", "acked"})
	if err != nil {
		return err
	}
	return u.render(w, r, "alerts", p, "Alerts", "alerts", map[string]any{"Alerts": a, "CanAck": p.Can(authz.AckAlerts)})
}

func (u *UI) ack(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	if err := u.svc.AckAlert(r.Context(), p, r.PathValue("id")); err != nil {
		return err
	}
	http.Redirect(w, r, "/alerts?flash=Alert+acknowledged", http.StatusSeeOther)
	return nil
}

func (u *UI) lineages(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	l, err := u.svc.ListLineages(r.Context(), p)
	if err != nil {
		return err
	}
	return u.render(w, r, "lineages", p, "Lineages", "lineages", l)
}

func (u *UI) audit(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after_seq"), 10, 64)
	ev, err := u.svc.AuditQuery(r.Context(), p, after, 200)
	if err != nil {
		return err
	}
	v, err := u.svc.AuditVerify(r.Context(), p)
	if err != nil {
		return err
	}
	exp, err := u.svc.AuditExportStatus(r.Context(), p)
	if err != nil {
		return err
	}
	return u.render(w, r, "audit", p, "Audit", "audit", map[string]any{"Events": ev, "Verify": v, "Export": exp})
}

// csrfKey derives the CSRF key from the KEK so that a form served by one
// replica verifies on any other. Without a KEK there is only one key per
// process, which is fine for a single replica.
func csrfKey(svc *app.Service, log *slog.Logger) []byte {
	if svc.PKI != nil && svc.PKI.KEK != nil {
		return svc.PKI.KEK.Derive("certloom csrf v1")
	}
	log.Warn("no KEK configured: CSRF tokens are valid only on this replica")
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return b
}
