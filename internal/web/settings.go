package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/notify"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Pages for organization settings: members, policy and notification channels.
// Destructive actions go through a confirmation page because there is no
// JavaScript to ask in the browser.

// maxPolicySize matches the API's limit for PUT /api/v1/policy.
const maxPolicySize = 64 << 10

// roles in the order the add-member form offers them.
var roles = []string{store.RoleViewer, store.RoleOperator, store.RoleRequester, store.RoleApprover,
	store.RoleDeploymentOperator, store.RoleIssuerAdmin, store.RoleAuditor, store.RoleOwner}

type confirmPage struct {
	Message string
	Action  string
	Button  string
	Back    string
}

type memberRow struct {
	M    store.Member
	Self bool
}

func (u *UI) members(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	ms, err := u.svc.ListMembers(r.Context(), p)
	if err != nil {
		return err
	}
	rows := make([]memberRow, 0, len(ms))
	for _, m := range ms {
		rows = append(rows, memberRow{M: m, Self: strings.EqualFold(p.Actor, "user:"+m.Email)})
	}
	offer := roles
	if p.Role != store.RoleOwner {
		offer = roles[:len(roles)-1]
	}
	return u.render(w, r, "members", p, "Members", "members", map[string]any{"Members": rows, "Roles": offer,
		"OIDC": u.svc.OIDC != nil})
}

func (u *UI) addMember(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	m, err := u.svc.CreateMember(r.Context(), p, strings.TrimSpace(r.FormValue("email")), r.FormValue("role"))
	if err != nil {
		return err
	}
	http.Redirect(w, r, "/members?flash="+url.QueryEscape(m.Email+" added as "+m.Role), http.StatusSeeOther)
	return nil
}

func (u *UI) confirmRemoveMember(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	ms, err := u.svc.ListMembers(r.Context(), p)
	if err != nil {
		return err
	}
	for _, m := range ms {
		if m.ID == r.PathValue("id") {
			return u.render(w, r, "confirm", p, "Remove member", "members", confirmPage{
				Message: fmt.Sprintf("Remove %s (%s)? Their sessions end immediately. API tokens they created keep working until revoked.", m.Email, m.Role),
				Action:  "/members/" + url.PathEscape(m.ID) + "/remove", Button: "Remove member", Back: "/members"})
		}
	}
	return store.ErrNotFound
}

func (u *UI) removeMember(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	if err := u.svc.DeleteMember(r.Context(), p, r.PathValue("id")); err != nil {
		return err
	}
	http.Redirect(w, r, "/members?flash=Member+removed", http.StatusSeeOther)
	return nil
}

// policySource returns the text to edit: what was applied, or the defaults
// rendered as YAML when no policy has been applied yet.
func policySource(pv *store.PolicyVersion) (string, error) {
	if pv.Source != "" {
		return pv.Source, nil
	}
	b, err := pv.Document.YAML()
	return string(b), err
}

func (u *UI) policy(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	pv, err := u.svc.GetPolicy(r.Context(), p)
	if err != nil {
		return err
	}
	src, err := policySource(pv)
	if err != nil {
		return err
	}
	return u.render(w, r, "policy", p, "Policy", "policy", map[string]any{"P": pv, "Source": src,
		"CanManage": p.Can(authz.ManagePolicy)})
}

// policyForm reads the edited source and the version it was based on.
// Browsers submit textareas with CRLF line endings; store LF. The permission
// is checked first: the service parses before it authorizes, and a parse
// error would otherwise send the editor back to someone who may not use it.
func policyForm(r *http.Request, p authz.Principal) ([]byte, int, error) {
	if err := p.Require(authz.ManagePolicy); err != nil {
		return nil, 0, err
	}
	src := strings.ReplaceAll(r.FormValue("source"), "\r\n", "\n")
	if len(src) > maxPolicySize {
		return nil, 0, fmt.Errorf("%w: policy is larger than %d KiB", app.ErrInvalid, maxPolicySize>>10)
	}
	base, err := strconv.Atoi(r.FormValue("base"))
	if err != nil || base < 0 {
		return nil, 0, fmt.Errorf("%w: missing policy base version; reload the policy page", app.ErrInvalid)
	}
	return []byte(src), base, nil
}

func (u *UI) planPolicy(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	src, base, err := policyForm(r, p)
	if err != nil {
		return err
	}
	plan, err := u.svc.ApplyPolicyOver(r.Context(), p, src, true, base)
	if errors.Is(err, app.ErrInvalid) {
		// Keep the edits: show the form again with the error.
		w.WriteHeader(http.StatusBadRequest)
		return u.render(w, r, "policy", p, "Policy", "policy", map[string]any{"P": &store.PolicyVersion{Version: base},
			"Source": string(src), "CanManage": true, "Error": err.Error()})
	}
	if err != nil {
		return err
	}
	return u.render(w, r, "policyplan", p, "Review policy change", "policy", map[string]any{"Plan": plan,
		"Source": string(src), "Base": base})
}

func (u *UI) applyPolicy(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	src, base, err := policyForm(r, p)
	if err != nil {
		return err
	}
	plan, err := u.svc.ApplyPolicyOver(r.Context(), p, src, false, base)
	if err != nil {
		return err
	}
	http.Redirect(w, r, fmt.Sprintf("/policy?flash=Policy+version+%d+applied", plan.Version), http.StatusSeeOther)
	return nil
}

type channelRow struct {
	C      store.Channel
	Target string
}

// channelTarget summarizes where a channel delivers, for the list.
func channelTarget(c store.Channel) string {
	switch c.Kind {
	case "webhook":
		var cfg notify.WebhookConfig
		if json.Unmarshal(c.Config, &cfg) == nil {
			return cfg.URL
		}
	case "email":
		var cfg notify.EmailConfig
		if json.Unmarshal(c.Config, &cfg) == nil {
			return strings.Join(cfg.To, ", ") + " via " + cfg.Host
		}
	}
	return ""
}

func (u *UI) channels(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	cs, err := u.svc.ListChannels(r.Context(), p)
	if err != nil {
		return err
	}
	rows := make([]channelRow, 0, len(cs))
	for _, c := range cs {
		rows = append(rows, channelRow{C: c, Target: channelTarget(c)})
	}
	return u.render(w, r, "channels", p, "Channels", "channels", map[string]any{"Channels": rows,
		"CanManage": p.Can(authz.ManageChannels)})
}

// addChannel builds the channel config from the form for the chosen kind.
// Secrets are never entered here: the form takes a server-side reference
// (env:NAME or file:/path), like the CLI.
func (u *UI) addChannel(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	c := &store.Channel{Name: strings.TrimSpace(r.FormValue("name")), Kind: r.FormValue("kind"),
		CredentialRef: strings.TrimSpace(r.FormValue("credential_ref")), MinSeverity: r.FormValue("min_severity")}
	var cfg any
	switch c.Kind {
	case "webhook":
		cfg = notify.WebhookConfig{URL: strings.TrimSpace(r.FormValue("url")), AllowPrivate: r.FormValue("allow_private") == "on"}
	case "email":
		port, _ := strconv.Atoi(r.FormValue("port"))
		var to []string
		for _, a := range strings.Split(r.FormValue("to"), ",") {
			if a = strings.TrimSpace(a); a != "" {
				to = append(to, a)
			}
		}
		cfg = notify.EmailConfig{Host: strings.TrimSpace(r.FormValue("host")), Port: port,
			Username: strings.TrimSpace(r.FormValue("username")), From: strings.TrimSpace(r.FormValue("from")),
			To: to, TLS: r.FormValue("tls")}
	default:
		return fmt.Errorf("%w: unknown channel kind %q", app.ErrInvalid, c.Kind)
	}
	var err error
	if c.Config, err = json.Marshal(cfg); err != nil {
		return err
	}
	if err := u.svc.CreateChannel(r.Context(), p, c); err != nil {
		return err
	}
	http.Redirect(w, r, "/channels?flash="+url.QueryEscape("Channel "+c.Name+" created. Send a test to check delivery."), http.StatusSeeOther)
	return nil
}

func (u *UI) testChannel(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	if err := u.svc.TestChannel(r.Context(), p, r.PathValue("id")); err != nil {
		return err
	}
	http.Redirect(w, r, "/channels?flash="+url.QueryEscape("Test notification queued. Failed deliveries are retried and logged."), http.StatusSeeOther)
	return nil
}
