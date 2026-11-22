package web

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
)

func (u *UI) authorities(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	all := r.URL.Query().Get("all") == "1"
	list, err := u.svc.ListAuthorities(r.Context(), p, app.AuthorityFilter{InUse: !all})
	if err != nil {
		return err
	}
	return u.render(w, r, "authorities", p, "Certificate authorities", "authorities", map[string]any{"Authorities": list, "All": all})
}

func (u *UI) authority(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	im, err := u.svc.GetAuthorityImpact(r.Context(), p, r.PathValue("key"))
	if err != nil {
		return err
	}
	return u.render(w, r, "authority", p, im.Authority.Subject, "authorities", map[string]any{"Impact": im,
		"CanRenew": p.Can(authz.RunRenewals)})
}

func (u *UI) renewAffected(w http.ResponseWriter, r *http.Request, p authz.Principal) error {
	res, err := u.svc.RenewAffectedDeployments(r.Context(), p, r.PathValue("key"), r.FormValue("all") == "1", false)
	if err != nil {
		return err
	}
	started := 0
	for _, it := range res.Items {
		if it.RunID != "" {
			started++
		}
	}
	msg := fmt.Sprintf("Started %d renewal runs, skipped %d", started, len(res.Items)-started)
	http.Redirect(w, r, "/authorities/"+url.PathEscape(res.Authority)+"?flash="+url.QueryEscape(msg), http.StatusSeeOther)
	return nil
}
