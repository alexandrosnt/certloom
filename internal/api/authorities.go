package api

import (
	"errors"
	"net/http"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/policy"
)

func (s *Server) listAuthorities(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	f := app.AuthorityFilter{InUse: q.Get("in_use") == "true"}
	switch q.Get("kind") {
	case "":
	case "root":
		f.Roots = true
	case "intermediate":
		f.Intermediates = true
	default:
		return errors.Join(errBadRequest, errors.New("kind must be root or intermediate"))
	}
	v, err := s.Svc.ListAuthorities(r.Context(), PrincipalFrom(r.Context()), f)
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) getAuthority(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetAuthorityImpact(r.Context(), PrincipalFrom(r.Context()), r.PathValue("key"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) authorityPlan(w http.ResponseWriter, r *http.Request) error {
	within := 365 * 24 * time.Hour
	if v := r.URL.Query().Get("within"); v != "" {
		d, err := policy.ParseDuration(v)
		if err != nil {
			return errors.Join(errBadRequest, err)
		}
		within = d
	}
	v, err := s.Svc.AuthorityPlan(r.Context(), PrincipalFrom(r.Context()), within)
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) renewAffected(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		All    bool `json:"all,omitempty"`
		DryRun bool `json:"dry_run,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.RenewAffectedDeployments(r.Context(), PrincipalFrom(r.Context()), r.PathValue("key"), req.All, req.DryRun)
	if err != nil {
		return err
	}
	status := 202
	if req.DryRun {
		status = 200
	}
	writeJSON(w, status, v)
	return nil
}
