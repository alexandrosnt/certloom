package api

import (
	"io"
	"net/http"
)

func (s *Server) listTemplates(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListTemplates(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) getTemplate(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetTemplate(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

// putTemplate validates a YAML/JSON template, reports its impact on the
// deployments using it, and applies it unless ?dry_run=true.
func (s *Server) putTemplate(w http.ResponseWriter, r *http.Request) error {
	src, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil {
		return err
	}
	plan, err := s.Svc.ApplyTemplate(r.Context(), PrincipalFrom(r.Context()), src, r.URL.Query().Get("dry_run") == "true")
	if err != nil {
		return err
	}
	writeJSON(w, 200, plan)
	return nil
}

func (s *Server) deleteTemplate(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.DeleteTemplate(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}
