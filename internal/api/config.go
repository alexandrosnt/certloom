package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Get, PATCH and DELETE for configuration objects. PATCH bodies follow JSON
// merge-patch: absent fields are left unchanged.

func (s *Server) getTeam(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetTeam(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) patchTeam(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name    *string `json:"name"`
		Contact *string `json:"contact"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.UpdateTeam(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), app.TeamPatch{Name: req.Name, Contact: req.Contact})
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) deleteTeam(w http.ResponseWriter, r *http.Request) error {
	return noContent(w, s.Svc.DeleteTeam(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")))
}

func (s *Server) getScope(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetScope(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) patchScope(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name   *string            `json:"name"`
		Config *store.ScopeConfig `json:"config"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.UpdateScope(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), app.ScopePatch{Name: req.Name, Config: req.Config})
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) deleteScope(w http.ResponseWriter, r *http.Request) error {
	return noContent(w, s.Svc.DeleteScope(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")))
}

func (s *Server) patchEndpoint(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Scope           *string `json:"scope"`
		Team            *string `json:"team"`
		Lineage         *string `json:"lineage"`
		IntervalSeconds *int    `json:"interval_seconds"`
		Enabled         *bool   `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	ver, err := ifMatch(r)
	if err != nil {
		return err
	}
	in := app.EndpointPatch{Scope: req.Scope, Team: req.Team, Lineage: req.Lineage, Enabled: req.Enabled}
	if req.IntervalSeconds != nil {
		d := time.Duration(*req.IntervalSeconds) * time.Second
		in.Interval = &d
	}
	v, err := s.Svc.UpdateEndpoint(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), in, ver)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", etag(v.Version))
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) deleteEndpoint(w http.ResponseWriter, r *http.Request) error {
	return noContent(w, s.Svc.DeleteEndpoint(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")))
}

func (s *Server) getChannel(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetChannel(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) patchChannel(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name          *string         `json:"name"`
		Config        json.RawMessage `json:"config"`
		CredentialRef *string         `json:"credential_ref"`
		MinSeverity   *string         `json:"min_severity"`
		Enabled       *bool           `json:"enabled"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.UpdateChannel(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), app.ChannelPatch{Name: req.Name,
		Config: req.Config, CredentialRef: req.CredentialRef, MinSeverity: req.MinSeverity, Enabled: req.Enabled})
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) deleteChannel(w http.ResponseWriter, r *http.Request) error {
	return noContent(w, s.Svc.DeleteChannel(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")))
}

func (s *Server) getIssuer(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetIssuer(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) patchIssuer(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name     *string `json:"name"`
		Email    *string `json:"email"`
		Profile  *string `json:"profile"`
		CABundle *string `json:"ca_bundle"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.UpdateIssuer(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), app.IssuerPatch{Name: req.Name,
		Email: req.Email, Profile: req.Profile, CABundle: req.CABundle})
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) deleteIssuer(w http.ResponseWriter, r *http.Request) error {
	return noContent(w, s.Svc.DeleteIssuer(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")))
}

func noContent(w http.ResponseWriter, err error) error {
	if err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}
