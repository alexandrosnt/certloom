package api

import (
	"encoding/json"
	"net/http"

	"github.com/alexandrosnt/certloom/internal/app"
)

// Cloud accounts that certloomd reads itself (ADR-0034). A stored secret is
// accepted on create and on PUT .../secret and is never returned.

func (s *Server) listCloudAccounts(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListCloudAccounts(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) getCloudAccount(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetCloudAccount(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set("ETag", etag(v.Version))
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) createCloudAccount(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name            string          `json:"name"`
		Provider        string          `json:"provider"`
		Credential      string          `json:"credential,omitempty"`
		Settings        json.RawMessage `json:"settings"`
		IntervalSeconds int             `json:"interval_seconds,omitempty"`
		Secret          json.RawMessage `json:"secret,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.CreateCloudAccount(r.Context(), PrincipalFrom(r.Context()), app.CloudAccountInput{Name: req.Name,
		Provider: req.Provider, Credential: req.Credential, Settings: req.Settings, IntervalSeconds: req.IntervalSeconds,
		Secret: secretBody(req.Secret)})
	clear(req.Secret)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", etag(v.Version))
	writeJSON(w, 201, v)
	return nil
}

func (s *Server) updateCloudAccount(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Settings        json.RawMessage `json:"settings"`
		IntervalSeconds int             `json:"interval_seconds,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	ver, err := ifMatch(r)
	if err != nil {
		return err
	}
	v, err := s.Svc.UpdateCloudAccount(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"),
		app.CloudAccountInput{Settings: req.Settings, IntervalSeconds: req.IntervalSeconds}, ver)
	if err != nil {
		return err
	}
	w.Header().Set("ETag", etag(v.Version))
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) setCloudAccountSecret(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Secret json.RawMessage `json:"secret"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	err := s.Svc.SetCloudAccountSecret(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), secretBody(req.Secret))
	clear(req.Secret)
	if err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) scanCloudAccount(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.RequestCloudScan(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(202)
	return nil
}

func (s *Server) cloudAccountInventory(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.CloudAccountInventory(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) deleteCloudAccount(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.DeleteCloudAccount(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}
