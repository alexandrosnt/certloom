package api

import (
	"net/http"
	"strconv"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/store"
)

func (s *Server) listWebhooks(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListWebhookEndpoints(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) getWebhook(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetWebhookEndpoint(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

// createWebhook returns the endpoint with its secret; the secret is never
// returned again.
func (s *Server) createWebhook(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name         string   `json:"name"`
		URL          string   `json:"url"`
		EventTypes   []string `json:"event_types"`
		AllowPrivate bool     `json:"allow_private,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.CreateWebhookEndpoint(r.Context(), PrincipalFrom(r.Context()), app.WebhookEndpointInput{Name: req.Name, URL: req.URL,
		EventTypes: req.EventTypes, AllowPrivate: req.AllowPrivate})
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 201, v)
	return nil
}

func (s *Server) setWebhookEnabled(enabled bool) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		if err := s.Svc.SetWebhookEndpointEnabled(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), enabled); err != nil {
			return err
		}
		w.WriteHeader(204)
		return nil
	}
}

func (s *Server) rotateWebhookSecret(w http.ResponseWriter, r *http.Request) error {
	sec, err := s.Svc.RotateWebhookSecret(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, map[string]string{"secret": sec})
	return nil
}

func (s *Server) deleteWebhook(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.DeleteWebhookEndpoint(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) listWebhookDeliveries(w http.ResponseWriter, r *http.Request) error {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, err := s.Svc.ListWebhookDeliveries(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), limit)
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) redeliverWebhook(w http.ResponseWriter, r *http.Request) error {
	id, err := strconv.ParseInt(r.PathValue("delivery"), 10, 64)
	if err != nil {
		return store.ErrNotFound
	}
	if err := s.Svc.RedeliverWebhook(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), id); err != nil {
		return err
	}
	w.WriteHeader(202)
	return nil
}
