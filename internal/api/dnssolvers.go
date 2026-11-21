package api

import (
	"encoding/json"
	"net/http"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/secret"
)

// secretBody returns a request's "secret" object as a secret value. The raw
// bytes go straight into secret.Value so they never pass through a type that
// could be logged or echoed.
func secretBody(raw json.RawMessage) secret.Value {
	if len(raw) == 0 || string(raw) == "null" {
		return secret.Value{}
	}
	return secret.New(raw)
}

func (s *Server) listDNSSolvers(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListDNSSolvers(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) getDNSSolver(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetDNSSolver(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) createDNSSolver(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name         string          `json:"name"`
		Provider     string          `json:"provider"`
		Plugin       string          `json:"plugin,omitempty"`
		PluginSHA256 string          `json:"plugin_sha256,omitempty"`
		Zones        []string        `json:"zones"`
		Config       map[string]any  `json:"config,omitempty"`
		Credential   string          `json:"credential,omitempty"`
		Secret       json.RawMessage `json:"secret,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.CreateDNSSolver(r.Context(), PrincipalFrom(r.Context()), app.DNSSolverInput{Name: req.Name, Provider: req.Provider,
		Plugin: req.Plugin, PluginSHA256: req.PluginSHA256, Zones: req.Zones, Config: req.Config, Credential: req.Credential,
		Secret: secretBody(req.Secret)})
	clear(req.Secret)
	if err != nil {
		return err
	}
	writeJSON(w, 201, v)
	return nil
}

func (s *Server) setDNSSolverSecret(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Secret json.RawMessage `json:"secret"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	err := s.Svc.SetDNSSolverSecret(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), secretBody(req.Secret))
	clear(req.Secret)
	if err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) assignDNSSolver(w http.ResponseWriter, r *http.Request) error {
	err := s.Svc.AssignDNSSolver(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), r.PathValue("agent"), r.Method == http.MethodPut)
	if err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) deleteDNSSolver(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.DeleteDNSSolver(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}
