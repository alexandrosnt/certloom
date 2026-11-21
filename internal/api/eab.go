package api

import (
	"net/http"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/secret"
)

func (s *Server) setIssuerEAB(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Mode string `json:"mode"`
		KID  string `json:"kid,omitempty"`
		HMAC string `json:"hmac,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	in := app.EABInput{Mode: req.Mode, KID: req.KID}
	if req.HMAC != "" {
		in.HMAC = secret.New([]byte(req.HMAC))
	}
	v, err := s.Svc.SetIssuerEAB(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), in)
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) listEABKeys(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListEABKeys(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) addEABKey(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		KID       string     `json:"kid"`
		HMAC      string     `json:"hmac"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.AddEABKey(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), req.KID, secret.New([]byte(req.HMAC)), req.ExpiresAt)
	if err != nil {
		return err
	}
	writeJSON(w, 201, v)
	return nil
}

func (s *Server) deleteEABKey(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.DeleteEABKey(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), r.PathValue("key")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}
