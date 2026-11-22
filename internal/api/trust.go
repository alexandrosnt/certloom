package api

import (
	"net/http"

	"github.com/alexandrosnt/certloom/internal/app"
)

func (s *Server) listTrustBundles(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListTrustBundles(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) getTrustBundle(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetTrustBundle(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) trustStatus(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.TrustStatus(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

// putTrustBundle plans and, unless dry_run, applies a bundle's desired state.
func (s *Server) putTrustBundle(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name        string              `json:"name"`
		Team        string              `json:"team,omitempty"`
		Anchors     []string            `json:"anchors"`
		Stores      []app.TrustStoreRef `json:"stores"`
		BaseVersion *int                `json:"base_version,omitempty"`
		DryRun      bool                `json:"dry_run,omitempty"`
		Force       bool                `json:"force,omitempty"`
		Reason      string              `json:"reason,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	plan, err := s.Svc.ApplyTrustBundle(r.Context(), PrincipalFrom(r.Context()), app.TrustBundleInput{Name: req.Name, Team: req.Team,
		Anchors: req.Anchors, Stores: req.Stores, BaseVersion: req.BaseVersion, DryRun: req.DryRun, Force: req.Force, Reason: req.Reason})
	if err != nil {
		return err
	}
	writeJSON(w, 200, plan)
	return nil
}

func (s *Server) deleteTrustBundle(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.DeleteTrustBundle(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}
