// Package agentapi serves the agent channel: HTTPS + JSON over
// mutual TLS on a dedicated listener. Agents always dial out to it.
package agentapi

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/api"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Server is the agent listener.
type Server struct {
	Svc         *app.Service
	Log         *slog.Logger
	enrollLimit *api.Limiter
}

// TLSConfig returns a TLS 1.3 config with a server certificate issued by the
// internal agent CA for names, verifying client certificates against that CA.
// Client certificates are optional at the TLS layer only so that enrollment
// (token-authenticated) can reach its endpoint; every other endpoint
// requires a verified client certificate.
func (s *Server) TLSConfig(names []string) (*tls.Config, error) {
	certPEM, keyPEM, err := s.Svc.PKI.ServerCert(names)
	if err != nil {
		return nil, err
	}
	kp, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(s.Svc.PKI.CA)
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{kp}, ClientCAs: pool,
		ClientAuth: tls.VerifyClientCertIfGiven}, nil
}

// Handler returns the agent API.
func (s *Server) Handler() http.Handler {
	if s.enrollLimit == nil {
		s.enrollLimit = api.NewLimiter(0.1, 5)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+agentproto.PathEnroll, s.enroll)
	mux.HandleFunc("POST "+agentproto.PathRenew, s.agent(s.renew))
	mux.HandleFunc("POST "+agentproto.PathHeartbeat, s.agent(s.heartbeat))
	mux.HandleFunc("GET "+agentproto.PathTasks, s.agent(s.tasks))
	mux.HandleFunc("POST "+agentproto.PathResult, s.agent(s.result))
	return api.RequestIDs(mux)
}

type agentHandler func(w http.ResponseWriter, r *http.Request, id app.AgentIdentity)

func (s *Server) agent(fn agentHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		id, err := s.Svc.AuthenticateAgent(r.Context(), r.TLS.VerifiedChains[0][0])
		if err != nil {
			http.Error(w, "agent unknown or revoked", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 8<<20)
		fn(w, r, id)
	}
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrInvalidToken):
		http.Error(w, "invalid, used or expired enrollment token", http.StatusUnauthorized)
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, app.ErrInvalid):
		http.Error(w, err.Error(), http.StatusBadRequest)
	default:
		s.Log.Error("agent api", "error", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) enroll(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	if ok, _, _ := s.enrollLimit.Allow(ip); !ok {
		http.Error(w, "too many enrollment attempts", http.StatusTooManyRequests)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req agentproto.EnrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	resp, err := s.Svc.Enroll(r.Context(), req)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, resp)
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request, id app.AgentIdentity) {
	var req agentproto.RenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	certPEM, err := s.Svc.RenewAgentCert(r.Context(), id, req.CSRPEM)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, map[string]string{"cert_pem": certPEM})
}

func (s *Server) heartbeat(w http.ResponseWriter, r *http.Request, id app.AgentIdentity) {
	var hb agentproto.Heartbeat
	if err := json.NewDecoder(r.Body).Decode(&hb); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.Svc.AgentHeartbeat(r.Context(), id, hb); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) tasks(w http.ResponseWriter, r *http.Request, id app.AgentIdentity) {
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	wait = min(max(wait, 0), 30)
	envs, err := s.Svc.AgentPoll(r.Context(), id, time.Duration(wait)*time.Second)
	if err != nil {
		s.fail(w, err)
		return
	}
	if envs == nil {
		envs = []agentproto.Envelope{}
	}
	writeJSON(w, agentproto.TaskList{Tasks: envs})
}

func (s *Server) result(w http.ResponseWriter, r *http.Request, id app.AgentIdentity) {
	var res agentproto.Result
	if err := json.NewDecoder(r.Body).Decode(&res); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := s.Svc.AgentResult(r.Context(), id, r.PathValue("id"), res); err != nil {
		s.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
