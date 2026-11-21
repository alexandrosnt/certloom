// Package api serves the versioned REST API. Handlers are thin:
// decode, call the service layer (which authorizes and audits), encode.
package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/version"
)

// MaxBody is the request body limit (certificate imports are <= 1 MiB raw).
const MaxBody = 2 << 20

// Server holds API dependencies.
type Server struct {
	Svc *app.Service
	Log *slog.Logger
	// Rate limiters; defaults are set by Handler when nil.
	UserLimit, IPFailLimit, PublicLimit *Limiter
	routes                              []string
}

type principalKey struct{}

// PrincipalFrom returns the authenticated principal.
func PrincipalFrom(ctx context.Context) authz.Principal {
	p, _ := ctx.Value(principalKey{}).(authz.Principal)
	return p
}

// WithPrincipal stores p in ctx.
func WithPrincipal(ctx context.Context, p authz.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// Handler returns the API handler.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	if s.UserLimit == nil {
		s.UserLimit = NewLimiter(20, 60) // per principal
	}
	if s.IPFailLimit == nil {
		s.IPFailLimit = NewLimiter(0.2, 10) // failed authentications per client IP
	}
	if s.PublicLimit == nil {
		s.PublicLimit = NewLimiter(1, 10) // unauthenticated sign-in calls per client IP
	}
	s.routes = nil
	h := func(pattern string, fn handlerFunc) {
		s.routes = append(s.routes, pattern)
		mux.Handle(pattern, s.authed(s.idempotent(pattern, fn)))
	}
	pub := func(pattern string, fn http.HandlerFunc) {
		s.routes = append(s.routes, pattern)
		mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
			if ok, _, retry := s.PublicLimit.Allow("ip:" + clientIP(r)); !ok {
				tooMany(w, r, retry, "too many sign-in requests from this address")
				return
			}
			fn(w, r)
		})
	}
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.Svc.DB.Pool.Ping(r.Context()); err != nil {
			problem(w, r, 503, "not-ready", "database unavailable", "")
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ready", "version": version.Version})
	})
	s.routes = append(s.routes, "GET /healthz", "GET /readyz")

	// Public (unauthenticated) sign-in endpoints.
	pub("GET /api/v1/auth/config", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, s.Svc.PublicAuthConfig()) })
	pub("POST /api/v1/auth/oidc/session", s.oidcSession)

	h("GET /api/v1/whoami", s.whoami)
	h("GET /api/v1/members", s.listMembers)
	h("POST /api/v1/members", s.createMember)
	h("DELETE /api/v1/members/{id}", s.deleteMember)
	h("DELETE /api/v1/auth/session", s.signOut)
	h("GET /api/v1/overview", s.overview)
	h("GET /api/v1/certificates", s.listCertificates)
	h("GET /api/v1/certificates/{fp}", s.getCertificate)
	h("POST /api/v1/certificates/import", s.importCertificates)
	h("GET /api/v1/scopes", s.listScopes)
	h("POST /api/v1/scopes", s.createScope)
	h("GET /api/v1/endpoints", s.listEndpoints)
	h("POST /api/v1/endpoints", s.createEndpoint)
	h("GET /api/v1/endpoints/{id}", s.getEndpoint)
	h("POST /api/v1/endpoints/{id}/probe", s.probeEndpoint)
	h("PUT /api/v1/endpoints/{id}/lineage", s.bindEndpointLineage)
	h("GET /api/v1/findings", s.listFindings)
	h("GET /api/v1/teams", s.listTeams)
	h("POST /api/v1/teams", s.createTeam)
	h("GET /api/v1/lineages", s.listLineages)
	h("POST /api/v1/lineages", s.createLineage)
	h("GET /api/v1/lineages/{id}", s.getLineage)
	h("PUT /api/v1/lineages/{id}/owner", s.assignOwner)
	h("GET /api/v1/alerts", s.listAlerts)
	h("POST /api/v1/alerts/{id}/ack", s.ackAlert)
	h("GET /api/v1/channels", s.listChannels)
	h("POST /api/v1/channels", s.createChannel)
	h("POST /api/v1/channels/{id}/test", s.testChannel)
	h("GET /api/v1/tokens", s.listTokens)
	h("POST /api/v1/tokens", s.createToken)
	h("DELETE /api/v1/tokens/{id}", s.revokeToken)
	h("GET /api/v1/audit", s.auditQuery)
	h("GET /api/v1/audit/verify", s.auditVerify)
	h("GET /api/v1/audit/export-status", s.auditExportStatus)
	h("GET /api/v1/agents", s.listAgents)
	h("POST /api/v1/agents/enrollment-tokens", s.createEnrollmentToken)
	h("POST /api/v1/agents/{id}/revoke", s.revokeAgent)
	h("GET /api/v1/agents/{id}/inventory", s.getAgentInventory)
	h("POST /api/v1/agents/{id}/inventory", s.agentInventory)
	h("GET /api/v1/issuers", s.listIssuers)
	h("POST /api/v1/issuers", s.createIssuer)
	h("PUT /api/v1/issuers/{id}/eab", s.setIssuerEAB)
	h("GET /api/v1/issuers/{id}/eab-keys", s.listEABKeys)
	h("POST /api/v1/issuers/{id}/eab-keys", s.addEABKey)
	h("DELETE /api/v1/issuers/{id}/eab-keys/{key}", s.deleteEABKey)
	h("GET /api/v1/dns-solvers", s.listDNSSolvers)
	h("POST /api/v1/dns-solvers", s.createDNSSolver)
	h("GET /api/v1/dns-solvers/{id}", s.getDNSSolver)
	h("DELETE /api/v1/dns-solvers/{id}", s.deleteDNSSolver)
	h("PUT /api/v1/dns-solvers/{id}/secret", s.setDNSSolverSecret)
	h("PUT /api/v1/dns-solvers/{id}/agents/{agent}", s.assignDNSSolver)
	h("DELETE /api/v1/dns-solvers/{id}/agents/{agent}", s.assignDNSSolver)
	h("GET /api/v1/deployments", s.listDeployments)
	h("POST /api/v1/deployments", s.createDeployment)
	h("POST /api/v1/deployments/{id}/renew", s.renewDeployment)
	h("PUT /api/v1/deployments/{id}/window", s.setDeploymentWindow)
	h("POST /api/v1/deployments/{id}/request-approval", s.requestDeploymentApproval)
	h("POST /api/v1/deployments/{id}/revoke-approval", s.revokeDeploymentApproval)
	h("GET /api/v1/exceptions", s.listExceptions)
	h("POST /api/v1/exceptions", s.requestException)
	h("GET /api/v1/exceptions/{id}", s.getException)
	h("POST /api/v1/exceptions/{id}/revoke", s.revokeException)
	h("GET /api/v1/approvals", s.listApprovals)
	h("GET /api/v1/approvals/{id}", s.getApproval)
	h("POST /api/v1/approvals/{id}/approve", s.decideApproval(true))
	h("POST /api/v1/approvals/{id}/deny", s.decideApproval(false))
	h("GET /api/v1/runs", s.listRuns)
	h("GET /api/v1/runs/{id}", s.getRun)
	h("POST /api/v1/runs/{id}/cancel", s.cancelRun)
	h("GET /api/v1/policy", s.getPolicy)
	h("PUT /api/v1/policy", s.putPolicy)
	h("GET /api/v1/webhooks", s.listWebhooks)
	h("POST /api/v1/webhooks", s.createWebhook)
	h("GET /api/v1/webhooks/{id}", s.getWebhook)
	h("DELETE /api/v1/webhooks/{id}", s.deleteWebhook)
	h("POST /api/v1/webhooks/{id}/enable", s.setWebhookEnabled(true))
	h("POST /api/v1/webhooks/{id}/disable", s.setWebhookEnabled(false))
	h("POST /api/v1/webhooks/{id}/rotate-secret", s.rotateWebhookSecret)
	h("GET /api/v1/webhooks/{id}/deliveries", s.listWebhookDeliveries)
	h("POST /api/v1/webhooks/{id}/deliveries/{delivery}/redeliver", s.redeliverWebhook)
	h("GET /api/v1/templates", s.listTemplates)
	h("PUT /api/v1/templates", s.putTemplate)
	h("GET /api/v1/templates/{id}", s.getTemplate)
	h("DELETE /api/v1/templates/{id}", s.deleteTemplate)
	h("POST /api/v1/automation/pause", s.pause(true))
	h("POST /api/v1/automation/resume", s.pause(false))
	return RequestIDs(mux)
}

// RequestIDs assigns each request an id (echoed in X-Request-Id and audit).
func RequestIDs(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 || strings.ContainsAny(id, "\r\n ") {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = "req_" + hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(app.WithRequestID(r.Context(), id)))
	})
}

type handlerFunc = func(w http.ResponseWriter, r *http.Request) error

// Routes returns every registered route pattern ("METHOD /path"), for the
// OpenAPI parity test. Valid after Handler has been called.
func (s *Server) Routes() []string { return append([]string(nil), s.routes...) }

func (s *Server) authed(fn handlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ipKey := "ip:" + clientIP(r)
		tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || tok == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="certloom"`)
			problem(w, r, 401, "unauthenticated", "missing bearer token", "Pass an API token: Authorization: Bearer <token>.")
			return
		}
		p, err := s.Svc.Authenticate(r.Context(), tok)
		if err != nil {
			if !errors.Is(err, store.ErrInvalidToken) {
				s.Log.Error("authenticate", "error", err)
			}
			// Throttle guessing: failed authentications consume a per-IP budget.
			if ok, _, retry := s.IPFailLimit.Allow(ipKey); !ok {
				tooMany(w, r, retry, "too many failed authentication attempts from this address")
				return
			}
			w.Header().Set("WWW-Authenticate", `Bearer realm="certloom", error="invalid_token"`)
			problem(w, r, 401, "unauthenticated", "invalid, expired or revoked token", "")
			return
		}
		allowed, remaining, retry := s.UserLimit.Allow(p.OrgID + "|" + p.Actor)
		w.Header().Set("RateLimit-Limit", strconv.Itoa(s.UserLimit.Burst))
		w.Header().Set("RateLimit-Remaining", strconv.Itoa(remaining))
		if !allowed {
			tooMany(w, r, retry, "rate limit exceeded for this principal")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, MaxBody)
		if err := fn(w, r.WithContext(WithPrincipal(r.Context(), p))); err != nil {
			s.writeError(w, r, err)
		}
	})
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var mbe *http.MaxBytesError
	switch {
	case errors.Is(err, authz.ErrForbidden):
		problem(w, r, 403, "forbidden", err.Error(), "Use a token with a role that grants this permission.")
	case errors.Is(err, store.ErrNotFound):
		problem(w, r, 404, "not-found", "resource not found", "")
	case errors.Is(err, store.ErrConflict):
		problem(w, r, 409, "conflict", "a resource with that name already exists", "")
	case errors.Is(err, store.ErrPrecondition):
		problem(w, r, 412, "precondition-failed", err.Error(), "GET the resource again for its current ETag, then retry with If-Match.")
	case errors.Is(err, store.ErrIdempotencyInProgress):
		problem(w, r, 409, "idempotency-in-progress", err.Error(), "Wait for the first request to finish, then retry.")
	case errors.Is(err, store.ErrIdempotencyMismatch):
		problem(w, r, 422, "idempotency-key-reused", err.Error(), "Use a new Idempotency-Key for a different request.")
	case errors.Is(err, app.ErrInvalid), errors.Is(err, errBadRequest):
		problem(w, r, 400, "invalid", err.Error(), "")
	case errors.As(err, &mbe):
		problem(w, r, 413, "too-large", "request body too large", "")
	default:
		s.Log.Error("request failed", "path", r.URL.Path, "request_id", w.Header().Get("X-Request-Id"), "error", err)
		problem(w, r, 500, "internal", "internal error", "Retry; if it persists, check server logs for the request id.")
	}
}

var errBadRequest = errors.New("bad request")

// Problem is an RFC 9457 problem document.
type Problem struct {
	Type        string `json:"type"`
	Title       string `json:"title"`
	Status      int    `json:"status"`
	Detail      string `json:"detail,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
}

func problem(w http.ResponseWriter, r *http.Request, status int, typ, detail, remediation string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{Type: "https://certloom.invalid/problems/" + typ, Title: http.StatusText(status), Status: status,
		Detail: detail, Remediation: remediation, RequestID: w.Header().Get("X-Request-Id")})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func decode(r *http.Request, v any) error {
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		return errors.Join(errBadRequest, err)
	}
	return nil
}

type list[T any] struct {
	Items      []T    `json:"items"`
	NextCursor string `json:"next_cursor,omitempty"`
}

func items[T any](v []T) list[T] {
	if v == nil {
		v = []T{}
	}
	return list[T]{Items: v}
}

// ---- handlers ----

func (s *Server) whoami(w http.ResponseWriter, r *http.Request) error {
	p := PrincipalFrom(r.Context())
	writeJSON(w, 200, map[string]any{"org_id": p.OrgID, "actor": p.Actor, "role": p.Role, "permissions": authz.Grants(p.Role)})
	return nil
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request) error {
	m, err := s.Svc.Overview(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(m))
	return nil
}

// ParseHorizon parses "30d", "12h", "0d".
func ParseHorizon(s string) (time.Duration, error) {
	if n, ok := strings.CutSuffix(s, "d"); ok {
		d, err := strconv.Atoi(n)
		if err != nil || d < 0 {
			return 0, errors.Join(errBadRequest, errors.New("invalid horizon"))
		}
		return time.Duration(d) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < 0 {
		return 0, errors.Join(errBadRequest, errors.New("invalid horizon"))
	}
	return d, nil
}

func encodeCursor(t time.Time, sha string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(t.UTC().Format(time.RFC3339Nano) + "|" + sha))
}

func decodeCursor(c string) (time.Time, string, error) {
	b, err := base64.RawURLEncoding.DecodeString(c)
	if err != nil {
		return time.Time{}, "", errors.Join(errBadRequest, errors.New("invalid cursor"))
	}
	ts, sha, ok := strings.Cut(string(b), "|")
	t, err := time.Parse(time.RFC3339Nano, ts)
	if !ok || err != nil {
		return time.Time{}, "", errors.Join(errBadRequest, errors.New("invalid cursor"))
	}
	return t, sha, nil
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	f := store.CertFilter{Search: q.Get("search"), IncludeCA: q.Get("include_ca") == "true"}
	if v := q.Get("limit"); v != "" {
		f.Limit, _ = strconv.Atoi(v)
	}
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 100
	}
	if v := q.Get("expiring"); v != "" {
		d, err := ParseHorizon(v)
		if err != nil {
			return err
		}
		f.ExpiresBefore = time.Now().Add(d)
		if d == 0 {
			f.ExpiresBefore = time.Now() // "0d" = already expired
		}
	}
	if c := q.Get("cursor"); c != "" {
		t, sha, err := decodeCursor(c)
		if err != nil {
			return err
		}
		f.AfterNotAfter, f.AfterSHA256 = t, sha
	}
	certs, err := s.Svc.ListCertificates(r.Context(), PrincipalFrom(r.Context()), f)
	if err != nil {
		return err
	}
	out := items(certs)
	if len(certs) == f.Limit {
		last := certs[len(certs)-1]
		out.NextCursor = encodeCursor(last.NotAfter, last.SHA256)
	}
	writeJSON(w, 200, out)
	return nil
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) error {
	d, err := s.Svc.GetCertificate(r.Context(), PrincipalFrom(r.Context()), r.PathValue("fp"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, d)
	return nil
}

// ImportRequest is the body of POST /certificates/import.
type ImportRequest struct {
	// Data is the certificate file (PEM, DER or PKCS#12), base64-encoded.
	Data     string `json:"data"`
	Password string `json:"password,omitempty"` // PKCS#12 only; never logged or stored
	Lineage  string `json:"lineage,omitempty"`
	Team     string `json:"team,omitempty"`
}

func (s *Server) importCertificates(w http.ResponseWriter, r *http.Request) error {
	var req ImportRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		return errors.Join(errBadRequest, errors.New("data must be base64"))
	}
	pass := secret.FromString(req.Password)
	req.Password = ""
	res, err := s.Svc.Import(r.Context(), PrincipalFrom(r.Context()), data, app.ImportOptions{
		Password: pass, Lineage: req.Lineage, Team: req.Team, DryRun: r.URL.Query().Get("dry_run") == "true"})
	if err != nil {
		return err
	}
	writeJSON(w, 200, res)
	return nil
}

func (s *Server) listScopes(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListScopes(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) createScope(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name   string            `json:"name"`
		Config store.ScopeConfig `json:"config"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.CreateScope(r.Context(), PrincipalFrom(r.Context()), req.Name, req.Config)
	if err != nil {
		return err
	}
	writeJSON(w, 201, v)
	return nil
}

func (s *Server) listEndpoints(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListEndpoints(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

// CreateEndpointRequest is the body of POST /endpoints.
type CreateEndpointRequest struct {
	Host            string `json:"host"`
	Port            int    `json:"port,omitempty"`
	SNI             string `json:"sni,omitempty"`
	Scope           string `json:"scope"`
	Lineage         string `json:"lineage,omitempty"`
	Team            string `json:"team,omitempty"`
	IntervalSeconds int    `json:"interval_seconds,omitempty"`
}

func (s *Server) createEndpoint(w http.ResponseWriter, r *http.Request) error {
	var req CreateEndpointRequest
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.AddEndpoint(r.Context(), PrincipalFrom(r.Context()), app.AddEndpointInput{Host: req.Host, Port: req.Port,
		SNI: req.SNI, Scope: req.Scope, Lineage: req.Lineage, Team: req.Team, Interval: time.Duration(req.IntervalSeconds) * time.Second})
	if err != nil {
		return err
	}
	writeJSON(w, 201, v)
	return nil
}

func (s *Server) getEndpoint(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetEndpoint(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set("ETag", etag(v.Version))
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) getLineage(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetLineage(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	w.Header().Set("ETag", etag(v.Version))
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) probeEndpoint(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.RequestProbe(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	writeJSON(w, 202, map[string]string{"status": "scheduled"})
	return nil
}

func (s *Server) bindEndpointLineage(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Lineage string `json:"lineage"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	ver, err := ifMatch(r)
	if err != nil {
		return err
	}
	if err := s.Svc.BindEndpointLineage(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), req.Lineage, ver); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) listFindings(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	v, err := s.Svc.ListFindings(r.Context(), PrincipalFrom(r.Context()), store.FindingFilter{
		SubjectType: q.Get("subject_type"), SubjectID: q.Get("subject_id"), MinSeverity: q.Get("severity"),
		IncludeResolved: q.Get("include_resolved") == "true"})
	if err != nil {
		return err
	}
	if c := q.Get("check"); c != "" {
		filtered := v[:0]
		for _, f := range v {
			if f.Check == c {
				filtered = append(filtered, f)
			}
		}
		v = filtered
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) listTeams(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListTeams(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) createTeam(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name    string `json:"name"`
		Contact string `json:"contact,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.CreateTeam(r.Context(), PrincipalFrom(r.Context()), req.Name, req.Contact)
	if err != nil {
		return err
	}
	writeJSON(w, 201, v)
	return nil
}

func (s *Server) listLineages(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListLineages(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) createLineage(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name    string `json:"name"`
		Team    string `json:"team,omitempty"`
		Current string `json:"current_sha256,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	v, err := s.Svc.CreateLineage(r.Context(), PrincipalFrom(r.Context()), req.Name, req.Team, req.Current)
	if err != nil {
		return err
	}
	writeJSON(w, 201, v)
	return nil
}

func (s *Server) assignOwner(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Team string `json:"team"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	ver, err := ifMatch(r)
	if err != nil {
		return err
	}
	if err := s.Svc.AssignOwner(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), req.Team, ver); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) error {
	var states []string
	if st := r.URL.Query().Get("state"); st != "" {
		states = strings.Split(st, ",")
	}
	v, err := s.Svc.ListAlerts(r.Context(), PrincipalFrom(r.Context()), states)
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) ackAlert(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.AckAlert(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) listChannels(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListChannels(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) createChannel(w http.ResponseWriter, r *http.Request) error {
	var c store.Channel
	if err := decode(r, &c); err != nil {
		return err
	}
	if err := s.Svc.CreateChannel(r.Context(), PrincipalFrom(r.Context()), &c); err != nil {
		return err
	}
	writeJSON(w, 201, c)
	return nil
}

func (s *Server) testChannel(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.TestChannel(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	writeJSON(w, 202, map[string]string{"status": "queued"})
	return nil
}

func (s *Server) listTokens(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListTokens(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) createToken(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name       string `json:"name"`
		Role       string `json:"role"`
		TTLSeconds int    `json:"ttl_seconds,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	t, v, err := s.Svc.CreateToken(r.Context(), PrincipalFrom(r.Context()), req.Name, req.Role, time.Duration(req.TTLSeconds)*time.Second)
	if err != nil {
		return err
	}
	// The only time the plaintext token leaves the server.
	writeJSON(w, 201, map[string]any{"token": t, "secret": v.RevealString(),
		"note": "Store this secret now; it cannot be retrieved again."})
	return nil
}

func (s *Server) revokeToken(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.RevokeToken(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) auditQuery(w http.ResponseWriter, r *http.Request) error {
	after, _ := strconv.ParseInt(r.URL.Query().Get("after_seq"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	v, err := s.Svc.AuditQuery(r.Context(), PrincipalFrom(r.Context()), after, limit)
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) auditVerify(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.AuditVerify(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) pause(paused bool) func(w http.ResponseWriter, r *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req struct {
			Reason string `json:"reason,omitempty"`
		}
		if r.ContentLength != 0 {
			if err := decode(r, &req); err != nil {
				return err
			}
		}
		if err := s.Svc.SetPaused(r.Context(), PrincipalFrom(r.Context()), paused, req.Reason); err != nil {
			return err
		}
		writeJSON(w, 200, map[string]bool{"paused": paused})
		return nil
	}
}

func (s *Server) auditExportStatus(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.AuditExportStatus(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

// oidcSession exchanges a device-flow ID token for a certloom session (CLI sign-in).
func (s *Server) oidcSession(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	var req struct {
		IDToken string `json:"id_token"`
		Org     string `json:"org,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		problem(w, r, 400, "invalid", err.Error(), "")
		return
	}
	tok, m, err := s.Svc.ExchangeCLIToken(r.Context(), req.IDToken, req.Org)
	if err != nil {
		var choose *app.ErrChooseOrg
		switch {
		case errors.As(err, &choose):
			problem(w, r, 409, "choose-org", err.Error(), "Pass --org NAME.")
		case errors.Is(err, app.ErrNoMembership):
			problem(w, r, 403, "not-a-member", err.Error(), "Ask an owner to run `certloom member add EMAIL --role ROLE`.")
		case errors.Is(err, store.ErrInvalidToken):
			problem(w, r, 401, "unauthenticated", "ID token rejected", "")
		case errors.Is(err, app.ErrInvalid):
			problem(w, r, 400, "invalid", err.Error(), "")
		default:
			s.Log.Error("oidc session exchange", "error", err)
			problem(w, r, 500, "internal", "internal error", "")
		}
		return
	}
	writeJSON(w, 201, map[string]any{"token": tok.RevealString(), "email": m.Email, "role": m.Role, "org_id": m.OrgID})
}

func (s *Server) signOut(w http.ResponseWriter, r *http.Request) error {
	tok, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if err := s.Svc.SignOut(r.Context(), tok); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) listMembers(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListMembers(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) createMember(w http.ResponseWriter, r *http.Request) error {
	var req struct{ Email, Role string }
	if err := decode(r, &req); err != nil {
		return err
	}
	m, err := s.Svc.CreateMember(r.Context(), PrincipalFrom(r.Context()), req.Email, req.Role)
	if err != nil {
		return err
	}
	writeJSON(w, 201, m)
	return nil
}

func (s *Server) deleteMember(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.DeleteMember(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) getPolicy(w http.ResponseWriter, r *http.Request) error {
	pv, err := s.Svc.GetPolicy(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	if strings.Contains(r.Header.Get("Accept"), "yaml") {
		y, err := pv.Document.YAML()
		if err != nil {
			return err
		}
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write(y)
		return nil
	}
	writeJSON(w, 200, pv)
	return nil
}

// putPolicy validates a YAML/JSON policy, reports its impact, and applies it
// unless ?dry_run=true.
func (s *Server) putPolicy(w http.ResponseWriter, r *http.Request) error {
	src, err := io.ReadAll(io.LimitReader(r.Body, 64<<10+1))
	if err != nil {
		return err
	}
	plan, err := s.Svc.ApplyPolicy(r.Context(), PrincipalFrom(r.Context()), src, r.URL.Query().Get("dry_run") == "true")
	if err != nil {
		return err
	}
	writeJSON(w, 200, plan)
	return nil
}

// ---- agents, issuers, deployments, renewal runs ----

type agentView struct {
	*store.Agent
	Health string `json:"health"`
}

func (s *Server) listAgents(w http.ResponseWriter, r *http.Request) error {
	as, err := s.Svc.ListAgents(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	out := make([]agentView, 0, len(as))
	for _, a := range as {
		out = append(out, agentView{a, a.Health(time.Now())})
	}
	writeJSON(w, 200, items(out))
	return nil
}

func (s *Server) createEnrollmentToken(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name       string `json:"name,omitempty"`
		TTLSeconds int    `json:"ttl_seconds,omitempty"`
	}
	if r.ContentLength != 0 {
		if err := decode(r, &req); err != nil {
			return err
		}
	}
	t, err := s.Svc.CreateEnrollmentToken(r.Context(), PrincipalFrom(r.Context()), req.Name,
		time.Duration(req.TTLSeconds)*time.Second, s.Svc.AgentServerURL)
	if err != nil {
		if errors.Is(err, app.ErrAgentsDisabled) {
			return errors.Join(errBadRequest, err)
		}
		return err
	}
	writeJSON(w, 201, t)
	return nil
}

func (s *Server) revokeAgent(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.RevokeAgent(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

func (s *Server) getAgentInventory(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.AgentInventory(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) agentInventory(w http.ResponseWriter, r *http.Request) error {
	id, err := s.Svc.RequestInventoryScan(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 202, map[string]string{"task_id": id})
	return nil
}

func (s *Server) listIssuers(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListIssuers(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) createIssuer(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Name         string `json:"name"`
		DirectoryURL string `json:"directory_url"`
		Email        string `json:"email,omitempty"`
		AgreeTOS     bool   `json:"agree_tos"`
		Profile      string `json:"profile,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	i := &store.Issuer{Name: req.Name, DirectoryURL: req.DirectoryURL, Email: req.Email, AgreeTOS: req.AgreeTOS, Profile: req.Profile}
	if err := s.Svc.CreateIssuer(r.Context(), PrincipalFrom(r.Context()), i); err != nil {
		return err
	}
	writeJSON(w, 201, i)
	return nil
}

func (s *Server) listDeployments(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListDeployments(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) createDeployment(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Lineage   string   `json:"lineage"`
		Agent     string   `json:"agent"`
		Target    string   `json:"target"`
		Issuer    string   `json:"issuer"`
		Endpoint  string   `json:"endpoint,omitempty"`
		SANs      []string `json:"sans"`
		Window    string   `json:"maintenance_window,omitempty"`
		Emergency string   `json:"window_emergency,omitempty"`
		Challenge string   `json:"challenge,omitempty"`
		Template  string   `json:"template,omitempty"`
		KeyAlg    string   `json:"key_algorithm,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	d, err := s.Svc.CreateDeployment(r.Context(), PrincipalFrom(r.Context()), app.DeploymentInput{Lineage: req.Lineage, Agent: req.Agent,
		Target: req.Target, Issuer: req.Issuer, Endpoint: req.Endpoint, SANs: req.SANs,
		Window: req.Window, Emergency: req.Emergency, Challenge: req.Challenge, Template: req.Template, KeyAlgorithm: req.KeyAlg})
	if err != nil {
		return err
	}
	writeJSON(w, 201, d)
	return nil
}

func (s *Server) setDeploymentWindow(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Window    string `json:"maintenance_window"`
		Emergency string `json:"window_emergency,omitempty"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	d, err := s.Svc.SetDeploymentWindow(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), req.Window, req.Emergency)
	if err != nil {
		return err
	}
	writeJSON(w, 200, d)
	return nil
}

func (s *Server) renewDeployment(w http.ResponseWriter, r *http.Request) error {
	run, err := s.Svc.RequestRenewal(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 202, run)
	return nil
}

func (s *Server) listRuns(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListRuns(r.Context(), PrincipalFrom(r.Context()))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) getRun(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.GetRun(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, v)
	return nil
}

func (s *Server) cancelRun(w http.ResponseWriter, r *http.Request) error {
	if err := s.Svc.CancelRun(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id")); err != nil {
		return err
	}
	w.WriteHeader(204)
	return nil
}

// ---- approvals ----

func (s *Server) requestDeploymentApproval(w http.ResponseWriter, r *http.Request) error {
	a, err := s.Svc.RequestDeploymentApproval(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 201, a)
	return nil
}

func (s *Server) listApprovals(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListApprovals(r.Context(), PrincipalFrom(r.Context()), r.URL.Query().Get("state"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) getApproval(w http.ResponseWriter, r *http.Request) error {
	a, err := s.Svc.GetApproval(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, a)
	return nil
}

func (s *Server) decideApproval(approve bool) func(http.ResponseWriter, *http.Request) error {
	return func(w http.ResponseWriter, r *http.Request) error {
		var req struct {
			Reason string `json:"reason,omitempty"`
		}
		if r.ContentLength != 0 {
			if err := decode(r, &req); err != nil {
				return err
			}
		}
		a, err := s.Svc.DecideApproval(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), approve, req.Reason)
		if err != nil {
			return err
		}
		writeJSON(w, 200, a)
		return nil
	}
}

func (s *Server) revokeDeploymentApproval(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	d, err := s.Svc.RevokeDeploymentApproval(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), req.Reason)
	if err != nil {
		return err
	}
	writeJSON(w, 200, d)
	return nil
}

// ---- policy exceptions ----

func (s *Server) requestException(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		SubjectType          string    `json:"subject_type"`
		SubjectID            string    `json:"subject_id"`
		Check                string    `json:"check"`
		Rationale            string    `json:"rationale"`
		CompensatingControls string    `json:"compensating_controls,omitempty"`
		RiskOwner            string    `json:"risk_owner"`
		RemediationOwner     string    `json:"remediation_owner,omitempty"`
		RemediationDue       string    `json:"remediation_due,omitempty"`
		TrackingRef          string    `json:"tracking_ref,omitempty"`
		ExpiresAt            time.Time `json:"expires_at"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	var due *time.Time
	if req.RemediationDue != "" {
		d, err := time.Parse(time.DateOnly, req.RemediationDue)
		if err != nil {
			return errors.Join(errBadRequest, errors.New("remediation_due must be a date like 2027-01-31"))
		}
		due = &d
	}
	e, a, err := s.Svc.RequestException(r.Context(), PrincipalFrom(r.Context()), app.ExceptionInput{SubjectType: req.SubjectType,
		SubjectID: req.SubjectID, Check: req.Check, Rationale: req.Rationale, CompensatingControls: req.CompensatingControls,
		RiskOwner: req.RiskOwner, RemediationOwner: req.RemediationOwner, RemediationDue: due, TrackingRef: req.TrackingRef,
		ExpiresAt: req.ExpiresAt})
	if err != nil {
		return err
	}
	writeJSON(w, 201, map[string]any{"exception": e, "approval": a})
	return nil
}

func (s *Server) listExceptions(w http.ResponseWriter, r *http.Request) error {
	v, err := s.Svc.ListExceptions(r.Context(), PrincipalFrom(r.Context()), r.URL.Query().Get("state"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, items(v))
	return nil
}

func (s *Server) getException(w http.ResponseWriter, r *http.Request) error {
	e, err := s.Svc.GetException(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"))
	if err != nil {
		return err
	}
	writeJSON(w, 200, e)
	return nil
}

func (s *Server) revokeException(w http.ResponseWriter, r *http.Request) error {
	var req struct {
		Reason string `json:"reason"`
	}
	if err := decode(r, &req); err != nil {
		return err
	}
	e, err := s.Svc.RevokeException(r.Context(), PrincipalFrom(r.Context()), r.PathValue("id"), req.Reason)
	if err != nil {
		return err
	}
	writeJSON(w, 200, e)
	return nil
}
