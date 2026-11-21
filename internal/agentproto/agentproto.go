// Package agentproto defines the control-plane <-> agent protocol:
// HTTPS + JSON over mutual TLS, with every task signed by the control plane's
// Ed25519 task key and bound to one agent, an expiry, a nonce and, for
// mutating tasks, a per-target sequence number.
package agentproto

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// Paths served on the agent listener.
const (
	PathEnroll    = "/agent/v1/enroll"
	PathRenew     = "/agent/v1/renew"
	PathHeartbeat = "/agent/v1/heartbeat"
	PathTasks     = "/agent/v1/tasks"
	PathResult    = "/agent/v1/tasks/{id}/result"
)

// Task types. The agent executes only types allowed by its local config.
const (
	TaskInventoryScan = "inventory.scan"
	TaskIssue         = "acme.issue"
	TaskDeploy        = "deploy.activate"
	TaskVerify        = "verify.local"
	TaskRollback      = "deploy.rollback"
)

// AllTaskTypes lists every known task type.
var AllTaskTypes = []string{TaskInventoryScan, TaskIssue, TaskDeploy, TaskVerify, TaskRollback}

// AgentURI is the URI SAN identifying an agent in its client certificate.
func AgentURI(orgID, agentID string) *url.URL {
	return &url.URL{Scheme: "certloom", Opaque: "agent:" + orgID + ":" + agentID}
}

// ParseAgentURI extracts org and agent ids from a certificate URI SAN.
func ParseAgentURI(u *url.URL) (org, agent string, ok bool) {
	if u == nil || u.Scheme != "certloom" {
		return "", "", false
	}
	rest, ok := strings.CutPrefix(u.Opaque, "agent:")
	if !ok {
		return "", "", false
	}
	org, agent, ok = strings.Cut(rest, ":")
	return org, agent, ok && org != "" && agent != ""
}

// EnrollRequest is sent once with a one-time token (no client certificate yet).
type EnrollRequest struct {
	Token    string `json:"token"`
	CSRPEM   string `json:"csr_pem"`
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
}

// EnrollResponse returns the agent identity and the trust material to pin.
type EnrollResponse struct {
	AgentID       string `json:"agent_id"`
	OrgID         string `json:"org_id"`
	CertPEM       string `json:"cert_pem"`
	CAPEM         string `json:"ca_pem"`
	TaskPublicKey []byte `json:"task_public_key"` // Ed25519
}

// RenewRequest rotates the agent certificate (over mTLS).
type RenewRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// Target is a deployment target configured locally on the agent.
type Target struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"` // nginx
	AllowedSANs []string `json:"allowed_sans"`
	ACME        bool     `json:"acme"` // has an HTTP-01 webroot
}

// Heartbeat reports liveness and capabilities.
type Heartbeat struct {
	Version  string   `json:"version"`
	Hostname string   `json:"hostname"`
	Targets  []Target `json:"targets"`
	Tasks    []string `json:"tasks"` // allowed task types
}

// Task is the signed unit of work.
type Task struct {
	ID       string          `json:"id"`
	OrgID    string          `json:"org_id"`
	AgentID  string          `json:"agent_id"`
	Type     string          `json:"type"`
	NotAfter time.Time       `json:"not_after"`
	Nonce    string          `json:"nonce"`
	Target   string          `json:"target,omitempty"`
	Seq      int64           `json:"seq,omitempty"` // per-target fence for mutating tasks
	Payload  json.RawMessage `json:"payload"`
}

// Envelope carries the exact signed bytes so verification is byte-exact.
type Envelope struct {
	Task      []byte `json:"task"`      // JSON of Task
	Signature []byte `json:"signature"` // Ed25519 over Task bytes
}

// Sign builds an envelope.
func Sign(key ed25519.PrivateKey, t Task) (Envelope, error) {
	b, err := json.Marshal(t)
	if err != nil {
		return Envelope{}, err
	}
	return Envelope{Task: b, Signature: ed25519.Sign(key, b)}, nil
}

// Verification errors.
var (
	ErrBadSignature  = errors.New("task signature invalid")
	ErrWrongAgent    = errors.New("task is addressed to another agent")
	ErrExpired       = errors.New("task has expired")
	ErrNotAllowed    = errors.New("task type not allowed by local agent configuration")
	ErrStaleSequence = errors.New("task sequence is older than one already executed for this target")
)

// Open verifies an envelope's signature, addressee and expiry.
func Open(pub ed25519.PublicKey, env Envelope, orgID, agentID string, now time.Time) (*Task, error) {
	if !ed25519.Verify(pub, env.Task, env.Signature) {
		return nil, ErrBadSignature
	}
	var t Task
	if err := json.Unmarshal(env.Task, &t); err != nil {
		return nil, fmt.Errorf("decode task: %w", err)
	}
	if t.AgentID != agentID || t.OrgID != orgID {
		return nil, ErrWrongAgent
	}
	if !now.Before(t.NotAfter) {
		return nil, ErrExpired
	}
	if t.Nonce == "" || t.ID == "" {
		return nil, errors.New("task lacks id or nonce")
	}
	return &t, nil
}

// TaskList is the long-poll response.
type TaskList struct {
	Tasks []Envelope `json:"tasks"`
}

// Result is posted by the agent for a task (idempotent by task id).
type Result struct {
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Output json.RawMessage `json:"output,omitempty"`
}

// ---- payloads ----

// IssuePayload asks the agent to generate a key, build a CSR and obtain a
// certificate via ACME HTTP-01. The private key never leaves the agent.
type IssuePayload struct {
	RunID          string   `json:"run_id"`
	DirectoryURL   string   `json:"directory_url"`
	Email          string   `json:"email,omitempty"`
	AgreeTOS       bool     `json:"agree_tos"`
	Profile        string   `json:"profile,omitempty"`
	ReplacesCertID string   `json:"replaces_cert_id,omitempty"`
	SANs           []string `json:"sans"`
}

// IssueOutput returns the public certificate chain (PEM, leaf first). On a
// failed issuance it carries what the CA said about when to try again.
type IssueOutput struct {
	ChainPEM string `json:"chain_pem,omitempty"`
	// ProblemType is the ACME error type (urn:ietf:params:acme:error:...).
	ProblemType string `json:"problem_type,omitempty"`
	// RetryAfterSeconds is the CA's Retry-After for a rate-limited request.
	RetryAfterSeconds int64 `json:"retry_after_seconds,omitempty"`
}

// DeployPayload activates the certificate issued in RunID on the target.
type DeployPayload struct {
	RunID    string `json:"run_id"`
	ChainPEM string `json:"chain_pem"`
}

// DeployOutput describes the switch. RolledBack is set when activation failed
// and the agent restored the previous certificate itself.
type DeployOutput struct {
	Previous   string `json:"previous,omitempty"` // previous run id ("" if none)
	RolledBack bool   `json:"rolled_back,omitempty"`
}

// VerifyPayload asks the agent to handshake locally and compare fingerprints.
type VerifyPayload struct {
	ExpectedSHA256 string `json:"expected_sha256"`
	SNI            string `json:"sni"`
}

// VerifyOutput reports what the local endpoint served.
type VerifyOutput struct {
	ServedSHA256 string `json:"served_sha256"`
	Match        bool   `json:"match"`
}

// RollbackPayload restores the certificate active before RunID.
type RollbackPayload struct {
	RunID string `json:"run_id"`
}

// InventoryOutput lists certificates found on the host (public data only).
type InventoryOutput struct {
	Certificates []FoundCert      `json:"certificates"`
	Certbot      []CertbotLineage `json:"certbot,omitempty"`
}

// FoundCert is a certificate file found on disk.
type FoundCert struct {
	Path     string `json:"path"`
	ChainPEM string `json:"chain_pem"`
}

// CertbotLineage is read-only metadata about a Certbot-managed lineage.
type CertbotLineage struct {
	Name          string `json:"name"`
	CertPath      string `json:"cert_path"`
	Authenticator string `json:"authenticator,omitempty"`
	Server        string `json:"server,omitempty"`
	Version       string `json:"version,omitempty"` // certbot version that last wrote the renewal conf
	ARIAware      bool   `json:"ari_aware"`         // version >= 4.1.0
}
