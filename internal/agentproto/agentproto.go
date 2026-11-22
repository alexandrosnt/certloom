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
	"slices"
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
	// TaskCSR makes the run's key and returns a CSR for the control plane to
	// have signed by a Vault or step-ca issuer (ADR-0028).
	TaskCSR = "csr.create"
	// TaskTrustApply writes a trust bundle version to a trust store (ADR-0030).
	TaskTrustApply = "trust.apply"
)

// AllTaskTypes lists every known task type.
var AllTaskTypes = []string{TaskInventoryScan, TaskIssue, TaskDeploy, TaskVerify, TaskRollback, TaskCSR, TaskTrustApply}

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
	Type        string   `json:"type"` // nginx, iis or plugin
	AllowedSANs []string `json:"allowed_sans"`
	ACME        bool     `json:"acme"` // has an HTTP-01 webroot
	// Site and Bindings identify an IIS target (ADR-0022); both are part of
	// the approved deployment spec.
	Site     string   `json:"site,omitempty"`
	Bindings []string `json:"bindings,omitempty"`
	// Plugin names the deploy_target plugin of a plugin target (ADR-0027),
	// without a version; it is part of the approved deployment spec.
	Plugin string `json:"plugin,omitempty"`
}

// Target types.
const (
	TargetNginx  = "nginx"
	TargetIIS    = "iis"
	TargetPlugin = "plugin"
)

// DNSSolver describes one DNS-01 solver configured on an agent host.
type DNSSolver struct {
	Name     string   `json:"name"`
	Provider string   `json:"provider"` // rfc2136, cloudflare or plugin:<name>
	Zones    []string `json:"zones"`
}

// CentralDNSSolver is a DNS-01 solver defined in the control plane. Its
// secret, if any, is sealed to the receiving agent for this task only
// (SealSecret with SealInfo(agent, task, ID)); it is a JSON object of strings:
// rfc2136 {"tsig_key": "<BIND key file>"}, cloudflare {"api_token": "..."},
// plugins any keys they document.
type CentralDNSSolver struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Provider string         `json:"provider"` // rfc2136, cloudflare or plugin
	Plugin   string         `json:"plugin,omitempty"`
	SHA256   string         `json:"sha256,omitempty"`
	Zones    []string       `json:"zones"`
	Config   map[string]any `json:"config,omitempty"`
	// Ambient: no secret; a plugin uses the host's cloud identity.
	Ambient bool   `json:"ambient,omitempty"`
	Sealed  []byte `json:"sealed,omitempty"`
}

// Heartbeat reports liveness and capabilities.
type Heartbeat struct {
	Version  string   `json:"version"`
	Hostname string   `json:"hostname"`
	Targets  []Target `json:"targets"`
	Tasks    []string `json:"tasks"` // allowed task types
	// DNSSolvers lists the host's DNS-01 solvers; credentials are never reported.
	DNSSolvers []DNSSolver `json:"dns_solvers,omitempty"`
	// SealKey is the agent's public HPKE key for secrets sent to it.
	SealKey []byte `json:"seal_key,omitempty"`
	// NoCentralDNS and NoCentralEAB are set when the host refuses central DNS
	// solvers or central EAB credentials (agent config).
	NoCentralDNS bool `json:"no_central_dns,omitempty"`
	NoCentralEAB bool `json:"no_central_eab,omitempty"`
	// ACMEAccounts lists the account slots this agent has registered.
	ACMEAccounts []string `json:"acme_accounts,omitempty"`
	// LocalEAB lists ACME directory URLs with EAB configured on the host.
	LocalEAB []string `json:"local_eab,omitempty"`
	// InventorySeconds asks the control plane for an inventory task at this
	// interval (in-cluster agents, IIS hosts for binding drift); 0 = on demand.
	InventorySeconds int `json:"inventory_seconds,omitempty"`
	// Plugins lists the plugins installed or pinned on the host (ADR-0027).
	Plugins []PluginInfo `json:"plugins,omitempty"`
	// TrustStores lists the trust stores declared in the agent config.
	TrustStores []TrustStoreInfo `json:"trust_stores,omitempty"`
}

// PluginInfo describes one plugin an agent may run.
type PluginInfo struct {
	Name    string   `json:"name"`
	Version string   `json:"version,omitempty"`
	Kinds   []string `json:"kinds"`
	// SHA256 is the digest of the executable.
	SHA256 string `json:"sha256"`
	// Trust and Signer are set for installed, signed plugins: the trust
	// entry that matched and the certificate identity or key fingerprint.
	Trust  string `json:"trust,omitempty"`
	Signer string `json:"signer,omitempty"`
	// Pinned is set for plugins configured by path and digest instead.
	Pinned bool `json:"pinned,omitempty"`
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
	// KeyAlgorithm is the key to generate; empty means KeyECDSAP256.
	KeyAlgorithm string `json:"key_algorithm,omitempty"`
	// Challenge is ChallengeHTTP01 or ChallengeDNS01; empty means HTTP-01.
	Challenge string `json:"challenge,omitempty"`
	// DNSSolvers are central solvers assigned to this agent (ADR-0018).
	DNSSolvers []CentralDNSSolver `json:"dns_solvers,omitempty"`
	// AccountSlot names the ACME account to use for issuers that need External
	// Account Binding (AccountSlot(issuer id)); empty uses the account kept
	// for the directory URL.
	AccountSlot string `json:"account_slot,omitempty"`
	// EAB is sent while the agent has not registered AccountSlot (ADR-0019).
	EAB *SealedEAB `json:"eab,omitempty"`
}

// CSRPayload asks for a CSR covering SANs, signed by a new key kept in the
// run directory for the deploy step.
type CSRPayload struct {
	RunID string   `json:"run_id"`
	SANs  []string `json:"sans"`
	// KeyAlgorithm is the key to generate; empty means KeyECDSAP256.
	KeyAlgorithm string `json:"key_algorithm,omitempty"`
}

// CSROutput carries the PEM CSR. The private key stays on the host.
type CSROutput struct {
	CSRPEM string `json:"csr_pem"`
}

// SealedEAB is an External Account Binding key: the key id in clear and the
// HMAC key (base64url, as issued by the CA) sealed with SealEABInfo.
type SealedEAB struct {
	KID    string `json:"kid"`
	Sealed []byte `json:"sealed"`
}

// KeyECDSAP256 is the only key algorithm agents generate so far.
const KeyECDSAP256 = "ecdsa-p256"

// IssueOutput returns the public certificate chain (PEM, leaf first). On a
// failed issuance it carries what the CA said about when to try again.
type IssueOutput struct {
	ChainPEM string `json:"chain_pem,omitempty"`
	// ProblemType is the ACME error type (urn:ietf:params:acme:error:...).
	ProblemType string `json:"problem_type,omitempty"`
	// RetryAfterSeconds is the CA's Retry-After for a rate-limited request.
	RetryAfterSeconds int64 `json:"retry_after_seconds,omitempty"`
	// AccountSlot is set once the agent holds a registered account for the
	// task's slot, so the control plane can mark a single-use EAB key used.
	AccountSlot string `json:"account_slot,omitempty"`
	// EABRejected means the CA refused account registration with EAB.
	EABRejected bool `json:"eab_rejected,omitempty"`
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
	// RunID identifies the deploy being verified; plugin targets pass it on
	// as the idempotency key. Older control planes leave it empty.
	RunID string `json:"run_id,omitempty"`
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
	// IIS and WinACME come from Windows agents, Kubernetes from in-cluster ones.
	IIS        []IISBinding     `json:"iis,omitempty"`
	WinACME    []WinACMERenewal `json:"win_acme,omitempty"`
	Kubernetes *KubeInventory   `json:"kubernetes,omitempty"`
	Cloud      *CloudInventory  `json:"cloud,omitempty"`
	// Plugins holds what discovery plugins and deploy_target plugins with
	// an inventory action reported.
	Plugins []PluginInventory `json:"plugins,omitempty"`
	// TrustStores holds what each declared trust store contains.
	TrustStores []TrustStoreState `json:"trust_stores,omitempty"`
}

// PluginInventory is the answer of one plugin inventory call. Source is the
// discovery or target name from the agent config. If Error is set, the
// call failed and Items is empty; findings from that source are kept.
type PluginInventory struct {
	Source string       `json:"source"`
	Kind   string       `json:"kind"`
	Plugin string       `json:"plugin"`
	Items  []PluginItem `json:"items,omitempty"`
	Error  string       `json:"error,omitempty"`
}

// PluginItem is one certificate a plugin found.
type PluginItem struct {
	PEM      string   `json:"pem"`
	Location string   `json:"location"`
	UsedBy   []string `json:"used_by,omitempty"`
}

// Cloud certificate services an agent can observe (ADR-0024). The value is
// also the inventory source of the certificates found there.
const (
	CloudAWSACM           = "aws_acm"
	CloudAWSPCA           = "aws_pca"
	CloudAzureKeyVault    = "azure_keyvault"
	CloudGCPCertManager   = "gcp_certmanager"
	CloudGCPCAS           = "gcp_cas"
	CloudCloudflareEdge   = "cloudflare_edge"
	CloudCloudflareOrigin = "cloudflare_origin_ca"
)

// CloudInventory is what an agent read from cloud certificate services.
// Scopes it could not list are named in Errors, so findings of objects in
// them are kept rather than resolved.
type CloudInventory struct {
	Objects []CloudObject     `json:"objects"`
	Errors  []CloudScopeError `json:"errors,omitempty"`
}

// CloudScopeError is one provider scope (account and region, vault,
// project and location, zone) that could not be read.
type CloudScopeError struct {
	Provider string `json:"provider"`
	Scope    string `json:"scope"`
	Error    string `json:"error"`
}

// CloudObject is a certificate or CA held by a cloud service. Only public
// data is carried. ChainPEM is empty when the service does not return the
// certificate (for example a pack that is not issued yet).
type CloudObject struct {
	Provider string   `json:"provider"`
	Scope    string   `json:"scope"`
	ID       string   `json:"id"` // ARN, vault/name, resource name, zone/id
	Name     string   `json:"name,omitempty"`
	CA       bool     `json:"ca,omitempty"`
	DNSNames []string `json:"dns_names,omitempty"`
	NotAfter string   `json:"not_after,omitempty"` // RFC 3339
	ChainPEM string   `json:"chain_pem,omitempty"`
	// Status is the service's own state word (ISSUED, ACTIVE, active, ...),
	// shown as is.
	Status string `json:"status,omitempty"`
	// Managed is true when the service renews the certificate by itself
	// (ACM-issued and renewal eligible, Key Vault AutoRenew, Google managed,
	// Cloudflare packs).
	Managed bool `json:"managed"`
	// Renewal is the service's issuance or renewal progress, normalised to
	// RenewalPending or RenewalFailed (empty when nothing is in progress),
	// with the service's reason and since when.
	Renewal       string   `json:"renewal,omitempty"`
	RenewalReason string   `json:"renewal_reason,omitempty"`
	RenewalSince  string   `json:"renewal_since,omitempty"`
	InUseBy       []string `json:"in_use_by,omitempty"`
	// NotPubliclyTrusted marks Cloudflare Origin CA certificates.
	NotPubliclyTrusted bool `json:"not_publicly_trusted,omitempty"`
	// Versions lists Key Vault certificate versions, newest first.
	Versions []CloudVersion `json:"versions,omitempty"`
}

// CloudObject.Renewal values.
const (
	RenewalPending = "pending"
	RenewalFailed  = "failed"
)

// CloudVersion is one version of a versioned cloud certificate.
type CloudVersion struct {
	ID       string `json:"id"`
	Created  string `json:"created"`
	Enabled  bool   `json:"enabled"`
	SHA256   string `json:"sha256,omitempty"` // of the leaf certificate
	NotAfter string `json:"not_after,omitempty"`
}

// IISBinding is one https binding of an IIS site with the certificate
// HTTP.sys holds for it. CertHash is the SHA-1 thumbprint (upper-case hex),
// empty when HTTP.sys has no entry for the binding. CertSHA256 is set when
// the certificate was found in its store.
type IISBinding struct {
	Site       string `json:"site"`
	Binding    string `json:"binding"` // ip:port:host as in applicationHost.config
	SSLFlags   int    `json:"ssl_flags"`
	CertHash   string `json:"cert_hash,omitempty"`
	CertStore  string `json:"cert_store,omitempty"`
	CertSHA256 string `json:"cert_sha256,omitempty"`
	ChainPEM   string `json:"chain_pem,omitempty"`
}

// WinACMERenewal is read-only metadata from a win-acme renewal file.
type WinACMERenewal struct {
	ID            string   `json:"id"`
	FriendlyName  string   `json:"friendly_name,omitempty"`
	Hosts         []string `json:"hosts,omitempty"`
	Target        string   `json:"target,omitempty"`
	Store         []string `json:"store,omitempty"`
	Installation  []string `json:"installation,omitempty"`
	LastRenewal   string   `json:"last_renewal,omitempty"`
	LastRenewalOK bool     `json:"last_renewal_ok"`
	Path          string   `json:"path"`
}

// KubeInventory is what an in-cluster agent observed (ADR-0023). Objects
// that could not be listed (missing CRD or permission) are named in Errors.
type KubeInventory struct {
	Cluster      string           `json:"cluster"`
	Certificates []KubeCert       `json:"certificates"`
	Issuers      []KubeIssuer     `json:"issuers"`
	Bundles      []KubeBundle     `json:"bundles"`
	Ingresses    []KubeIngressTLS `json:"ingresses"`
	Errors       []string         `json:"errors,omitempty"`
}

// KubeCondition is a status condition of a cert-manager or trust-manager object.
type KubeCondition struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	Message            string `json:"message,omitempty"`
	LastTransitionTime string `json:"last_transition_time,omitempty"`
}

// KubeCert is a cert-manager Certificate. ChainPEM comes from the
// CertificateRequest of the current revision and is empty when that request
// no longer exists.
type KubeCert struct {
	Namespace     string          `json:"namespace"`
	Name          string          `json:"name"`
	SecretName    string          `json:"secret_name"`
	DNSNames      []string        `json:"dns_names,omitempty"`
	IssuerKind    string          `json:"issuer_kind"`
	IssuerName    string          `json:"issuer_name"`
	Revision      int             `json:"revision,omitempty"`
	NotAfter      string          `json:"not_after,omitempty"`
	RenewalTime   string          `json:"renewal_time,omitempty"`
	Conditions    []KubeCondition `json:"conditions,omitempty"`
	RequestName   string          `json:"request_name,omitempty"`
	RequestFailed string          `json:"request_failed,omitempty"` // Denied or Failed reason of the latest request
	ChainPEM      string          `json:"chain_pem,omitempty"`
}

// KubeIssuer is an Issuer (Namespace set) or ClusterIssuer.
type KubeIssuer struct {
	Namespace  string          `json:"namespace,omitempty"`
	Name       string          `json:"name"`
	Type       string          `json:"type"` // acme, ca, selfSigned, vault, ...
	Conditions []KubeCondition `json:"conditions,omitempty"`
}

// KubeBundle is a trust-manager Bundle.
type KubeBundle struct {
	Name       string          `json:"name"`
	Target     string          `json:"target"`
	Conditions []KubeCondition `json:"conditions,omitempty"`
}

// KubeIngressTLS maps an Ingress TLS secret to its hosts.
type KubeIngressTLS struct {
	Namespace  string   `json:"namespace"`
	Name       string   `json:"name"`
	SecretName string   `json:"secret_name"`
	Hosts      []string `json:"hosts"`
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

// Challenge types.
const (
	ChallengeHTTP01 = "http-01"
	ChallengeDNS01  = "dns-01"
	// ChallengeNone is used with issuers that sign a CSR without ACME.
	ChallengeNone = "none"
)

// SANAllowed matches a SAN against an allowlist. An entry matches itself, and
// an entry "*.parent" also matches any name exactly one label below parent.
// A wildcard SAN is allowed only when wildcards is set (DNS-01) and the
// allowlist holds that exact wildcard: "www.example.com" never permits
// "*.example.com". Both the control plane and the agent check this.
func SANAllowed(san string, allowed []string, wildcards bool) bool {
	san = strings.ToLower(strings.TrimSuffix(san, "."))
	if strings.Contains(san, "*") {
		if !wildcards || strings.Count(san, "*") != 1 || !strings.HasPrefix(san, "*.") {
			return false
		}
		for _, a := range allowed {
			if strings.ToLower(strings.TrimSuffix(a, ".")) == san {
				return true
			}
		}
		return false
	}
	for _, a := range allowed {
		a = strings.ToLower(strings.TrimSuffix(a, "."))
		if a == san {
			return true
		}
		if rest, ok := strings.CutPrefix(a, "*."); ok {
			if label, parent, ok := strings.Cut(san, "."); ok && label != "" && label != "*" && parent == rest {
				return true
			}
		}
	}
	return false
}

// AcceptsCentralDNS reports whether central DNS solvers can be sent to the
// agent. Older agents signal a refusal only by omitting the sealing key.
func (h Heartbeat) AcceptsCentralDNS() bool { return len(h.SealKey) > 0 && !h.NoCentralDNS }

// AcceptsCentralEAB reports whether EAB keys can be sent to the agent.
func (h Heartbeat) AcceptsCentralEAB() bool { return len(h.SealKey) > 0 && !h.NoCentralEAB }

// PluginKindDeployTarget is the plugin kind of plugin targets; the values
// match package plugin.
const PluginKindDeployTarget = "deploy_target"

// HasPlugin reports whether the agent runs plugin name (an installed name
// or a pinned path, as plugin targets report it) for kind.
func (h Heartbeat) HasPlugin(name, kind string) bool {
	for _, p := range h.Plugins {
		if p.Name == name && slices.Contains(p.Kinds, kind) {
			return true
		}
	}
	return false
}
