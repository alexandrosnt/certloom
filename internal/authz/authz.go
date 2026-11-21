// Package authz maps roles to permissions. Checks happen in the
// service layer, so API, UI and CLI share one enforcement point.
package authz

import (
	"errors"
	"fmt"
)

// Permission is a (verb, resource) pair.
type Permission string

// Permissions.
const (
	ViewInventory    Permission = "inventory:view"
	ImportCerts      Permission = "certificates:import"
	ManageEndpoints  Permission = "endpoints:manage"
	ManageScopes     Permission = "scopes:manage" // can widen what the prober may reach
	ManageOwnership  Permission = "ownership:manage"
	AckAlerts        Permission = "alerts:ack"
	ManageChannels   Permission = "channels:manage"
	ManageTokens     Permission = "tokens:manage"
	ViewAudit        Permission = "audit:view"
	ManageAutomation Permission = "automation:manage" // pause switches
	ManageMembers    Permission = "members:manage"    // OIDC members
	ManagePolicy     Permission = "policy:manage"     // monitoring policy versions
	// issuance and deployment
	ManageAgents      Permission = "agents:manage"      // enroll, revoke agents
	ManageIssuers     Permission = "issuers:manage"     // ACME issuer configuration
	ManageDeployments Permission = "deployments:manage" // bind lineages to agent targets
	RunRenewals       Permission = "renewals:run"       // start/cancel renewal runs
	// approvals (separation of duties: nobody approves their own request)
	RequestDeployments Permission = "deployments:request" // propose a deployment; it waits for approval
	ApproveRequests    Permission = "approvals:decide"    // approve or deny requests made by someone else
	RequestExceptions  Permission = "exceptions:request"  // ask to accept the risk of a finding for a while
	// DNS-01 solvers defined centrally, including their credentials
	ManageDNS Permission = "dns:manage"
	// certificate templates (ADR-0020)
	ManageTemplates Permission = "templates:manage"
	// event webhook endpoints and their secrets (ADR-0021)
	ManageWebhooks Permission = "webhooks:manage"
)

var grants = map[string][]Permission{
	"owner": {ViewInventory, ImportCerts, ManageEndpoints, ManageScopes, ManageOwnership, AckAlerts,
		ManageChannels, ManageTokens, ViewAudit, ManageAutomation, ManageMembers, ManagePolicy,
		ManageAgents, ManageIssuers, ManageDeployments, RunRenewals, RequestDeployments, ApproveRequests, RequestExceptions, ManageDNS, ManageTemplates, ManageWebhooks},
	"operator":            {ViewInventory, ImportCerts, ManageEndpoints, ManageOwnership, AckAlerts, RunRenewals, RequestExceptions},
	"viewer":              {ViewInventory},
	"auditor":             {ViewInventory, ViewAudit},
	"requester":           {ViewInventory, RequestDeployments, RequestExceptions},
	"approver":            {ViewInventory, ApproveRequests},
	"deployment_operator": {ViewInventory, AckAlerts, ManageDeployments, RunRenewals},
	"issuer_admin":        {ViewInventory, ManageIssuers, ManageDNS, ManageTemplates},
}

// ErrForbidden is returned when the principal lacks a permission.
var ErrForbidden = errors.New("forbidden")

// Principal is an authenticated caller.
type Principal struct {
	OrgID string
	Actor string // e.g. "token:tok_..." or "user:alice@example.com"
	Role  string
}

// Can reports whether the principal holds p.
func (pr Principal) Can(p Permission) bool {
	for _, g := range grants[pr.Role] {
		if g == p {
			return true
		}
	}
	return false
}

// Require returns ErrForbidden (wrapped with the permission) if p is not held.
func (pr Principal) Require(p Permission) error {
	if pr.Can(p) {
		return nil
	}
	return fmt.Errorf("%w: role %q lacks %s", ErrForbidden, pr.Role, p)
}

// Roles lists known roles.
func Roles() []string {
	return []string{"owner", "operator", "viewer", "auditor", "requester", "approver", "deployment_operator", "issuer_admin"}
}

// Grants returns the permission set for a role (for docs and tests).
func Grants(role string) []Permission { return append([]Permission(nil), grants[role]...) }
