package authz

import "testing"

// The full role x permission matrix. Changing a grant must change this table.
func TestMatrix(t *testing.T) {
	all := []Permission{ViewInventory, ImportCerts, ManageEndpoints, ManageScopes, ManageOwnership, AckAlerts,
		ManageChannels, ManageTokens, ViewAudit, ManageAutomation, ManageMembers, ManagePolicy,
		ManageAgents, ManageIssuers, ManageDeployments, RunRenewals, RequestDeployments, ApproveRequests, RequestExceptions}
	owner := map[Permission]bool{}
	for _, p := range all {
		owner[p] = true
	}
	want := map[string]map[Permission]bool{
		"owner":               owner,
		"operator":            {ViewInventory: true, ImportCerts: true, ManageEndpoints: true, ManageOwnership: true, AckAlerts: true, RunRenewals: true, RequestExceptions: true},
		"viewer":              {ViewInventory: true},
		"auditor":             {ViewInventory: true, ViewAudit: true},
		"requester":           {ViewInventory: true, RequestDeployments: true, RequestExceptions: true},
		"approver":            {ViewInventory: true, ApproveRequests: true},
		"deployment_operator": {ViewInventory: true, AckAlerts: true, ManageDeployments: true, RunRenewals: true},
		"issuer_admin":        {ViewInventory: true, ManageIssuers: true},
		"":                    {},
		"unknown":             {},
	}
	for role, perms := range want {
		p := Principal{Role: role}
		for _, perm := range all {
			if got := p.Can(perm); got != perms[perm] {
				t.Errorf("role %q permission %s: got %v, want %v", role, perm, got, perms[perm])
			}
		}
	}
}

// Operators must not be able to widen what the prober may reach (threat T1),
// mint tokens, change notification destinations, enroll agents, or change
// where certificates come from or are deployed (threat T12).
func TestOperatorCannotEscalate(t *testing.T) {
	op := Principal{Role: "operator"}
	for _, p := range []Permission{ManageScopes, ManageTokens, ManageChannels, ManageAutomation, ManageMembers, ManagePolicy,
		ManageAgents, ManageIssuers, ManageDeployments} {
		if op.Require(p) == nil {
			t.Errorf("operator must not hold %s", p)
		}
	}
}

// Requesting and approving must never meet in a non-owner role, and the
// roles that can approve must not be able to change what gets issued.
func TestSeparationOfDuties(t *testing.T) {
	for _, role := range Roles() {
		p := Principal{Role: role}
		if role != "owner" && p.Can(ApproveRequests) && (p.Can(RequestDeployments) || p.Can(RequestExceptions) || p.Can(ManageDeployments) || p.Can(ManageIssuers)) {
			t.Errorf("role %q can both approve and change deployments or issuers", role)
		}
	}
	for _, role := range []string{"requester", "approver", "issuer_admin"} {
		if (Principal{Role: role}).Can(RunRenewals) {
			t.Errorf("role %q must not start renewals", role)
		}
	}
}
