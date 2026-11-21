package authz

import "testing"

// The full role x permission matrix. Changing a grant must change this table.
func TestMatrix(t *testing.T) {
	all := []Permission{ViewInventory, ImportCerts, ManageEndpoints, ManageScopes, ManageOwnership, AckAlerts,
		ManageChannels, ManageTokens, ViewAudit, ManageAutomation, ManageMembers, ManagePolicy,
		ManageAgents, ManageIssuers, ManageDeployments, RunRenewals}
	owner := map[Permission]bool{}
	for _, p := range all {
		owner[p] = true
	}
	want := map[string]map[Permission]bool{
		"owner":    owner,
		"operator": {ViewInventory: true, ImportCerts: true, ManageEndpoints: true, ManageOwnership: true, AckAlerts: true, RunRenewals: true},
		"viewer":   {ViewInventory: true},
		"auditor":  {ViewInventory: true, ViewAudit: true},
		"":         {},
		"unknown":  {},
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
