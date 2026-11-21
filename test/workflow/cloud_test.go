package workflow

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/app"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

func TestCloudObservation(t *testing.T) {
	e := newEnv(t)
	now := time.Now().UTC()
	ts := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339) }
	kvOld := testpki.Issue(t, e.ca, testpki.Options{CommonName: "api.example.com", DNSNames: []string{"api.example.com"}})
	kvNew := testpki.Issue(t, e.ca, testpki.Options{CommonName: "api.example.com", DNSNames: []string{"api.example.com"}})
	acmLeaf := testpki.Issue(t, e.ca, testpki.Options{CommonName: "www.example.com", DNSNames: []string{"www.example.com"}})

	// An endpoint still serving the previous Key Vault version.
	if _, err := e.svc.CreateScope(ctx, e.owner, "internet", store.ScopeConfig{AllowHosts: []string{"*.example.com"}}); err != nil {
		t.Fatal(err)
	}
	ep, err := e.svc.AddEndpoint(ctx, e.owner, app.AddEndpointInput{Host: "api.example.com", Scope: "internet"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.db.Owner.Exec(ctx, `UPDATE endpoints SET last_leaf_sha256 = $1 WHERE id = $2`, sha(kvOld), ep.ID); err != nil {
		t.Fatal(err)
	}

	const failedARN = "arn:aws:acm:eu-west-1:111122223333:certificate/failed"
	const importedARN = "arn:aws:acm:eu-west-1:111122223333:certificate/imported"
	inv := agentproto.CloudInventory{Objects: []agentproto.CloudObject{
		{Provider: agentproto.CloudAWSACM, Scope: "prod/eu-west-1", ID: failedARN, Managed: true, NotAfter: ts(20 * 24 * time.Hour),
			Renewal: agentproto.RenewalFailed, RenewalReason: "CAA_ERROR", ChainPEM: string(acmLeaf.PEM())},
		{Provider: agentproto.CloudAWSACM, Scope: "prod/eu-west-1", ID: importedARN, NotAfter: ts(10 * 24 * time.Hour),
			InUseBy: []string{"arn:aws:cloudfront::111122223333:distribution/E1"}},
		{Provider: agentproto.CloudAzureKeyVault, Scope: "https://corp.vault.azure.net", ID: "https://corp.vault.azure.net/api",
			Managed: true, NotAfter: ts(300 * 24 * time.Hour), ChainPEM: string(kvNew.PEM()),
			Versions: []agentproto.CloudVersion{
				{ID: "v2", Created: ts(-48 * time.Hour), Enabled: true, SHA256: sha(kvNew)},
				{ID: "v1", Created: ts(-400 * 24 * time.Hour), Enabled: true, SHA256: sha(kvOld)},
			}},
		{Provider: agentproto.CloudCloudflareEdge, Scope: "main", ID: "example.com/pack", Managed: true, NotAfter: ts(60 * 24 * time.Hour), Status: "active"},
	}}
	e.report(agentproto.InventoryOutput{Cloud: &inv})
	fs := findings(t, e)
	failing := openOf(fs, "cloud_renewal_failing")
	if len(failing) != 1 || failing[0].severity != "critical" || !strings.HasSuffix(failing[0].subjectID, "/aws_acm/prod/eu-west-1/"+failedARN) {
		t.Fatalf("renewal failing: %+v", failing)
	}
	if manual := openOf(fs, "cloud_renewal_manual"); len(manual) != 1 || !strings.HasSuffix(manual[0].subjectID, importedARN) {
		t.Fatalf("manual renewal: %+v", manual)
	}
	if na := openOf(fs, "cloud_version_not_adopted"); len(na) != 1 {
		t.Fatalf("version not adopted: %+v", fs)
	}
	var imported int
	_ = e.db.Owner.QueryRow(ctx, `SELECT count(*) FROM certificates WHERE source IN ('aws_acm','azure_keyvault')`).Scan(&imported)
	if imported != 2 {
		t.Fatalf("cloud certificates imported: %d", imported)
	}
	var stored string
	_ = e.db.Owner.QueryRow(ctx, `SELECT data::text FROM agent_inventories`).Scan(&stored)
	if strings.Contains(stored, "BEGIN CERTIFICATE") || !strings.Contains(stored, failedARN) {
		t.Fatal("stored inventory must keep the observations without certificate PEMs")
	}

	// The endpoint picked up the new version; the failed certificate is
	// deleted; the vault could not be read this time.
	if _, err := e.db.Owner.Exec(ctx, `UPDATE endpoints SET last_leaf_sha256 = $1 WHERE id = $2`, sha(kvNew), ep.ID); err != nil {
		t.Fatal(err)
	}
	inv.Objects = inv.Objects[1:2]
	inv.Errors = []agentproto.CloudScopeError{{Provider: agentproto.CloudAzureKeyVault, Scope: "https://corp.vault.azure.net", Error: "403"}}
	e.report(agentproto.InventoryOutput{Cloud: &inv})
	fs = findings(t, e)
	if len(openOf(fs, "cloud_renewal_failing")) != 0 {
		t.Fatal("findings of a deleted certificate must resolve")
	}
	if len(openOf(fs, "cloud_version_not_adopted")) != 1 {
		t.Fatal("a vault that could not be read is not known to be fixed; keep its finding")
	}
	if len(openOf(fs, "cloud_renewal_manual")) != 1 {
		t.Fatal("the imported certificate is still there")
	}

	// Next good read of the vault: the endpoint serves the new version.
	inv.Errors = nil
	e.report(agentproto.InventoryOutput{Cloud: &agentproto.CloudInventory{Objects: []agentproto.CloudObject{{
		Provider: agentproto.CloudAzureKeyVault, Scope: "https://corp.vault.azure.net", ID: "https://corp.vault.azure.net/api",
		Managed: true, NotAfter: ts(300 * 24 * time.Hour),
		Versions: []agentproto.CloudVersion{
			{ID: "v2", Created: ts(-48 * time.Hour), Enabled: true, SHA256: sha(kvNew)},
			{ID: "v1", Created: ts(-400 * 24 * time.Hour), Enabled: true, SHA256: sha(kvOld)},
		}}}}})
	if len(openOf(findings(t, e), "cloud_version_not_adopted")) != 0 {
		t.Fatal("adoption finding must resolve once no endpoint serves the old version")
	}
}

func sha(c *testpki.Cert) string {
	s := sha256.Sum256(c.DER)
	return hex.EncodeToString(s[:])
}
