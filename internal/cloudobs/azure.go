package cloudobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azcertificates"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// AzureConfig is a set of Key Vaults read with one identity: by default
// DefaultAzureCredential (environment, workload identity, managed
// identity, Azure CLI); a service principal only through a file.
type AzureConfig struct {
	Name   string   `json:"name"`
	Vaults []string `json:"vaults"` // https://<vault>.vault.azure.net
	// TenantID and ClientID with one of the files select a service
	// principal instead of the default chain.
	TenantID              string `json:"tenant_id,omitempty"`
	ClientID              string `json:"client_id,omitempty"`
	ClientSecretFile      string `json:"client_secret_file,omitempty"`
	ClientCertificateFile string `json:"client_certificate_file,omitempty"`
	// ClientSecret is a service principal secret held in memory (certloomd).
	ClientSecret string `json:"-"`
}

// kvVersionsKept bounds the versions reported per certificate.
const kvVersionsKept = 10

func (a AzureConfig) validate() []string {
	var p []string
	w := "cloud.azure " + a.Name
	if len(a.Vaults) == 0 {
		p = append(p, w+": vaults is required")
	}
	for _, v := range a.Vaults {
		if !strings.HasPrefix(v, "https://") {
			p = append(p, w+": vault "+v+" must be an https URL")
		}
	}
	if a.ClientSecretFile != "" && a.ClientCertificateFile != "" {
		p = append(p, w+": set client_secret_file or client_certificate_file, not both")
	}
	for _, f := range []string{a.ClientSecretFile, a.ClientCertificateFile} {
		if f == "" {
			continue
		}
		if !filepath.IsAbs(f) {
			p = append(p, w+": credential files must be absolute paths")
		}
		if a.TenantID == "" || a.ClientID == "" {
			p = append(p, w+": tenant_id and client_id are required with a credential file")
		}
	}
	return p
}

func (a AzureConfig) credential(hc *http.Client) (azcore.TokenCredential, error) {
	co := azcore.ClientOptions{Transport: hc}
	switch {
	case a.ClientSecret != "":
		return azidentity.NewClientSecretCredential(a.TenantID, a.ClientID, a.ClientSecret,
			&azidentity.ClientSecretCredentialOptions{ClientOptions: co})
	case a.ClientSecretFile != "":
		b, err := os.ReadFile(a.ClientSecretFile)
		if err != nil {
			return nil, err
		}
		return azidentity.NewClientSecretCredential(a.TenantID, a.ClientID, strings.TrimSpace(string(b)),
			&azidentity.ClientSecretCredentialOptions{ClientOptions: co})
	case a.ClientCertificateFile != "":
		b, err := os.ReadFile(a.ClientCertificateFile)
		if err != nil {
			return nil, err
		}
		certs, key, err := azidentity.ParseCertificates(b, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", a.ClientCertificateFile, err)
		}
		return azidentity.NewClientCertificateCredential(a.TenantID, a.ClientID, certs, key,
			&azidentity.ClientCertificateCredentialOptions{ClientOptions: co})
	}
	return azidentity.NewDefaultAzureCredential(&azidentity.DefaultAzureCredentialOptions{ClientOptions: co, TenantID: a.TenantID})
}

func azureScopes(a AzureConfig, h *Hooks) ([]cloudScope, error) {
	cred := h.AzureCred
	if cred == nil {
		c, err := a.credential(h.HTTPClient)
		if err != nil {
			return nil, err
		}
		cred = c
	}
	var scopes []cloudScope
	for _, v := range a.Vaults {
		v = strings.TrimSuffix(v, "/")
		c, err := azcertificates.NewClient(v, cred, &azcertificates.ClientOptions{ClientOptions: azcore.ClientOptions{
			Transport: h.HTTPClient, Retry: policy.RetryOptions{MaxRetries: 4}}, DisableChallengeResourceVerification: h.AzureAnyResource})
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, cloudScope{provider: agentproto.CloudAzureKeyVault, scope: v,
			read: func(ctx context.Context, emit func(agentproto.CloudObject) bool) error {
				return readKeyVault(ctx, c, v, emit)
			}})
	}
	return scopes, nil
}

// readKeyVault lists a vault's certificates. Only certificate endpoints are
// called; the secret that holds a certificate's private key never is.
func readKeyVault(ctx context.Context, c *azcertificates.Client, vault string, emit func(agentproto.CloudObject) bool) error {
	p := c.NewListCertificatePropertiesPager(nil)
	for p.More() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return err
		}
		for _, props := range page.Value {
			if props.ID == nil {
				continue
			}
			o, err := keyVaultObject(ctx, c, vault, props.ID.Name())
			if notFound(err) {
				continue // deleted since the list call
			}
			if err != nil {
				return err
			}
			if !emit(o) {
				return nil
			}
		}
	}
	return nil
}

func keyVaultObject(ctx context.Context, c *azcertificates.Client, vault, name string) (agentproto.CloudObject, error) {
	o := agentproto.CloudObject{ID: vault + "/" + name, Name: name}
	cur, err := c.GetCertificate(ctx, name, "", nil)
	if err != nil {
		return o, err
	}
	if cur.Attributes != nil {
		o.NotAfter = rfc3339(cur.Attributes.Expires)
		if cur.Attributes.Enabled != nil && !*cur.Attributes.Enabled {
			o.Status = "disabled"
		}
	}
	if len(cur.CER) > 0 {
		o.ChainPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cur.CER}))
	}
	if pol := cur.Policy; pol != nil {
		for _, la := range pol.LifetimeActions {
			if la != nil && la.Action != nil && la.Action.ActionType != nil &&
				*la.Action.ActionType == azcertificates.CertificatePolicyActionAutoRenew {
				o.Managed = true
			}
		}
		if x := pol.X509CertificateProperties; x != nil && x.SubjectAlternativeNames != nil {
			for _, n := range x.SubjectAlternativeNames.DNSNames {
				if n != nil {
					o.DNSNames = append(o.DNSNames, *n)
				}
			}
			o.DNSNames = sortedUnique(o.DNSNames)
		}
	}
	op, err := c.GetCertificateOperation(ctx, name, nil)
	switch {
	case err == nil && op.Status != nil:
		switch strings.ToLower(*op.Status) {
		case "inprogress":
			o.Renewal = agentproto.RenewalPending
		case "failed":
			o.Renewal = agentproto.RenewalFailed
			if op.Error != nil {
				o.RenewalReason = op.Error.Error()
			}
		}
	case err != nil && !notFound(err) && !forbidden(err):
		// No operation is a 404; a role without access to it is not an
		// error for the inventory as a whole.
		return o, err
	}
	o.Versions, err = keyVaultVersions(ctx, c, name)
	return o, err
}

// keyVaultVersions lists the newest versions with the SHA-256 of the two
// newest enabled ones, which is enough to tell whether consumers moved on.
func keyVaultVersions(ctx context.Context, c *azcertificates.Client, name string) ([]agentproto.CloudVersion, error) {
	type ver struct {
		id      string
		created time.Time
		enabled bool
		exp     *time.Time
	}
	var all []ver
	p := c.NewListCertificatePropertiesVersionsPager(name, nil)
	for p.More() {
		page, err := p.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, v := range page.Value {
			if v.ID == nil || v.Attributes == nil || v.Attributes.Created == nil {
				continue
			}
			all = append(all, ver{id: v.ID.Version(), created: *v.Attributes.Created,
				enabled: v.Attributes.Enabled == nil || *v.Attributes.Enabled, exp: v.Attributes.Expires})
		}
	}
	slices.SortFunc(all, func(a, b ver) int { return b.created.Compare(a.created) })
	if len(all) > kvVersionsKept {
		all = all[:kvVersionsKept]
	}
	out := make([]agentproto.CloudVersion, 0, len(all))
	hashed := 0
	for _, v := range all {
		cv := agentproto.CloudVersion{ID: v.id, Created: rfc3339(&v.created), Enabled: v.enabled, NotAfter: rfc3339(v.exp)}
		if v.enabled && hashed < 2 {
			r, err := c.GetCertificate(ctx, name, v.id, nil)
			if err != nil && !notFound(err) {
				return nil, err
			}
			if len(r.CER) > 0 {
				sum := sha256.Sum256(r.CER)
				cv.SHA256 = hex.EncodeToString(sum[:])
			}
			hashed++
		}
		out = append(out, cv)
	}
	return out, nil
}

func notFound(err error) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && re.StatusCode == http.StatusNotFound
}

func forbidden(err error) bool {
	var re *azcore.ResponseError
	return errors.As(err, &re) && re.StatusCode == http.StatusForbidden
}
