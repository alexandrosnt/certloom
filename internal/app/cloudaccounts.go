package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/cloudobs"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/policy"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Cloud accounts that certloomd reads itself, without an agent (ADR-0034).
// They use the same read-only calls as the agent (package cloudobs). Unlike
// an agent's config file, settings come from the API, so they name no local
// files and no endpoints: either could make certloomd read its own secrets
// or send a cloud token somewhere else.

// JobKindCloudScan reads one cloud account.
const JobKindCloudScan = "cloud_scan"

// cloudScanTimeout keeps a scan inside the job lease.
const cloudScanTimeout = 75 * time.Second

// CloudAccountInput describes a new account, or new settings for one.
type CloudAccountInput struct {
	Name, Provider string
	// Credential is "ambient" (certloomd's own cloud identity, the default)
	// or "stored" (Secret, kept encrypted with the KEK).
	Credential      string
	Settings        json.RawMessage
	IntervalSeconds int
	// Secret is a JSON object of strings; the keys depend on the provider.
	Secret secret.Value
}

type awsAccountSettings struct {
	Regions       []string `json:"regions"`
	AssumeRoleARN string   `json:"assume_role_arn,omitempty"`
	ExternalID    string   `json:"external_id,omitempty"`
	PrivateCA     bool     `json:"private_ca,omitempty"`
}

type azureAccountSettings struct {
	Vaults   []string `json:"vaults"`
	TenantID string   `json:"tenant_id,omitempty"`
	ClientID string   `json:"client_id,omitempty"`
}

type gcpAccountSettings struct {
	Project            string   `json:"project"`
	Locations          []string `json:"locations,omitempty"`
	CertificateManager *bool    `json:"certificate_manager,omitempty"`
	CAS                bool     `json:"cas,omitempty"`
}

type cloudflareAccountSettings struct {
	Zones    []string `json:"zones,omitempty"`
	OriginCA bool     `json:"origin_ca,omitempty"`
}

// cloudSecretKeys lists the keys each provider's stored secret needs.
var cloudSecretKeys = map[string][]string{
	"aws":        {"access_key_id", "secret_access_key"},
	"azure":      {"client_secret"},
	"gcp":        {"service_account_key"},
	"cloudflare": {"api_token"},
}

// Key Vault hosts in the public and sovereign clouds.
var keyVaultSuffixes = []string{".vault.azure.net", ".vault.azure.cn", ".vault.usgovcloudapi.net", ".vault.microsoftazure.de"}

var (
	cloudNameRE   = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)
	awsRegionRE   = regexp.MustCompile(`^[a-z]{2}(-[a-z]+)+-[0-9]+$`)
	gcpProjectRE  = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	gcpLocationRE = regexp.MustCompile(`^[a-z0-9-]+$`)
	cfZoneRE      = regexp.MustCompile(`^[a-z0-9.-]+$`)
)

func cloudAccountAAD(id string) string { return "cloud_account:" + id }

// decodeSettings parses settings strictly: unknown keys are refused, so
// nothing beyond the documented fields reaches the providers.
func decodeSettings(raw json.RawMessage, v any) error {
	if len(raw) == 0 {
		raw = json.RawMessage(`{}`)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return invalid("settings: %v", err)
	}
	return nil
}

// checkCloudSettings validates settings for a provider. They are stored as
// given (only re-encoded), so declarative clients see no drift.
func checkCloudSettings(provider, credential string, raw json.RawMessage) (json.RawMessage, error) {
	var v any
	switch provider {
	case "aws":
		var s awsAccountSettings
		if err := decodeSettings(raw, &s); err != nil {
			return nil, err
		}
		if len(s.Regions) == 0 {
			return nil, invalid("settings.regions is required, e.g. [\"us-east-1\"]")
		}
		for _, r := range s.Regions {
			if !awsRegionRE.MatchString(r) {
				return nil, invalid("settings.regions: %q is not an AWS region name", r)
			}
		}
		if s.AssumeRoleARN != "" && !strings.HasPrefix(s.AssumeRoleARN, "arn:aws") {
			return nil, invalid("settings.assume_role_arn must be a role ARN")
		}
		if s.ExternalID != "" && s.AssumeRoleARN == "" {
			return nil, invalid("settings.external_id needs assume_role_arn")
		}
		if hasDuplicates(s.Regions) {
			return nil, invalid("settings.regions lists a region twice")
		}
		v = s
	case "azure":
		var s azureAccountSettings
		if err := decodeSettings(raw, &s); err != nil {
			return nil, err
		}
		if len(s.Vaults) == 0 {
			return nil, invalid("settings.vaults is required, e.g. [\"https://corp-tls.vault.azure.net\"]")
		}
		for _, vault := range s.Vaults {
			u, err := url.Parse(vault)
			if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || strings.Trim(u.Path, "/") != "" || u.RawQuery != "" ||
				!slices.ContainsFunc(keyVaultSuffixes, func(sfx string) bool { return strings.HasSuffix(u.Hostname(), sfx) }) ||
				vault != "https://"+strings.ToLower(u.Hostname()) {
				return nil, invalid("settings.vaults: %q is not a Key Vault URL in the form https://<name>.vault.azure.net (lowercase, no trailing slash)", vault)
			}
		}
		if credential == "stored" && (s.TenantID == "" || s.ClientID == "") {
			return nil, invalid("settings.tenant_id and settings.client_id are required with a stored client secret")
		}
		v = s
	case "gcp":
		var s gcpAccountSettings
		if err := decodeSettings(raw, &s); err != nil {
			return nil, err
		}
		if !gcpProjectRE.MatchString(s.Project) {
			return nil, invalid("settings.project must be a Google Cloud project id")
		}
		for _, l := range s.Locations {
			if !gcpLocationRE.MatchString(l) {
				return nil, invalid("settings.locations: invalid location %q", l)
			}
		}
		if s.CertificateManager != nil && !*s.CertificateManager && !s.CAS {
			return nil, invalid("settings: nothing to read; enable certificate_manager or cas")
		}
		v = s
	case "cloudflare":
		var s cloudflareAccountSettings
		if err := decodeSettings(raw, &s); err != nil {
			return nil, err
		}
		for _, z := range s.Zones {
			if !cfZoneRE.MatchString(z) || strings.HasPrefix(z, ".") || strings.HasSuffix(z, ".") {
				return nil, invalid("settings.zones: %q is not a zone name (lowercase, no trailing dot)", z)
			}
		}
		if hasDuplicates(s.Zones) {
			return nil, invalid("settings.zones lists a zone twice")
		}
		if credential != "stored" {
			return nil, invalid("cloudflare needs a stored API token (credential stored)")
		}
		v = s
	default:
		return nil, invalid("provider must be aws, azure, gcp or cloudflare")
	}
	return json.Marshal(v)
}

func checkCloudSecret(provider string, v secret.Value) error {
	var m map[string]string
	if err := json.Unmarshal(v.Reveal(), &m); err != nil || len(m) == 0 {
		return invalid("secret must be a non-empty JSON object of strings")
	}
	for _, k := range cloudSecretKeys[provider] {
		if strings.TrimSpace(m[k]) == "" {
			return invalid("secret for %s needs %q", provider, k)
		}
	}
	for k := range m {
		if !slices.Contains(cloudSecretKeys[provider], k) {
			return invalid("secret for %s has an unknown key %q", provider, k)
		}
	}
	if provider == "gcp" {
		var key struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(m["service_account_key"]), &key); err != nil || key.Type != "service_account" {
			return invalid("secret.service_account_key must be a service account key file (type service_account)")
		}
	}
	return nil
}

func (s *Service) cloudCentralAllowed(ctx context.Context, tx *store.Tx) (bool, error) {
	pv, err := tx.ActivePolicy(ctx)
	if err != nil {
		return false, err
	}
	return pv.Document.Spec.Cloud.CentralCredentials != policy.CentralCredentialsForbidden, nil
}

// errNoKEK is returned when a credential would have to be stored without a
// key-encryption key.
var errNoKEK = invalid("storing a cloud credential needs a key-encryption key (CERTLOOM_KEK_FILE)")

func checkInterval(sec *int) error {
	switch {
	case *sec == 0:
		*sec = cloudobs.DefaultInterval
	case *sec < cloudobs.MinInterval:
		return invalid("interval_seconds must be at least %d", cloudobs.MinInterval)
	}
	return nil
}

// CreateCloudAccount adds an account; its first scan starts right away.
func (s *Service) CreateCloudAccount(ctx context.Context, p authz.Principal, in CloudAccountInput) (*store.CloudAccount, error) {
	if !cloudNameRE.MatchString(in.Name) {
		return nil, invalid("name must be 1-64 letters, digits, '.', '_' or '-'")
	}
	if in.Credential == "" {
		in.Credential = "ambient"
	}
	if in.Credential != "ambient" && in.Credential != "stored" {
		return nil, invalid("credential must be ambient or stored")
	}
	settings, err := checkCloudSettings(in.Provider, in.Credential, in.Settings)
	if err != nil {
		return nil, err
	}
	if err := checkInterval(&in.IntervalSeconds); err != nil {
		return nil, err
	}
	if in.Credential == "ambient" && !in.Secret.IsEmpty() {
		return nil, invalid("an ambient account takes no secret")
	}
	if in.Credential == "stored" {
		if s.PKI == nil {
			return nil, errNoKEK
		}
		if err := checkCloudSecret(in.Provider, in.Secret); err != nil {
			return nil, err
		}
	}
	a := &store.CloudAccount{ID: store.NewCloudAccountID(), Name: in.Name, Provider: in.Provider, Settings: settings,
		Credential: in.Credential, IntervalSeconds: in.IntervalSeconds}
	err = s.tx(ctx, p, authz.ManageCloud, func(tx *store.Tx) error {
		if a.Credential == "stored" {
			ok, err := s.cloudCentralAllowed(ctx, tx)
			if err != nil {
				return err
			}
			if !ok {
				return invalid("policy cloud.centralCredentials is forbidden: use certloomd's own cloud identity (credential ambient) or an agent")
			}
			if a.SecretCiphertext, err = s.PKI.KEK.Seal(in.Secret.Reveal(), cloudAccountAAD(a.ID)); err != nil {
				return err
			}
		}
		if err := tx.CreateCloudAccount(ctx, a, p.Actor); err != nil {
			return err
		}
		a.HasSecret = len(a.SecretCiphertext) > 0
		if err := s.enqueueCloudScan(ctx, tx, a.ID, "create"); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "cloud_accounts.create", "cloud_account", a.ID, map[string]any{"name": a.Name,
			"provider": a.Provider, "settings": a.Settings, "credential": a.Credential, "interval_seconds": a.IntervalSeconds})
	})
	return a, err
}

// UpdateCloudAccount replaces an account's settings and interval. The
// provider and the credential kind cannot change; create a new account.
func (s *Service) UpdateCloudAccount(ctx context.Context, p authz.Principal, ref string, in CloudAccountInput, ifVersion *int64) (a *store.CloudAccount, err error) {
	if err := checkInterval(&in.IntervalSeconds); err != nil {
		return nil, err
	}
	err = s.tx(ctx, p, authz.ManageCloud, func(tx *store.Tx) error {
		if a, err = tx.GetCloudAccount(ctx, ref); err != nil {
			return err
		}
		settings, err := checkCloudSettings(a.Provider, a.Credential, in.Settings)
		if err != nil {
			return err
		}
		a.Settings, a.IntervalSeconds = settings, in.IntervalSeconds
		if err := tx.UpdateCloudAccount(ctx, a, ifVersion); err != nil {
			return err
		}
		if err := s.enqueueCloudScan(ctx, tx, a.ID, fmt.Sprint("update-", a.Version)); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "cloud_accounts.update", "cloud_account", a.ID, map[string]any{"name": a.Name,
			"settings": a.Settings, "interval_seconds": a.IntervalSeconds})
	})
	return a, err
}

// ListCloudAccounts lists accounts without their secrets.
func (s *Service) ListCloudAccounts(ctx context.Context, p authz.Principal) (out []*store.CloudAccount, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListCloudAccounts(ctx); return err })
	return out, err
}

// GetCloudAccount returns one account without its secret.
func (s *Service) GetCloudAccount(ctx context.Context, p authz.Principal, ref string) (a *store.CloudAccount, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { a, err = tx.GetCloudAccount(ctx, ref); return err })
	return a, err
}

// CloudAccountInventory returns what the last scan saw, without PEMs.
func (s *Service) CloudAccountInventory(ctx context.Context, p authz.Principal, ref string) (out map[string]any, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error {
		a, err := tx.GetCloudAccount(ctx, ref)
		if err != nil {
			return err
		}
		data, err := tx.CloudAccountInventory(ctx, a.ID)
		if err != nil {
			return err
		}
		out = map[string]any{"cloud_account_id": a.ID, "scanned_at": a.LastScanAt, "cloud": data}
		return nil
	})
	return out, err
}

// SetCloudAccountSecret replaces (rotates) a stored secret and rescans.
func (s *Service) SetCloudAccountSecret(ctx context.Context, p authz.Principal, ref string, v secret.Value) error {
	if s.PKI == nil {
		return errNoKEK
	}
	return s.tx(ctx, p, authz.ManageCloud, func(tx *store.Tx) error {
		a, err := tx.GetCloudAccount(ctx, ref)
		if err != nil {
			return err
		}
		if a.Credential != "stored" {
			return invalid("cloud account %s uses certloomd's own identity and stores no secret", a.Name)
		}
		if ok, err := s.cloudCentralAllowed(ctx, tx); err != nil || !ok {
			if err != nil {
				return err
			}
			return invalid("policy cloud.centralCredentials is forbidden")
		}
		if err := checkCloudSecret(a.Provider, v); err != nil {
			return err
		}
		ct, err := s.PKI.KEK.Seal(v.Reveal(), cloudAccountAAD(a.ID))
		if err != nil {
			return err
		}
		if err := tx.SetCloudAccountSecret(ctx, a.ID, ct); err != nil {
			return err
		}
		if err := s.enqueueCloudScan(ctx, tx, a.ID, fmt.Sprint("secret-", s.now().UnixNano())); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "cloud_accounts.set_secret", "cloud_account", a.ID, map[string]any{"name": a.Name})
	})
}

// DeleteCloudAccount deletes an account and its secret, and resolves the
// findings of what it saw.
func (s *Service) DeleteCloudAccount(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ManageCloud, func(tx *store.Tx) error {
		a, err := tx.GetCloudAccount(ctx, ref)
		if err != nil {
			return err
		}
		if err := tx.DeleteCloudAccount(ctx, a.ID); err != nil {
			return err
		}
		// An empty inventory resolves every finding under the account.
		if err := s.syncCloud(ctx, tx, a.ID, &agentproto.CloudInventory{}, s.now()); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "cloud_accounts.delete", "cloud_account", a.ID, map[string]any{"name": a.Name})
	})
}

// RequestCloudScan scans an account now instead of at its next due time.
func (s *Service) RequestCloudScan(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error {
		a, err := tx.GetCloudAccount(ctx, ref)
		if err != nil {
			return err
		}
		return s.enqueueCloudScan(ctx, tx, a.ID, fmt.Sprint("manual-", s.now().Unix()/60))
	})
}

func (s *Service) enqueueCloudScan(ctx context.Context, tx *store.Tx, id, why string) error {
	_, err := jobs.Enqueue(ctx, tx, tx.OrgID, JobKindCloudScan, id+":"+why, map[string]string{"cloud_account_id": id}, time.Time{})
	return err
}

// ScheduleCloudScans queues a scan for every account that is due. The next
// due time moves forward at once, so a slow scan is not queued twice.
func (s *Service) ScheduleCloudScans(ctx context.Context) error {
	orgs, err := s.orgIDs(ctx)
	if err != nil {
		return err
	}
	for _, org := range orgs {
		err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
			now := s.now()
			due, err := tx.CloudAccountsDue(ctx, now)
			if err != nil {
				return err
			}
			for _, a := range due {
				if err := s.enqueueCloudScan(ctx, tx, a.ID, a.NextScanAt.UTC().Format(time.RFC3339)); err != nil {
					return err
				}
				if err := tx.ScheduleCloudScan(ctx, a.ID, now.Add(time.Duration(a.IntervalSeconds)*time.Second)); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// RunCloudScan reads one account and records what it saw. The cloud calls
// run outside any transaction.
func (s *Service) RunCloudScan(ctx context.Context, j jobs.Job) error {
	var pl struct {
		ID string `json:"cloud_account_id"`
	}
	if err := json.Unmarshal(j.Payload, &pl); err != nil {
		return err
	}
	var a *store.CloudAccount
	var cfg *cloudobs.Config
	var refused string
	err := s.DB.WithOrg(ctx, j.OrgID, func(tx *store.Tx) error {
		var err error
		if a, err = tx.GetCloudAccount(ctx, pl.ID); err != nil {
			return err
		}
		var plain []byte
		if a.Credential == "stored" {
			ok, err := s.cloudCentralAllowed(ctx, tx)
			if err != nil {
				return err
			}
			switch {
			case !ok:
				refused = "policy cloud.centralCredentials is forbidden; the stored credential is not used"
				return nil
			case s.PKI == nil:
				refused = "certloomd has no key-encryption key to open the stored credential"
				return nil
			}
			if plain, err = s.PKI.KEK.Open(a.SecretCiphertext, cloudAccountAAD(a.ID)); err != nil {
				return fmt.Errorf("cloud account %s: stored secret cannot be decrypted: %w", a.Name, err)
			}
			defer clear(plain)
		}
		cfg, err = cloudConfig(a, plain)
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		// Deleted after the scan was queued.
		return s.DB.WithOrg(ctx, j.OrgID, func(tx *store.Tx) error { return jobs.Complete(ctx, tx, j) })
	}
	if err != nil {
		return err
	}
	var inv *agentproto.CloudInventory
	if refused != "" {
		inv = &agentproto.CloudInventory{Errors: []agentproto.CloudScopeError{{Provider: a.Provider, Scope: a.Name, Error: refused}}}
	} else {
		sctx, cancel := context.WithTimeout(ctx, cloudScanTimeout)
		inv = cloudobs.Collect(sctx, cfg, s.CloudHooks, s.logger().With("cloud_account", a.Name))
		cancel()
	}
	return s.DB.WithOrg(ctx, j.OrgID, func(tx *store.Tx) error {
		if err := jobs.Fence(ctx, tx, j); err != nil {
			return err
		}
		now := s.now()
		if _, err := s.importCloudInventory(ctx, tx, a.ID, inv, now); err != nil {
			return err
		}
		next := now.Add(time.Duration(a.IntervalSeconds) * time.Second)
		if err := tx.SaveCloudScan(ctx, a.ID, stripChains(inv), now, next); err != nil {
			return err
		}
		return jobs.Complete(ctx, tx, j)
	})
}

// cloudConfig turns an account into a one-entry provider config. plain is
// the decrypted secret, nil for ambient accounts.
func cloudConfig(a *store.CloudAccount, plain []byte) (*cloudobs.Config, error) {
	sec := map[string]string{}
	if len(plain) > 0 {
		if err := json.Unmarshal(plain, &sec); err != nil {
			return nil, fmt.Errorf("cloud account %s: stored secret: %w", a.Name, err)
		}
	}
	cfg := &cloudobs.Config{}
	switch a.Provider {
	case "aws":
		var st awsAccountSettings
		if err := json.Unmarshal(a.Settings, &st); err != nil {
			return nil, err
		}
		cfg.AWS = []cloudobs.AWSAccountConfig{{Name: a.Name, Regions: st.Regions, AssumeRoleARN: st.AssumeRoleARN,
			ExternalID: st.ExternalID, PrivateCA: st.PrivateCA, AccessKeyID: sec["access_key_id"],
			SecretAccessKey: sec["secret_access_key"], SessionName: "certloomd"}}
	case "azure":
		var st azureAccountSettings
		if err := json.Unmarshal(a.Settings, &st); err != nil {
			return nil, err
		}
		cfg.Azure = []cloudobs.AzureConfig{{Name: a.Name, Vaults: st.Vaults, TenantID: st.TenantID, ClientID: st.ClientID,
			ClientSecret: sec["client_secret"]}}
	case "gcp":
		var st gcpAccountSettings
		if err := json.Unmarshal(a.Settings, &st); err != nil {
			return nil, err
		}
		g := cloudobs.GCPConfig{Name: a.Name, Project: st.Project, Locations: st.Locations,
			CertificateManager: st.CertificateManager, CAS: st.CAS}
		if k := sec["service_account_key"]; k != "" {
			g.CredentialsJSON = []byte(k)
		}
		cfg.GCP = []cloudobs.GCPConfig{g}
	case "cloudflare":
		var st cloudflareAccountSettings
		if err := json.Unmarshal(a.Settings, &st); err != nil {
			return nil, err
		}
		cfg.Cloudflare = []cloudobs.CloudflareConfig{{Name: a.Name, Zones: st.Zones, OriginCA: st.OriginCA,
			APIToken: sec["api_token"]}}
	default:
		return nil, fmt.Errorf("cloud account %s: unknown provider %q", a.Name, a.Provider)
	}
	return cfg, nil
}

// importCloudInventory adds the certificates a cloud inventory carries to
// the inventory and syncs cloud findings under owner (an agent or a cloud
// account id). It returns the number of new certificates.
func (s *Service) importCloudInventory(ctx context.Context, tx *store.Tx, owner string, inv *agentproto.CloudInventory, now time.Time) (int, error) {
	n := 0
	for _, o := range inv.Objects {
		added, err := importChain(ctx, tx, o.ChainPEM, o.Provider)
		if err != nil {
			return n, err
		}
		n += added
	}
	return n, s.syncCloud(ctx, tx, owner, inv, now)
}

// stripChains returns a copy of inv without PEMs, which live in the
// certificate inventory instead.
func stripChains(inv *agentproto.CloudInventory) *agentproto.CloudInventory {
	c := *inv
	c.Objects = slices.Clone(c.Objects)
	for i := range c.Objects {
		c.Objects[i].ChainPEM = ""
	}
	return &c
}

func hasDuplicates(s []string) bool {
	seen := map[string]bool{}
	for _, v := range s {
		if seen[v] {
			return true
		}
		seen[v] = true
	}
	return false
}
