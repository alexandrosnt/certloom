package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/privateca"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

// Vault PKI and step-ca issuers (ADR-0028). The agent sends a CSR, the
// control plane checks it and has it signed. The issuer credential is stored
// under the KEK, bound to the issuer id, and never returned.

func issuerCredentialAAD(issuerID string) string { return "issuer_credential:" + issuerID }

var vaultTTL = regexp.MustCompile(`^[1-9][0-9]{0,6}[smhd]$`)

// checkNativeIssuer validates a Vault or step-ca issuer and its credential
// and clears the ACME-only fields.
func checkNativeIssuer(i *store.Issuer, cred secret.Value) error {
	u, err := url.Parse(i.DirectoryURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" ||
		(u.Path != "" && u.Path != "/") {
		return invalid("url must be an https URL with no path, e.g. https://ca.example:8200")
	}
	i.DirectoryURL = strings.TrimSuffix(i.DirectoryURL, "/")
	if err := checkCABundle(i.CABundle); err != nil {
		return err
	}
	if i.AgreeTOS || i.Email != "" || i.Profile != "" {
		return invalid("agree_tos, email and profile belong to ACME issuers")
	}
	if cred.IsEmpty() {
		return invalid("a %s issuer needs a credential", i.Kind)
	}
	st := &i.Settings
	switch i.Kind {
	case store.IssuerVault:
		if !privateca.ValidVaultPath(st.Mount, true) {
			return invalid("vault mount is required (letters, digits, -_. and / between segments)")
		}
		if !privateca.ValidVaultPath(st.Role, false) {
			return invalid("vault role is required (letters, digits, -_.)")
		}
		if st.IssuerRef != "" && !privateca.ValidVaultPath(st.IssuerRef, false) {
			return invalid("vault issuer_ref may contain letters, digits, -_.")
		}
		if st.Namespace != "" && !privateca.ValidVaultPath(st.Namespace, true) {
			return invalid("vault namespace may contain letters, digits, -_. and /")
		}
		if st.TTL != "" && !vaultTTL.MatchString(st.TTL) {
			return invalid("vault ttl must look like 720h or 30d")
		}
		switch st.AuthMethod {
		case privateca.VaultAppRole:
			if strings.TrimSpace(st.RoleID) == "" {
				return invalid("vault auth approle needs role_id (the credential is the secret_id)")
			}
			if st.AuthMount != "" && !privateca.ValidVaultPath(st.AuthMount, true) {
				return invalid("vault auth_mount may contain letters, digits, -_. and /")
			}
		case privateca.VaultToken:
			if st.RoleID != "" || st.AuthMount != "" {
				return invalid("role_id and auth_mount belong to auth approle")
			}
		default:
			return invalid("vault auth_method must be approle or token")
		}
		if st.Provisioner != "" || st.KeyID != "" {
			return invalid("provisioner and key_id belong to step-ca issuers")
		}
	case store.IssuerStepCA:
		if strings.TrimSpace(st.Provisioner) == "" {
			return invalid("step-ca provisioner name is required")
		}
		kid, err := privateca.ParseProvisionerKey(cred.Reveal())
		if err != nil {
			return invalid("%s", err.Error())
		}
		if st.KeyID == "" {
			st.KeyID = kid
		}
		if st.KeyID == "" {
			return invalid("the provisioner key has no kid; set key_id")
		}
		if st.Mount != "" || st.Role != "" || st.IssuerRef != "" || st.Namespace != "" || st.TTL != "" ||
			st.AuthMethod != "" || st.AuthMount != "" || st.RoleID != "" {
			return invalid("mount, role, issuer_ref, namespace, ttl and auth settings belong to vault issuers")
		}
	default:
		return invalid("kind must be acme, vault or stepca")
	}
	return nil
}

// checkCABundle requires at least one certificate and nothing else.
func checkCABundle(b string) error {
	rest := []byte(b)
	n := 0
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			return invalid("ca_bundle may only contain certificates")
		}
		if _, err := x509.ParseCertificate(blk.Bytes); err != nil {
			return invalid("ca_bundle: %s", err.Error())
		}
		n++
	}
	if n == 0 || strings.TrimSpace(string(rest)) != "" {
		return invalid("ca_bundle must be the PEM certificates trusted for TLS to the CA")
	}
	return nil
}

// SetIssuerCredential replaces the credential of a Vault or step-ca issuer.
func (s *Service) SetIssuerCredential(ctx context.Context, p authz.Principal, ref string, cred secret.Value) (iss *store.Issuer, err error) {
	if s.PKI == nil {
		return nil, ErrAgentsDisabled
	}
	if cred.IsEmpty() {
		return nil, invalid("credential is required")
	}
	err = s.tx(ctx, p, authz.ManageIssuers, func(tx *store.Tx) error {
		if iss, err = tx.GetIssuer(ctx, ref); err != nil {
			return err
		}
		if !iss.Native() {
			return invalid("issuer %s is an ACME issuer; use set-eab for its account binding", iss.Name)
		}
		if iss.Kind == store.IssuerStepCA {
			kid, err := privateca.ParseProvisionerKey(cred.Reveal())
			if err != nil {
				return invalid("%s", err.Error())
			}
			if kid != "" && kid != iss.Settings.KeyID {
				return invalid("the new key's kid %q is not the issuer's key_id %q; create a new issuer for a new provisioner key", kid, iss.Settings.KeyID)
			}
		}
		ct, err := s.PKI.KEK.Seal(cred.Reveal(), issuerCredentialAAD(iss.ID))
		if err != nil {
			return err
		}
		if err := tx.SetIssuerCredential(ctx, iss.ID, ct); err != nil {
			return err
		}
		if iss, err = tx.GetIssuer(ctx, iss.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "issuers.set_credential", "issuer", iss.ID, map[string]any{"name": iss.Name})
	})
	return iss, err
}

// NewCASigner builds the client for a Vault or step-ca issuer.
func NewCASigner(iss *store.Issuer, cred secret.Value) (privateca.Signer, error) {
	hc, err := privateca.HTTPClient(iss.CABundle)
	if err != nil {
		return nil, err
	}
	st := iss.Settings
	switch iss.Kind {
	case store.IssuerVault:
		return &privateca.Vault{Addr: iss.DirectoryURL, Mount: st.Mount, Role: st.Role, IssuerRef: st.IssuerRef, Namespace: st.Namespace,
			TTL: st.TTL, AuthMethod: st.AuthMethod, AuthMount: st.AuthMount, RoleID: st.RoleID, Secret: cred, HTTP: hc}, nil
	case store.IssuerStepCA:
		return &privateca.StepCA{URL: iss.DirectoryURL, Provisioner: st.Provisioner, KeyID: st.KeyID, JWK: cred, HTTP: hc}, nil
	}
	return nil, errors.New("issuer kind " + iss.Kind + " does not sign CSRs")
}

// signResult is the outcome of one signing call.
type signResult struct {
	chain string
	err   error
}

// externalSign calls the CA for a run in state signing. It runs before the
// advance transaction, so no lock is held during network I/O. A run that
// moved on meanwhile discards the result in advance.
func (s *Service) externalSign(ctx context.Context, org, runID string) (*signResult, error) {
	var iss *store.Issuer
	var sans []string
	var csrPEM string
	var cred secret.Value
	err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
		r, err := tx.GetRun(ctx, runID, false)
		if err != nil || r.State != store.RunSigning || r.CurrentTaskID == nil {
			return err
		}
		d, err := tx.GetDeployment(ctx, r.DeploymentID, false)
		if err != nil {
			return err
		}
		t, err := tx.GetTask(ctx, *r.CurrentTaskID)
		if err != nil {
			return err
		}
		var out agentproto.CSROutput
		if err := json.Unmarshal(t.Result, &out); err != nil {
			return err
		}
		if iss, err = tx.GetIssuer(ctx, d.IssuerID); err != nil {
			return err
		}
		sans, csrPEM = d.SANs, out.CSRPEM
		return nil
	})
	if err != nil || iss == nil {
		return nil, err
	}
	if !iss.Native() || !iss.HasCredential {
		return &signResult{err: &privateca.Error{Permanent: true, Msg: "issuer " + iss.Name + " has no credential"}}, nil
	}
	if s.PKI == nil {
		return nil, ErrAgentsDisabled
	}
	plain, err := s.PKI.KEK.Open(iss.CredentialCiphertext, issuerCredentialAAD(iss.ID))
	if err != nil {
		return &signResult{err: &privateca.Error{Permanent: true, Msg: "stored credential cannot be decrypted: " + err.Error()}}, nil
	}
	cred = secret.New(plain)
	clear(plain)
	build := s.CASigner
	if build == nil {
		build = NewCASigner
	}
	signer, err := build(iss, cred)
	if err != nil {
		return &signResult{err: &privateca.Error{Permanent: true, Msg: err.Error()}}, nil
	}
	chain, err := signer.Sign(ctx, csrPEM, sans)
	return &signResult{chain: chain, err: err}, nil
}
