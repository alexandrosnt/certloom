package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

// ACME External Account Binding (ADR-0019). HMAC keys are encrypted with the
// KEK, never returned, and reach an agent only sealed to it inside an issue
// task, and only until the agent reports its account as registered.

// eabMinValidity is how long a single-use key must stay valid when it is
// claimed, so it does not expire while the issue task waits for the agent.
const eabMinValidity = 2 * time.Hour

// eabExpiryWarning is when a claimed, unused key starts to raise a finding.
const eabExpiryWarning = 48 * time.Hour

func eabIssuerAAD(issuerID string) string { return "issuer_eab:" + issuerID }
func eabKeyAAD(keyID string) string       { return "eab_key:" + keyID }

// checkHMAC accepts the base64url HMAC keys CAs issue (padding optional).
func checkHMAC(v secret.Value) error {
	s := strings.TrimSpace(string(v.Reveal()))
	b, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(b) < 16 {
		return invalid("EAB HMAC key must be base64url and at least 16 bytes")
	}
	return nil
}

// EABInput sets an issuer's EAB mode. HMAC is only for mode reusable; when it
// is empty there, the stored key is kept.
type EABInput struct {
	Mode, KID string
	HMAC      secret.Value
}

// SetIssuerEAB changes an issuer's EAB mode and its reusable key.
func (s *Service) SetIssuerEAB(ctx context.Context, p authz.Principal, ref string, in EABInput) (iss *store.Issuer, err error) {
	if s.PKI == nil {
		return nil, ErrAgentsDisabled
	}
	in.KID = strings.TrimSpace(in.KID)
	switch in.Mode {
	case store.EABReusable:
		if in.KID == "" {
			return nil, invalid("mode reusable needs a key id")
		}
		if !in.HMAC.IsEmpty() {
			if err := checkHMAC(in.HMAC); err != nil {
				return nil, err
			}
		}
	case store.EABNone, store.EABSingleUse:
		if in.KID != "" || !in.HMAC.IsEmpty() {
			return nil, invalid("a key id and HMAC belong to mode reusable; add single-use keys with eab-key add")
		}
	default:
		return nil, invalid("mode must be none, reusable or single_use")
	}
	err = s.tx(ctx, p, authz.ManageIssuers, func(tx *store.Tx) error {
		if iss, err = tx.GetIssuer(ctx, ref); err != nil {
			return err
		}
		var ct []byte
		if !in.HMAC.IsEmpty() {
			if ct, err = s.PKI.KEK.Seal([]byte(strings.TrimSpace(string(in.HMAC.Reveal()))), eabIssuerAAD(iss.ID)); err != nil {
				return err
			}
		} else if in.Mode == store.EABReusable && (!iss.HasEABHMAC || iss.EABKID != in.KID) {
			return invalid("a new key id needs its HMAC key")
		}
		if err := tx.SetIssuerEAB(ctx, iss.ID, in.Mode, in.KID, ct, in.Mode != store.EABReusable); err != nil {
			return err
		}
		if iss, err = tx.GetIssuer(ctx, iss.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "issuers.set_eab", "issuer", iss.ID, map[string]any{"name": iss.Name, "mode": in.Mode,
			"kid": in.KID, "hmac_changed": ct != nil})
	})
	return iss, err
}

// AddEABKey adds a single-use key to an issuer's pool.
func (s *Service) AddEABKey(ctx context.Context, p authz.Principal, issuerRef, kid string, hmac secret.Value, expiresAt *time.Time) (k *store.EABKey, err error) {
	if s.PKI == nil {
		return nil, ErrAgentsDisabled
	}
	kid = strings.TrimSpace(kid)
	if kid == "" {
		return nil, invalid("key id is required")
	}
	if err := checkHMAC(hmac); err != nil {
		return nil, err
	}
	if expiresAt != nil && !expiresAt.After(s.now()) {
		return nil, invalid("key has already expired")
	}
	err = s.tx(ctx, p, authz.ManageIssuers, func(tx *store.Tx) error {
		iss, err := tx.GetIssuer(ctx, issuerRef)
		if err != nil {
			return err
		}
		if iss.EABMode != store.EABSingleUse {
			return invalid("issuer %s is not in EAB mode single_use", iss.Name)
		}
		k = &store.EABKey{ID: store.NewEABKeyID(), IssuerID: iss.ID, KID: kid, ExpiresAt: expiresAt}
		if k.HMACCiphertext, err = s.PKI.KEK.Seal([]byte(strings.TrimSpace(string(hmac.Reveal()))), eabKeyAAD(k.ID)); err != nil {
			return err
		}
		if err := tx.AddEABKey(ctx, k, p.Actor); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "issuers.eab_key_add", "issuer", iss.ID, map[string]any{"key": k.ID, "kid": kid, "expires_at": expiresAt})
	})
	return k, err
}

// ListEABKeys lists an issuer's single-use pool without the HMAC keys.
func (s *Service) ListEABKeys(ctx context.Context, p authz.Principal, issuerRef string) (out []*store.EABKey, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error {
		iss, err := tx.GetIssuer(ctx, issuerRef)
		if err != nil {
			return err
		}
		out, err = tx.ListEABKeys(ctx, iss.ID)
		return err
	})
	return out, err
}

// DeleteEABKey removes an unused or failed key from the pool.
func (s *Service) DeleteEABKey(ctx context.Context, p authz.Principal, issuerRef, keyRef string) error {
	return s.tx(ctx, p, authz.ManageIssuers, func(tx *store.Tx) error {
		iss, err := tx.GetIssuer(ctx, issuerRef)
		if err != nil {
			return err
		}
		k, err := tx.DeleteEABKey(ctx, iss.ID, keyRef)
		if err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "issuers.eab_key_delete", "issuer", iss.ID, map[string]any{"key": k.ID, "kid": k.KID})
	})
}

// eabNeed says whether an agent still has to register an account for an
// EAB issuer with a key from the control plane.
func eabNeed(iss *store.Issuer, a *store.Agent) bool {
	return !slices.Contains(a.Capabilities.ACMEAccounts, agentproto.AccountSlot(iss.ID)) &&
		!slices.Contains(a.Capabilities.LocalEAB, iss.DirectoryURL)
}

// eabPlan is the EAB part of an issue task, decided before the task exists.
type eabPlan struct {
	iss     *store.Issuer
	agentID string
	kid     string
	hmacCT  []byte
	aad     string
	keyID   string // single-use key, for the audit record
}

// planEAB picks the key an issue task will carry. It returns nil when the
// agent needs none, and a reason when the run cannot proceed.
func (s *Service) planEAB(ctx context.Context, tx *store.Tx, iss *store.Issuer, a *store.Agent) (*eabPlan, string, error) {
	if iss.EABMode == store.EABNone || !eabNeed(iss, a) {
		return nil, "", nil
	}
	if !a.Capabilities.AcceptsCentralEAB() {
		return nil, fmt.Sprintf("issuer %s needs External Account Binding, but agent %s refuses central EAB keys (or is too old) "+
			"and has no acme_eab entry for %s", iss.Name, a.Name, iss.DirectoryURL), nil
	}
	if iss.EABMode == store.EABReusable {
		if !iss.HasEABHMAC {
			return nil, "issuer " + iss.Name + " has EAB mode reusable but no key; set one with `certloom issuer set-eab`", nil
		}
		return &eabPlan{iss: iss, agentID: a.ID, kid: iss.EABKID, hmacCT: iss.EABHMACCiphertext, aad: eabIssuerAAD(iss.ID)}, "", nil
	}
	if used, err := tx.EABKeyConsumed(ctx, iss.ID, a.ID); err != nil || used {
		return nil, "", err // registered; the heartbeat has not caught up yet
	}
	k, err := tx.ClaimEABKey(ctx, iss.ID, a.ID, s.now().Add(eabMinValidity))
	if err != nil {
		return nil, "", err
	}
	if k == nil {
		return nil, "issuer " + iss.Name + " has no unused single-use EAB key left; add keys with `certloom issuer eab-key add`", nil
	}
	if k.ExpiresAt != nil && !k.ExpiresAt.After(s.now()) {
		// The agent never registered with its claimed key before it expired.
		if _, err := tx.FinishEABClaim(ctx, iss.ID, a.ID, "failed"); err != nil {
			return nil, "", err
		}
		return s.planEAB(ctx, tx, iss, a)
	}
	return &eabPlan{iss: iss, agentID: a.ID, kid: k.KID, hmacCT: k.HMACCiphertext, aad: eabKeyAAD(k.ID), keyID: k.ID}, "", nil
}

// sealEAB opens the stored HMAC and seals it to the agent for one task.
func (s *Service) sealEAB(ctx context.Context, tx *store.Tx, pl *eabPlan, a *store.Agent, runID, taskID string) (*agentproto.SealedEAB, error) {
	plain, err := s.PKI.KEK.Open(pl.hmacCT, pl.aad)
	if err != nil {
		return nil, fmt.Errorf("issuer %s: stored EAB key cannot be decrypted: %w", pl.iss.Name, err)
	}
	sealed, err := agentproto.SealSecret(a.Capabilities.SealKey, agentproto.SealEABInfo(a.ID, taskID, pl.iss.ID), plain)
	clear(plain)
	if err != nil {
		return nil, fmt.Errorf("issuer %s: %w", pl.iss.Name, err)
	}
	if err := s.systemAudit(ctx, tx, workflowActor, "issuers.eab_delivered", "issuer", pl.iss.ID,
		map[string]any{"name": pl.iss.Name, "kid": pl.kid, "key": pl.keyID, "agent": a.ID, "run": runID, "task": taskID}); err != nil {
		return nil, err
	}
	return &agentproto.SealedEAB{KID: pl.kid, Sealed: sealed}, nil
}

// eabRegistered records that an agent holds an account for an issuer slot:
// a single-use key it claimed is used up.
func (s *Service) eabRegistered(ctx context.Context, tx *store.Tx, agentID, slot string) error {
	issuerID, ok := strings.CutPrefix(slot, "issuer:")
	if !ok {
		return nil
	}
	k, err := tx.FinishEABClaim(ctx, issuerID, agentID, "consumed")
	if err != nil || k == nil {
		return err
	}
	return s.systemAudit(ctx, tx, "agent:"+agentID, "issuers.eab_key_consumed", "issuer", issuerID, map[string]any{"key": k.ID, "kid": k.KID})
}

// eabRejected records that the CA refused an agent's EAB key. A single-use
// key is marked failed so the next run claims another one.
func (s *Service) eabRejected(ctx context.Context, tx *store.Tx, issuerID, agentID string) error {
	k, err := tx.FinishEABClaim(ctx, issuerID, agentID, "failed")
	if err != nil || k == nil {
		return err
	}
	return s.systemAudit(ctx, tx, "agent:"+agentID, "issuers.eab_key_failed", "issuer", issuerID, map[string]any{"key": k.ID, "kid": k.KID})
}

// SweepEABPools raises findings for single-use pools that cannot cover the
// agents still waiting for a key, and for claimed keys about to expire.
func (s *Service) SweepEABPools(ctx context.Context) error {
	orgs, err := s.orgIDs(ctx)
	if err != nil {
		return err
	}
	for _, org := range orgs {
		err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
			issuers, err := tx.ListIssuers(ctx)
			if err != nil {
				return err
			}
			now := s.now()
			for i := range issuers {
				iss := &issuers[i]
				var current []checks.Finding
				if iss.EABMode == store.EABSingleUse {
					pool, err := tx.EABPoolStatus(ctx, iss, now.Add(eabMinValidity), now.Add(eabExpiryWarning), func(a *store.Agent) bool {
						return a.State == "active" && eabNeed(iss, a) && a.Capabilities.AcceptsCentralEAB()
					})
					if err != nil {
						return err
					}
					current = eabPoolFindings(iss, pool)
				}
				if _, err := tx.SyncFindings(ctx, "issuer", iss.ID, current, now); err != nil {
					return err
				}
			}
			return nil
		})
		if err != nil {
			return fmt.Errorf("org %s: %w", org, err)
		}
	}
	return nil
}

func eabPoolFindings(iss *store.Issuer, pool *store.EABPool) []checks.Finding {
	var out []checks.Finding
	if pool.Waiting > pool.Available {
		out = append(out, checks.New(checks.CheckEABPool, checks.Critical,
			fmt.Sprintf("issuer %s: %d agent(s) need a single-use EAB key, %d available", iss.Name, pool.Waiting, pool.Available),
			"request new EAB keys from the CA and add them with `certloom issuer eab-key add`", iss.ID))
	}
	for _, k := range pool.ExpiringClaims {
		out = append(out, checks.New(checks.CheckEABKeyExpiring, checks.Warning,
			fmt.Sprintf("issuer %s: EAB key %s, claimed by agent %s, expires %s before the account is registered",
				iss.Name, k.KID, deref(k.AgentID), k.ExpiresAt.UTC().Format(time.RFC3339)),
			"check why the agent has not completed issuance; an expired key is replaced from the pool", iss.ID, k.ID))
	}
	return out
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
