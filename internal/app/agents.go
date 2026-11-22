package app

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/audit"
	"github.com/alexandrosnt/certloom/internal/authz"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/ids"
	"github.com/alexandrosnt/certloom/internal/jobs"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
)

// ErrAgentsDisabled is returned when the agent subsystem is not configured.
var ErrAgentsDisabled = errors.New("agent support is not enabled on this server (configure CERTLOOM_KEK and CERTLOOM_AGENT_LISTEN)")

// AgentIdentity is an authenticated agent (from its mTLS certificate).
type AgentIdentity struct{ OrgID, AgentID string }

func (s *Service) systemAudit(ctx context.Context, tx *store.Tx, actor, action, rtype, rid string, detail map[string]any) error {
	return audit.Write(ctx, tx, &audit.Event{OrgID: tx.OrgID, Actor: actor, Action: action, ResourceType: rtype, ResourceID: rid,
		RequestID: RequestID(ctx), Detail: detail})
}

// EnrollmentToken is what an owner hands to a new host.
type EnrollmentToken struct {
	ID        string    `json:"id"`
	Token     string    `json:"token"`
	CAHash    string    `json:"ca_hash"`
	ExpiresAt time.Time `json:"expires_at"`
	Command   string    `json:"command"`
}

// CreateEnrollmentToken issues a one-time enrollment token (TTL <= 1h).
func (s *Service) CreateEnrollmentToken(ctx context.Context, p authz.Principal, nameHint string, ttl time.Duration, server string) (*EnrollmentToken, error) {
	if s.PKI == nil {
		return nil, ErrAgentsDisabled
	}
	if ttl <= 0 || ttl > time.Hour {
		ttl = time.Hour
	}
	var out EnrollmentToken
	err := s.tx(ctx, p, authz.ManageAgents, func(tx *store.Tx) error {
		id, tok, err := tx.CreateEnrollmentToken(ctx, nameHint, p.Actor, ttl)
		if err != nil {
			return err
		}
		out = EnrollmentToken{ID: id, Token: tok.RevealString(), CAHash: s.PKI.CAFingerprint(), ExpiresAt: time.Now().Add(ttl).UTC()}
		out.Command = fmt.Sprintf("certloom-agent enroll --server %s --ca-hash %s --token-stdin", server, out.CAHash)
		return s.audit(ctx, tx, p, "agents.enrollment_token.create", "enrollment_token", id, map[string]any{"name_hint": nameHint, "ttl_seconds": int(ttl.Seconds())})
	})
	return &out, err
}

// Enroll exchanges a one-time token and CSR for an agent identity.
func (s *Service) Enroll(ctx context.Context, req agentproto.EnrollRequest) (*agentproto.EnrollResponse, error) {
	if s.PKI == nil {
		return nil, ErrAgentsDisabled
	}
	org, ok := store.ParseEnrollOrg(req.Token)
	if !ok {
		return nil, store.ErrInvalidToken
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = req.Hostname
	}
	if name == "" || len(name) > 100 {
		return nil, invalid("agent name required (<= 100 characters)")
	}
	var resp agentproto.EnrollResponse
	err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
		agentID := ids.New("agt")
		hint, err := tx.ConsumeEnrollmentToken(ctx, req.Token, agentID)
		if err != nil {
			return err
		}
		if hint != "" && hint != name {
			return invalid("this token was issued for agent %q", hint)
		}
		cert, certPEM, err := s.PKI.IssueAgentCert(req.CSRPEM, org, agentID)
		if err != nil {
			return invalid("%v", err)
		}
		if err := tx.CreateAgent(ctx, agentID, name, req.Hostname, cert.SerialNumber.Text(16), cert.NotAfter); err != nil {
			return err
		}
		resp = agentproto.EnrollResponse{AgentID: agentID, OrgID: org, CertPEM: string(certPEM), CAPEM: s.PKI.CAPEM(),
			TaskPublicKey: s.PKI.TaskPublicKey()}
		if err := s.emit(ctx, tx, "agent.enrolled", agentID, map[string]any{"agent_id": agentID, "name": name, "hostname": req.Hostname}); err != nil {
			return err
		}
		return s.systemAudit(ctx, tx, "agent:"+agentID, "agents.enroll", "agent", agentID, map[string]any{"name": name, "hostname": req.Hostname})
	})
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

// AuthenticateAgent maps a verified client certificate to an active agent.
func (s *Service) AuthenticateAgent(ctx context.Context, cert *x509.Certificate) (AgentIdentity, error) {
	for _, u := range cert.URIs {
		org, agent, ok := agentproto.ParseAgentURI(u)
		if !ok {
			continue
		}
		var a *store.Agent
		err := s.DB.WithOrg(ctx, org, func(tx *store.Tx) (err error) { a, err = tx.GetAgent(ctx, agent); return err })
		if err != nil || a.ID != agent || a.State != "active" {
			return AgentIdentity{}, store.ErrInvalidToken
		}
		return AgentIdentity{OrgID: org, AgentID: agent}, nil
	}
	return AgentIdentity{}, store.ErrInvalidToken
}

// RenewAgentCert issues a fresh identity certificate for an authenticated agent.
func (s *Service) RenewAgentCert(ctx context.Context, id AgentIdentity, csrPEM string) (string, error) {
	var out string
	err := s.DB.WithOrg(ctx, id.OrgID, func(tx *store.Tx) error {
		cert, pemb, err := s.PKI.IssueAgentCert(csrPEM, id.OrgID, id.AgentID)
		if err != nil {
			return invalid("%v", err)
		}
		if err := tx.RotateAgentCert(ctx, id.AgentID, cert.SerialNumber.Text(16), cert.NotAfter); err != nil {
			return err
		}
		out = string(pemb)
		return s.systemAudit(ctx, tx, "agent:"+id.AgentID, "agents.renew_identity", "agent", id.AgentID, map[string]any{"not_after": cert.NotAfter})
	})
	return out, err
}

// AgentHeartbeat records liveness and the agent's locally configured targets.
func (s *Service) AgentHeartbeat(ctx context.Context, id AgentIdentity, hb agentproto.Heartbeat) error {
	return s.DB.WithOrg(ctx, id.OrgID, func(tx *store.Tx) error {
		if err := tx.RecordHeartbeat(ctx, id.AgentID, hb); err != nil {
			return err
		}
		for _, slot := range hb.ACMEAccounts {
			if err := s.eabRegistered(ctx, tx, id.AgentID, slot); err != nil {
				return err
			}
		}
		return nil
	})
}

// AgentPoll returns tasks for the agent, waiting up to wait for new ones.
func (s *Service) AgentPoll(ctx context.Context, id AgentIdentity, wait time.Duration) ([]agentproto.Envelope, error) {
	deadline := time.Now().Add(wait)
	for {
		var envs []agentproto.Envelope
		err := s.DB.WithOrg(ctx, id.OrgID, func(tx *store.Tx) (err error) { envs, err = tx.PendingTasks(ctx, id.AgentID); return err })
		if err != nil || len(envs) > 0 || !time.Now().Before(deadline) {
			return envs, err
		}
		select {
		case <-ctx.Done():
			return nil, nil
		case <-time.After(time.Second):
		}
	}
}

// AgentResult records a task result and advances the owning workflow.
func (s *Service) AgentResult(ctx context.Context, id AgentIdentity, taskID string, res agentproto.Result) error {
	return s.DB.WithOrg(ctx, id.OrgID, func(tx *store.Tx) error {
		task, err := tx.GetTask(ctx, taskID)
		if err != nil {
			return err
		}
		if task.AgentID != id.AgentID {
			return store.ErrNotFound // never reveal other agents' tasks
		}
		runID, changed, err := tx.CompleteTask(ctx, id.AgentID, taskID, res)
		if err != nil || !changed {
			return err // duplicate result: idempotent no-op
		}
		if task.Type == agentproto.TaskInventoryScan && res.OK {
			if err := s.importInventory(ctx, tx, id, res.Output); err != nil {
				return err
			}
		}
		if task.Type == agentproto.TaskTrustApply {
			if err := s.importTrustResult(ctx, tx, id, task, res); err != nil {
				return err
			}
		}
		if runID != nil {
			// Keyed by task: a run-keyed job could be deduplicated against an
			// advance that is executing right now and miss this result.
			_, err = jobs.Enqueue(ctx, tx, id.OrgID, JobKindAdvance, *runID+":"+taskID, map[string]string{"run_id": *runID}, time.Time{})
		}
		return err
	})
}

func (s *Service) importInventory(ctx context.Context, tx *store.Tx, id AgentIdentity, out json.RawMessage) error {
	var inv agentproto.InventoryOutput
	if err := json.Unmarshal(out, &inv); err != nil {
		return nil // malformed agent output is ignored, not fatal
	}
	n := 0
	for _, f := range inv.Certificates {
		parsed, err := certparse.Parse([]byte(f.ChainPEM), secret.Value{})
		if err != nil {
			continue
		}
		for _, c := range parsed.Certificates {
			if ins, err := tx.UpsertCertificate(ctx, c, "agent"); err != nil {
				return err
			} else if ins {
				n++
			}
		}
	}
	observed, err := s.importObservations(ctx, tx, id.AgentID, inv)
	if err != nil {
		return err
	}
	n += observed
	return s.systemAudit(ctx, tx, "agent:"+id.AgentID, "agents.inventory", "agent", id.AgentID, map[string]any{
		"files": len(inv.Certificates), "new_certificates": n, "certbot_lineages": len(inv.Certbot),
		"iis_bindings": len(inv.IIS), "win_acme_renewals": len(inv.WinACME), "kubernetes": inv.Kubernetes != nil, "cloud_objects": cloudCount(inv.Cloud)})
}

// ListAgents lists agents with derived health.
func (s *Service) ListAgents(ctx context.Context, p authz.Principal) (out []*store.Agent, err error) {
	err = s.tx(ctx, p, authz.ViewInventory, func(tx *store.Tx) error { out, err = tx.ListAgents(ctx); return err })
	return out, err
}

// RevokeAgent revokes an agent immediately; its pending tasks expire.
func (s *Service) RevokeAgent(ctx context.Context, p authz.Principal, ref string) error {
	return s.tx(ctx, p, authz.ManageAgents, func(tx *store.Tx) error {
		a, err := tx.GetAgent(ctx, ref)
		if err != nil {
			return err
		}
		if err := tx.RevokeAgent(ctx, a.ID); err != nil {
			return err
		}
		if err := s.emit(ctx, tx, "agent.revoked", a.ID, map[string]any{"agent_id": a.ID, "name": a.Name, "by": p.Actor}); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "agents.revoke", "agent", a.ID, map[string]any{"name": a.Name})
	})
}

// RequestInventoryScan asks an agent to report certificates found on its host.
func (s *Service) RequestInventoryScan(ctx context.Context, p authz.Principal, ref string) (string, error) {
	var taskID string
	err := s.tx(ctx, p, authz.ImportCerts, func(tx *store.Tx) error {
		a, err := tx.GetAgent(ctx, ref)
		if err != nil {
			return err
		}
		if taskID, err = s.queueInventory(ctx, tx, a.ID); err != nil {
			return err
		}
		return s.audit(ctx, tx, p, "agents.inventory_requested", "agent", a.ID, nil)
	})
	return taskID, err
}

// queueInventory signs and queues an inventory task for an agent.
func (s *Service) queueInventory(ctx context.Context, tx *store.Tx, agentID string) (string, error) {
	t, err := s.signTask(tx.OrgID, agentID, agentproto.TaskInventoryScan, "", 0, struct{}{}, time.Hour)
	if err != nil {
		return "", err
	}
	env, err := agentproto.Sign(s.PKI.TaskKey, t)
	if err != nil {
		return "", err
	}
	return t.ID, tx.InsertTask(ctx, t, env, nil)
}

func (s *Service) signTask(org, agent, typ, target string, seq int64, payload any, ttl time.Duration) (agentproto.Task, error) {
	if s.PKI == nil {
		return agentproto.Task{}, ErrAgentsDisabled
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return agentproto.Task{}, err
	}
	return agentproto.Task{ID: ids.New("tsk"), OrgID: org, AgentID: agent, Type: typ, Target: target, Seq: seq,
		NotAfter: time.Now().Add(ttl).UTC(), Nonce: ids.New("n"), Payload: b}, nil
}

func pemEncode(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
