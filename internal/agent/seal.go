package agent

import (
	"errors"
	"os"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// The sealing key receives secrets from the control plane (ADR-0018). It is
// separate from the TLS identity key and the task-verification key, never
// leaves this host, and is replaced whenever the identity is renewed. The
// previous key is kept so tasks sealed just before a rotation still open.

func (a *Agent) loadSealKey() error {
	b, err := os.ReadFile(a.path("seal.key"))
	if errors.Is(err, os.ErrNotExist) {
		return a.rotateSealKey()
	}
	if err != nil {
		return err
	}
	pub, err := agentproto.SealPublicKey(b)
	if err != nil {
		return err
	}
	a.mu.Lock()
	a.sealPriv, a.sealPub = b, pub
	a.mu.Unlock()
	if prev, err := os.ReadFile(a.path("seal.key.prev")); err == nil {
		a.mu.Lock()
		a.sealPrev = prev
		a.mu.Unlock()
	}
	return nil
}

func (a *Agent) rotateSealKey() error {
	priv, pub, err := agentproto.NewSealKey()
	if err != nil {
		return err
	}
	a.mu.Lock()
	old := a.sealPriv
	a.mu.Unlock()
	if old != nil {
		if err := writeAtomic(a.path("seal.key.prev"), old, 0o600); err != nil {
			return err
		}
	}
	if err := writeAtomic(a.path("seal.key"), priv, 0o600); err != nil {
		return err
	}
	a.mu.Lock()
	a.sealPrev, a.sealPriv, a.sealPub = old, priv, pub
	a.mu.Unlock()
	return nil
}

// openSecret opens a secret sealed to this agent with the current key, or
// with the previous one for tasks sealed before the last rotation.
func (a *Agent) openSecret(info, sealed []byte) ([]byte, error) {
	a.mu.Lock()
	cur, prev := a.sealPriv, a.sealPrev
	a.mu.Unlock()
	b, err := agentproto.OpenSecret(cur, info, sealed)
	if err != nil && prev != nil {
		b, err = agentproto.OpenSecret(prev, info, sealed)
	}
	return b, err
}
