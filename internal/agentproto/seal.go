package agentproto

import (
	"crypto/hpke"
	"errors"
)

// Secrets for an agent (central DNS credentials, ADR-0018) are sealed with
// HPKE (RFC 9180) to a key pair that only that agent holds. The hybrid
// post-quantum KEM is used because sealed secrets are kept in the task table.
var (
	sealKEM  = hpke.MLKEM768X25519()
	sealKDF  = hpke.HKDFSHA256()
	sealAEAD = hpke.AES256GCM()
)

// NewSealKey generates an agent's sealing key and returns the private key
// bytes (kept on the agent) and the public key bytes (sent in heartbeats).
func NewSealKey() (priv, pub []byte, err error) {
	k, err := sealKEM.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	if priv, err = k.Bytes(); err != nil {
		return nil, nil, err
	}
	return priv, k.PublicKey().Bytes(), nil
}

// SealInfo binds a sealed secret to one agent, task and solver, so it cannot
// be replayed into another task or opened as another solver's secret.
func SealInfo(agentID, taskID, solverID string) []byte {
	return []byte("certloom dns secret v1\x00" + agentID + "\x00" + taskID + "\x00" + solverID)
}

// SealSecret encrypts plaintext to an agent's public sealing key.
func SealSecret(pub, info, plaintext []byte) ([]byte, error) {
	pk, err := sealKEM.NewPublicKey(pub)
	if err != nil {
		return nil, errors.New("agent sealing key is invalid")
	}
	return hpke.Seal(pk, sealKDF, sealAEAD, info, plaintext)
}

// OpenSecret decrypts a secret sealed to this agent.
func OpenSecret(priv, info, sealed []byte) ([]byte, error) {
	k, err := sealKEM.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return hpke.Open(k, sealKDF, sealAEAD, info, sealed)
}

// SealPublicKey returns the public key for a private sealing key.
func SealPublicKey(priv []byte) ([]byte, error) {
	k, err := sealKEM.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return k.PublicKey().Bytes(), nil
}

// SealEABInfo binds a sealed EAB HMAC to one agent, task and issuer. The
// label differs from SealInfo so a DNS secret never opens as an EAB key.
func SealEABInfo(agentID, taskID, issuerID string) []byte {
	return []byte("certloom eab v1\x00" + agentID + "\x00" + taskID + "\x00" + issuerID)
}

// AccountSlot is the account slot of an issuer that uses EAB.
func AccountSlot(issuerID string) string { return "issuer:" + issuerID }
