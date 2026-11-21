// Package agentpki manages the control plane's internal agent CA and task
// signing key. These keys identify agents and authorize tasks;
// they are separate from any customer PKI and stored encrypted with the KEK.
package agentpki

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/kek"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentCertLifetime is short so a leaked agent key has limited value.
const AgentCertLifetime = 7 * 24 * time.Hour

// PKI holds the loaded keys.
type PKI struct {
	CA      *x509.Certificate
	caKey   *ecdsa.PrivateKey
	TaskKey ed25519.PrivateKey
	// KEK protects other secrets the control plane stores (ADR-0009).
	KEK *kek.KEK
}

// CAFingerprint is the SHA-256 of the CA certificate, used by agents to pin
// the server on first contact (printed in the enrollment command).
func (p *PKI) CAFingerprint() string {
	s := sha256.Sum256(p.CA.Raw)
	return "sha256:" + hex.EncodeToString(s[:])
}

// CAPEM returns the CA certificate in PEM form.
func (p *PKI) CAPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.CA.Raw}))
}

// TaskPublicKey returns the task-verification key agents pin.
func (p *PKI) TaskPublicKey() ed25519.PublicKey { return p.TaskKey.Public().(ed25519.PublicKey) }

// LoadOrCreate loads the keys, generating them on first use. Concurrent
// replicas race safely: INSERT ... ON CONFLICT DO NOTHING, then re-read.
func LoadOrCreate(ctx context.Context, pool *pgxpool.Pool, k *kek.KEK) (*PKI, error) {
	p := &PKI{KEK: k}
	caDER, caKeyDER, err := loadOrCreate(ctx, pool, k, "agent-ca", func() ([]byte, []byte, []byte, error) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, nil, err
		}
		tmpl := &x509.Certificate{
			SerialNumber: randSerial(), Subject: pkix.Name{CommonName: "certloom internal agent CA", Organization: []string{"certloom"}},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * 365 * 24 * time.Hour),
			IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true,
			KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			return nil, nil, nil, err
		}
		kd, err := x509.MarshalPKCS8PrivateKey(key)
		pub, _ := x509.MarshalPKIXPublicKey(&key.PublicKey)
		return der, pub, kd, err
	})
	if err != nil {
		return nil, err
	}
	if p.CA, err = x509.ParseCertificate(caDER); err != nil {
		return nil, err
	}
	ck, err := x509.ParsePKCS8PrivateKey(caKeyDER)
	if err != nil {
		return nil, err
	}
	var ok bool
	if p.caKey, ok = ck.(*ecdsa.PrivateKey); !ok {
		return nil, errors.New("agent CA key is not ECDSA")
	}
	_, tkDER, err := loadOrCreate(ctx, pool, k, "task-signing", func() ([]byte, []byte, []byte, error) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		return nil, pub, priv.Seed(), err
	})
	if err != nil {
		return nil, err
	}
	p.TaskKey = ed25519.NewKeyFromSeed(tkDER)
	return p, nil
}

func loadOrCreate(ctx context.Context, pool *pgxpool.Pool, k *kek.KEK, name string,
	gen func() (certDER, pub, priv []byte, err error)) ([]byte, []byte, error) {
	read := func() ([]byte, []byte, error) {
		var cert, ct []byte
		err := pool.QueryRow(ctx, `SELECT cert_der, key_ciphertext FROM system_keys WHERE name = $1`, name).Scan(&cert, &ct)
		if err != nil {
			return nil, nil, err
		}
		pt, err := k.Open(ct, "system_keys:"+name)
		return cert, pt, err
	}
	cert, priv, err := read()
	if err == nil {
		return cert, priv, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, nil, err
	}
	certDER, pub, privDER, err := gen()
	if err != nil {
		return nil, nil, err
	}
	ct, err := k.Seal(privDER, "system_keys:"+name)
	if err != nil {
		return nil, nil, err
	}
	if _, err := pool.Exec(ctx, `INSERT INTO system_keys (name, cert_der, public_key, key_ciphertext) VALUES ($1,$2,$3,$4)
		ON CONFLICT (name) DO NOTHING`, name, certDER, pub, ct); err != nil {
		return nil, nil, err
	}
	return read()
}

func randSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}

// IssueAgentCert signs an agent CSR. The identity comes from the arguments,
// never from the CSR's requested names.
func (p *PKI) IssueAgentCert(csrPEM, orgID, agentID string) (*x509.Certificate, []byte, error) {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil || b.Type != "CERTIFICATE REQUEST" {
		return nil, nil, errors.New("csr_pem must be a PEM CERTIFICATE REQUEST")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return nil, nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, nil, fmt.Errorf("csr signature: %w", err)
	}
	switch k := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if k.Curve.Params().BitSize < 256 {
			return nil, nil, errors.New("agent key must be ECDSA P-256 or stronger, or Ed25519")
		}
	case ed25519.PublicKey:
	default:
		return nil, nil, errors.New("agent key must be ECDSA P-256 or stronger, or Ed25519")
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(), Subject: pkix.Name{CommonName: "certloom-agent " + agentID, Organization: []string{orgID}},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(AgentCertLifetime),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{agentproto.AgentURI(orgID, agentID)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.CA, csr.PublicKey, p.caKey)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), err
}

// ServerCert issues the agent listener's TLS certificate for the given names.
func (p *PKI) ServerCert(names []string) (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: randSerial(), Subject: pkix.Name{CommonName: "certloom agent endpoint"},
		NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(90 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, p.CA, &key.PublicKey, p.caKey)
	if err != nil {
		return nil, nil, err
	}
	kd, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	// Send the CA too: an enrolling agent knows only the CA's SHA-256 and pins
	// the presented CA certificate against it.
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), []byte(p.CAPEM())...)
	return chain, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: kd}), nil
}
