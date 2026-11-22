package main

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"

	"github.com/alexandrosnt/certloom/internal/pluginstore"
)

// trustPolicy verifies package signatures against the plugins.trust entries
// of the agent config.
type trustPolicy struct {
	cfg *pluginstore.Config
	// keyless is the Sigstore trusted root for keyless entries, loaded on
	// first use: plugins.trusted_root if set, else the public-good instance
	// through its TUF repository.
	keyless root.TrustedMaterial
	// keylessChecks overrides keylessVerifierOptions in tests.
	keylessChecks []verify.VerifierOption
}

// keylessVerifierOptions are the checks cosign verify-blob makes: certificate
// chain to Fulcio, an SCT from a CT log, a transparency log entry, and a
// signing time inside the certificate's validity.
func keylessVerifierOptions() []verify.VerifierOption {
	return []verify.VerifierOption{verify.WithSignedCertificateTimestamps(1), verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1)}
}

// signer is who signed a package, as recorded in install.json.
type signer struct {
	Trust    string // trust entry name
	Identity string // certificate identity, or "key sha256:<fingerprint>"
}

func (p *trustPolicy) keylessRoot() (root.TrustedMaterial, error) {
	if p.keyless != nil {
		return p.keyless, nil
	}
	var err error
	if p.cfg.TrustedRoot != "" {
		var b []byte
		if b, err = os.ReadFile(p.cfg.TrustedRoot); err != nil {
			return nil, err
		}
		p.keyless, err = root.NewTrustedRootFromJSON(b)
	} else {
		p.keyless, err = root.FetchTrustedRoot()
	}
	if err != nil {
		return nil, fmt.Errorf("sigstore trusted root: %w", err)
	}
	return p.keyless, nil
}

// verify returns the first trust entry whose publisher signed the archive
// with this SHA-256 digest.
func (p *trustPolicy) verify(entity verify.SignedEntity, digest []byte) (signer, error) {
	if p.cfg == nil || len(p.cfg.Trust) == 0 {
		return signer{}, errors.New("the agent config has no plugins.trust entries, so no package can be trusted")
	}
	var fails []string
	for _, pub := range p.cfg.Trust {
		id, err := p.verifyWith(pub, entity, digest)
		if err == nil {
			return signer{Trust: pub.Name, Identity: id}, nil
		}
		fails = append(fails, pub.Name+": "+err.Error())
	}
	return signer{}, fmt.Errorf("package is not signed by a trusted publisher (%s)", strings.Join(fails, "; "))
}

func (p *trustPolicy) verifyWith(pub pluginstore.Publisher, entity verify.SignedEntity, digest []byte) (string, error) {
	artifact := verify.WithArtifactDigest("sha256", digest)
	if k := pub.Keyless; k != nil {
		tm, err := p.keylessRoot()
		if err != nil {
			return "", err
		}
		id, err := verify.NewShortCertificateIdentity(k.Issuer, "", k.Identity, k.IdentityRegexp)
		if err != nil {
			return "", err
		}
		opts := p.keylessChecks
		if opts == nil {
			opts = keylessVerifierOptions()
		}
		v, err := verify.NewVerifier(tm, opts...)
		if err != nil {
			return "", err
		}
		res, err := v.Verify(entity, verify.NewPolicy(artifact, verify.WithCertificateIdentity(id)))
		if err != nil {
			return "", err
		}
		return res.Signature.Certificate.SubjectAlternativeName, nil
	}
	b, err := os.ReadFile(pub.PublicKey)
	if err != nil {
		return "", err
	}
	pk, err := cryptoutils.UnmarshalPEMToPublicKey(b)
	if err != nil {
		return "", fmt.Errorf("%s: %w", pub.PublicKey, err)
	}
	sv, err := signature.LoadVerifier(pk, crypto.SHA256)
	if err != nil {
		return "", err
	}
	km := root.NewTrustedPublicKeyMaterial(func(string) (root.TimeConstrainedVerifier, error) {
		return root.NewExpiringKey(sv, time.Time{}, time.Time{}), nil
	})
	// Key-based publishers may sign offline, without a transparency log.
	v, err := verify.NewVerifier(km, verify.WithNoObserverTimestamps())
	if err != nil {
		return "", err
	}
	if _, err := v.Verify(entity, verify.NewPolicy(artifact, verify.WithKey())); err != nil {
		return "", err
	}
	der, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return "key sha256:" + hex.EncodeToString(sum[:]), nil
}
