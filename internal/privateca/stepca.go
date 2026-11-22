package privateca

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// StepCA signs through a step-ca JWK provisioner (POST /1.0/sign with a
// one-time token signed by the provisioner key).
type StepCA struct {
	URL         string // https://ca.example:9000, a name in the CA's dnsNames
	Provisioner string
	// KeyID is the provisioner key's kid; empty uses the JWK's own.
	KeyID string
	// JWK is the provisioner's private key as JSON (decrypted).
	JWK  secret.Value
	HTTP *http.Client
	Now  func() time.Time
}

// tokenLifetime is how long a one-time token is valid. step-ca's default
// maximum is 5 minutes.
const tokenLifetime = 5 * time.Minute

// ParseProvisionerKey checks that b is a private JWK usable for signing
// tokens and returns its key id.
func ParseProvisionerKey(b []byte) (string, error) {
	k, _, err := provisionerKey(b)
	if err != nil {
		return "", err
	}
	return k.KeyID, nil
}

func provisionerKey(b []byte) (*jose.JSONWebKey, jose.SignatureAlgorithm, error) {
	var k jose.JSONWebKey
	if err := json.Unmarshal(b, &k); err != nil {
		return nil, "", errors.New("provisioner key is not a JWK (decrypt it with `step crypto jwe decrypt` first)")
	}
	if k.IsPublic() || !k.Valid() {
		return nil, "", errors.New("provisioner key must be a private JWK")
	}
	alg := jose.SignatureAlgorithm(k.Algorithm)
	if alg == "" {
		alg = jose.ES256 // step's default for JWK provisioners
	}
	switch alg {
	case jose.ES256, jose.ES384, jose.ES512, jose.EdDSA, jose.RS256, jose.PS256:
	default:
		return nil, "", errors.New("unsupported provisioner key algorithm " + string(alg))
	}
	return &k, alg, nil
}

func (s *StepCA) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// token mints the one-time token step-ca expects for /1.0/sign.
func (s *StepCA) token(signURL string, sans []string) (string, error) {
	k, alg, err := provisionerKey(s.JWK.Reveal())
	if err != nil {
		return "", &Error{Permanent: true, Msg: err.Error()}
	}
	kid := s.KeyID
	if kid == "" {
		kid = k.KeyID
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: k.Key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader(jose.HeaderKey("kid"), kid))
	if err != nil {
		return "", &Error{Permanent: true, Msg: "provisioner key: " + err.Error()}
	}
	jti := make([]byte, 16)
	_, _ = rand.Read(jti)
	now := s.now()
	claims := jwt.Claims{
		Issuer:    s.Provisioner,
		Subject:   sans[0],
		Audience:  jwt.Audience{signURL},
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(tokenLifetime)),
		ID:        hex.EncodeToString(jti),
	}
	return jwt.Signed(sig).Claims(claims).Claims(map[string]any{"sans": sans}).Serialize()
}

func stepMsg(b []byte) string {
	var e struct {
		Message string `json:"message"`
	}
	if json.Unmarshal(b, &e) == nil {
		return e.Message
	}
	return ""
}

// Sign implements Signer.
func (s *StepCA) Sign(ctx context.Context, csrPEM string, sans []string) (string, error) {
	if len(sans) == 0 {
		return "", &Error{Permanent: true, Msg: "no names to sign"}
	}
	signURL := strings.TrimSuffix(s.URL, "/") + "/1.0/sign"
	ott, err := s.token(signURL, sans)
	if err != nil {
		return "", err
	}
	var out struct {
		Crt       string   `json:"crt"`
		CA        string   `json:"ca"`
		CertChain []string `json:"certChain"`
	}
	if err := postJSON(ctx, s.HTTP, signURL, nil, map[string]string{"csr": csrPEM, "ott": ott}, &out, stepMsg); err != nil {
		return "", err
	}
	if len(out.CertChain) > 0 {
		return chain(out.CertChain...)
	}
	return chain(out.Crt, out.CA)
}
