package e2e

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
)

func certFP(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}
