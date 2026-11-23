// Package kek implements envelope encryption of system secrets with a
// key-encryption key that never touches the database.
package kek

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// KEK wraps and unwraps data keys / small secrets with AES-256-GCM.
type KEK struct {
	aead cipher.AEAD
	key  []byte
}

// ErrMissing is returned when no KEK is configured.
var ErrMissing = errors.New("no key-encryption key configured (set CERTLOOM_KEK_FILE or CERTLOOM_KEK; generate one with `certloomd gen-kek`)")

// New builds a KEK from 32 raw bytes.
func New(key []byte) (*KEK, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("KEK must be 32 bytes, got %d", len(key))
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(b)
	if err != nil {
		return nil, err
	}
	return &KEK{aead: a, key: append([]byte(nil), key...)}, nil
}

// FromEnv loads the KEK from CERTLOOM_KEK_FILE (preferred) or CERTLOOM_KEK (base64).
func FromEnv() (*KEK, error) {
	var s string
	if f := os.Getenv("CERTLOOM_KEK_FILE"); f != "" {
		b, err := os.ReadFile(f)
		if err != nil {
			return nil, fmt.Errorf("CERTLOOM_KEK_FILE: %w", err)
		}
		s = string(b)
	} else {
		s = os.Getenv("CERTLOOM_KEK")
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, ErrMissing
	}
	key, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("KEK must be base64: %w", err)
	}
	return New(key)
}

// Generate returns a new random KEK, base64-encoded.
func Generate() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}

// Seal encrypts plaintext; aad binds the ciphertext to its purpose (e.g. key name).
func (k *KEK) Seal(plaintext []byte, aad string) ([]byte, error) {
	nonce := make([]byte, k.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return k.aead.Seal(nonce, nonce, plaintext, []byte(aad)), nil
}

// Open decrypts ciphertext produced by Seal with the same aad.
func (k *KEK) Open(ciphertext []byte, aad string) ([]byte, error) {
	n := k.aead.NonceSize()
	if len(ciphertext) < n {
		return nil, errors.New("ciphertext too short")
	}
	pt, err := k.aead.Open(nil, ciphertext[:n], ciphertext[n:], []byte(aad))
	if err != nil {
		return nil, errors.New("cannot decrypt system key: wrong KEK or corrupted data")
	}
	return pt, nil
}

// Derive returns a 32-byte subkey for label (HKDF-SHA256). Every process with
// the same KEK derives the same subkey, which is what lets replicas share
// keys such as the CSRF key without storing them.
func (k *KEK) Derive(label string) []byte {
	b, err := hkdf.Key(sha256.New, k.key, nil, label, 32)
	if err != nil {
		panic(err) // only fails for lengths HKDF cannot produce
	}
	return b
}
