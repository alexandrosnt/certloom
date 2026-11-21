package winapi

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // Windows thumbprints are SHA-1
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func testKeyName(t *testing.T) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "certloom-test-" + hex.EncodeToString(b)
	t.Cleanup(func() { _ = DeleteKey(name, ScopeUser) })
	return name
}

func TestKeySignsCSRAndCertificate(t *testing.T) {
	name := testKeyName(t)
	if _, err := OpenKey(name, ScopeUser); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("OpenKey on a missing key: %v", err)
	}
	k, err := CreateKey(name, ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "www.example.test"}, DNSNames: []string{"www.example.test"}}, k)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		t.Fatal(err)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatalf("CSR signature: %v", err)
	}
	// Reopening yields the same key.
	k2, err := OpenKey(name, ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	defer k2.Close()
	if !k2.Public().(*ecdsa.PublicKey).Equal(k.Public()) {
		t.Fatal("reopened key differs")
	}
	if err := DeleteKey(name, ScopeUser); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenKey(name, ScopeUser); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("key still there after delete: %v", err)
	}
}

func TestStoreAddLinksKeyAndLists(t *testing.T) {
	name := testKeyName(t)
	k, err := CreateKey(name, ScopeUser)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "certloom store test"},
		DNSNames: []string{"store.example.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	store := LeafStore(ScopeUser)
	friendly := "certloom:test:" + name
	thumb, err := AddCert(store, ScopeUser, []*x509.Certificate{cert}, name, friendly)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = RemoveCert(store, ScopeUser, thumb) })
	want := sha1.Sum(der) //nolint:gosec // thumbprint
	if !bytes.Equal(thumb, want[:]) {
		t.Fatalf("thumbprint %x, want %x", thumb, want)
	}
	got, err := Cert(store, ScopeUser, thumb)
	if err != nil || sha256.Sum256(got) != sha256.Sum256(der) {
		t.Fatalf("Cert: %v", err)
	}
	own, err := OwnCerts(store, ScopeUser, friendly)
	if err != nil || len(own) != 1 || !bytes.Equal(own[0].Thumb, thumb) {
		t.Fatalf("OwnCerts = %+v, %v", own, err)
	}
	// Windows itself must find the private key through the link.
	if !hasPrivateKey(t, store, thumb) {
		t.Fatal("store does not resolve the certificate's CNG key")
	}
	if err := RemoveCert(store, ScopeUser, thumb); err != nil {
		t.Fatal(err)
	}
	if got, _ := Cert(store, ScopeUser, thumb); got != nil {
		t.Fatal("certificate still there after remove")
	}
}

var procCryptAcquireCertificatePrivateKey = crypt32.NewProc("CryptAcquireCertificatePrivateKey")

func hasPrivateKey(t *testing.T, store string, thumb []byte) bool {
	h, err := openStore(store, ScopeUser, true)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // test
	ctx, err := findByThumb(h, thumb)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CertFreeCertificateContext(ctx) //nolint:errcheck // test
	const onlyNCrypt = 0x00040000                 // CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG
	var key uintptr
	var spec uint32
	var free int32
	r, _, _ := procCryptAcquireCertificatePrivateKey.Call(uintptr(unsafe.Pointer(ctx)), onlyNCrypt|0x40, 0, uintptr(unsafe.Pointer(&key)),
		uintptr(unsafe.Pointer(&spec)), uintptr(unsafe.Pointer(&free)))
	if r == 0 {
		return false
	}
	if free != 0 {
		freeObject(key)
	}
	return true
}

// machineCert creates a machine CNG key and a self-signed certificate for it
// in LocalMachine\My, and removes both at the end of the test.
func machineCert(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	name := "certloom-test-" + hex.EncodeToString(b)
	k, err := CreateKey(name, ScopeMachine)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { k.Close(); _ = DeleteKey(name, ScopeMachine) })
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "certloom httpsys test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	thumb, err := AddCert("My", ScopeMachine, []*x509.Certificate{c}, name, "certloom:test:"+name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = RemoveCert("My", ScopeMachine, thumb) })
	return thumb
}

func TestHTTPSysRoundTrip(t *testing.T) {
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("HTTP.sys configuration and machine keys need an elevated process (runs in the Windows CI job)")
	}
	for _, b := range []SSLBinding{{IP: "127.0.0.1", Port: 47443}, {Host: "httpsys.certloom.test", Port: 47443}} {
		t.Run(b.String(), func(t *testing.T) {
			if _, ok, err := GetSSLCert(b); err != nil || ok {
				t.Skipf("%s already has an HTTP.sys entry or query failed: %v", b, err)
			}
			first, second := machineCert(t), machineCert(t)
			if err := SetSSLCert(b, SSLCert{Hash: first, Store: "MY"}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = deleteSSLCert(b) })
			got, ok, err := GetSSLCert(b)
			if err != nil || !ok || !bytes.Equal(got.Hash, first) || !strings.EqualFold(got.Store, "MY") {
				t.Fatalf("GetSSLCert = %+v %v %v", got, ok, err)
			}
			if err := SetSSLCert(b, SSLCert{Hash: second, Store: "MY"}); err != nil {
				t.Fatal(err)
			}
			if got, _, _ = GetSSLCert(b); !bytes.Equal(got.Hash, second) {
				t.Fatalf("update not applied: %x", got.Hash)
			}
		})
	}
}
