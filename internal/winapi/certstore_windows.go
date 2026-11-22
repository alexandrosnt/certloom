package winapi

import (
	"bytes"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	crypt32                               = windows.NewLazySystemDLL("crypt32.dll")
	procCertSetCertificateContextProperty = crypt32.NewProc("CertSetCertificateContextProperty")
	procCertGetCertificateContextProperty = crypt32.NewProc("CertGetCertificateContextProperty")
)

const (
	certHashPropID         = 3
	certKeyProvInfoPropID  = 2
	certFriendlyNamePropID = 11
	cryptMachineKeyset     = 0x20
	encoding               = windows.X509_ASN_ENCODING | windows.PKCS_7_ASN_ENCODING
)

// cryptKeyProvInfo is CRYPT_KEY_PROV_INFO. A zero provider type means CNG.
type cryptKeyProvInfo struct {
	ContainerName *uint16
	ProvName      *uint16
	ProvType      uint32
	Flags         uint32
	ProvParams    uint32
	ProvParam     uintptr
	KeySpec       uint32
}

func (s Scope) storeFlags() uint32 {
	if s == ScopeMachine {
		return windows.CERT_SYSTEM_STORE_LOCAL_MACHINE
	}
	return windows.CERT_SYSTEM_STORE_CURRENT_USER
}

func openStore(name string, scope Scope, mustExist bool) (windows.Handle, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	flags := scope.storeFlags()
	if mustExist {
		flags |= windows.CERT_STORE_OPEN_EXISTING_FLAG
	}
	h, err := windows.CertOpenStore(windows.CERT_STORE_PROV_SYSTEM, 0, 0, flags, uintptr(unsafe.Pointer(n)))
	if err != nil {
		return 0, fmt.Errorf("open certificate store %s: %w", name, err)
	}
	return h, nil
}

// LeafStore is the store for server certificates: WebHosting where it exists
// (IIS 8 and later, machine scope), otherwise My.
func LeafStore(scope Scope) string {
	if scope == ScopeMachine {
		if h, err := openStore("WebHosting", scope, true); err == nil {
			_ = windows.CertCloseStore(h, 0)
			return "WebHosting"
		}
	}
	return "My"
}

// StoredCert is a certificate found by OwnCerts.
type StoredCert struct {
	Store, FriendlyName string
	Thumb               []byte
}

// AddCert adds the leaf to store, linked to the CNG key keyName and labelled
// friendlyName, and the intermediates to the CA store. It returns the leaf's
// SHA-1 thumbprint.
func AddCert(store string, scope Scope, chain []*x509.Certificate, keyName, friendlyName string) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("empty chain")
	}
	if len(chain) > 1 {
		ca, err := openStore("CA", scope, false)
		if err != nil {
			return nil, err
		}
		for _, c := range chain[1:] {
			ctx, err := windows.CertCreateCertificateContext(encoding, &c.Raw[0], uint32(len(c.Raw)))
			if err != nil {
				_ = windows.CertCloseStore(ca, 0)
				return nil, err
			}
			err = windows.CertAddCertificateContextToStore(ca, ctx, windows.CERT_STORE_ADD_USE_EXISTING, nil)
			_ = windows.CertFreeCertificateContext(ctx)
			if err != nil {
				_ = windows.CertCloseStore(ca, 0)
				return nil, fmt.Errorf("add intermediate: %w", err)
			}
		}
		_ = windows.CertCloseStore(ca, 0)
	}
	h, err := openStore(store, scope, false)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // close of a store opened read-write
	leaf := chain[0]
	tmp, err := windows.CertCreateCertificateContext(encoding, &leaf.Raw[0], uint32(len(leaf.Raw)))
	if err != nil {
		return nil, err
	}
	defer windows.CertFreeCertificateContext(tmp) //nolint:errcheck // nothing to do on failure
	var ctx *windows.CertContext
	if err := windows.CertAddCertificateContextToStore(h, tmp, windows.CERT_STORE_ADD_REPLACE_EXISTING, &ctx); err != nil {
		return nil, fmt.Errorf("add certificate: %w", err)
	}
	defer windows.CertFreeCertificateContext(ctx) //nolint:errcheck // nothing to do on failure
	cn, _ := windows.UTF16PtrFromString(keyName)
	pn, _ := windows.UTF16PtrFromString(KeyStorageProvider)
	info := cryptKeyProvInfo{ContainerName: cn, ProvName: pn}
	if scope == ScopeMachine {
		info.Flags = cryptMachineKeyset
	}
	if err := setProp(ctx, certKeyProvInfoPropID, unsafe.Pointer(&info)); err != nil {
		return nil, fmt.Errorf("link key: %w", err)
	}
	fn := windows.StringToUTF16(friendlyName)
	blob := windows.CryptDataBlob{Size: uint32(len(fn) * 2), Data: (*byte)(unsafe.Pointer(&fn[0]))}
	if err := setProp(ctx, certFriendlyNamePropID, unsafe.Pointer(&blob)); err != nil {
		return nil, fmt.Errorf("set friendly name: %w", err)
	}
	return getProp(ctx, certHashPropID)
}

func setProp(ctx *windows.CertContext, id uint32, data unsafe.Pointer) error {
	r, _, err := procCertSetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), uintptr(id), 0, uintptr(data))
	if r == 0 {
		return err
	}
	return nil
}

func getProp(ctx *windows.CertContext, id uint32) ([]byte, error) {
	var n uint32
	r, _, err := procCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), uintptr(id), 0, uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	b := make([]byte, n)
	r, _, err = procCertGetCertificateContextProperty.Call(uintptr(unsafe.Pointer(ctx)), uintptr(id), uintptr(unsafe.Pointer(&b[0])), uintptr(unsafe.Pointer(&n)))
	if r == 0 {
		return nil, err
	}
	return b[:n], nil
}

func friendlyName(ctx *windows.CertContext) string {
	b, err := getProp(ctx, certFriendlyNamePropID)
	if err != nil || len(b) < 2 {
		return ""
	}
	u := unsafe.Slice((*uint16)(unsafe.Pointer(&b[0])), len(b)/2)
	return windows.UTF16ToString(u)
}

// OwnCerts lists the certificates in store whose friendly name starts with prefix.
func OwnCerts(store string, scope Scope, prefix string) ([]StoredCert, error) {
	h, err := openStore(store, scope, false)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // read-only use
	var out []StoredCert
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(h, ctx)
		if err != nil {
			break // end of store
		}
		if fn := friendlyName(ctx); strings.HasPrefix(fn, prefix) {
			thumb, err := getProp(ctx, certHashPropID)
			if err == nil {
				out = append(out, StoredCert{Store: store, FriendlyName: fn, Thumb: thumb})
			}
		}
	}
	return out, nil
}

func findByThumb(h windows.Handle, thumb []byte) (*windows.CertContext, error) {
	if len(thumb) == 0 {
		return nil, errors.New("empty thumbprint")
	}
	blob := windows.CryptHashBlob{Size: uint32(len(thumb)), Data: &thumb[0]}
	return windows.CertFindCertificateInStore(h, encoding, 0, windows.CERT_FIND_SHA1_HASH, unsafe.Pointer(&blob), nil)
}

// RemoveCert deletes a certificate; a missing one is not an error.
func RemoveCert(store string, scope Scope, thumb []byte) error {
	h, err := openStore(store, scope, false)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // nothing to do on failure
	ctx, err := findByThumb(h, thumb)
	if err != nil {
		return nil //nolint:nilerr // not found
	}
	return windows.CertDeleteCertificateFromStore(ctx)
}

// Cert returns the DER encoding of a stored certificate, nil if absent.
func Cert(store string, scope Scope, thumb []byte) ([]byte, error) {
	h, err := openStore(store, scope, true)
	if err != nil {
		return nil, nil //nolint:nilerr // store does not exist: certificate absent
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // read-only use
	ctx, err := findByThumb(h, thumb)
	if err != nil {
		return nil, nil //nolint:nilerr // not found
	}
	defer windows.CertFreeCertificateContext(ctx) //nolint:errcheck // nothing to do on failure
	return bytes.Clone(unsafe.Slice(ctx.EncodedCert, ctx.Length)), nil
}

// TrustedCert is a certificate in a root store with its friendly name.
type TrustedCert struct {
	DER          []byte
	FriendlyName string
}

// ListCerts returns every certificate in store.
func ListCerts(store string, scope Scope) ([]TrustedCert, error) {
	h, err := openStore(store, scope, true)
	if err != nil {
		return nil, err
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // read-only use
	var out []TrustedCert
	var ctx *windows.CertContext
	for {
		ctx, err = windows.CertEnumCertificatesInStore(h, ctx)
		if err != nil {
			break // end of store
		}
		out = append(out, TrustedCert{DER: bytes.Clone(unsafe.Slice(ctx.EncodedCert, ctx.Length)), FriendlyName: friendlyName(ctx)})
	}
	return out, nil
}

// AddTrusted adds a CA certificate to store, labelled friendlyName.
func AddTrusted(store string, scope Scope, c *x509.Certificate, friendly string) error {
	h, err := openStore(store, scope, false)
	if err != nil {
		return err
	}
	defer windows.CertCloseStore(h, 0) //nolint:errcheck // nothing to do on failure
	tmp, err := windows.CertCreateCertificateContext(encoding, &c.Raw[0], uint32(len(c.Raw)))
	if err != nil {
		return err
	}
	defer windows.CertFreeCertificateContext(tmp) //nolint:errcheck // nothing to do on failure
	var ctx *windows.CertContext
	if err := windows.CertAddCertificateContextToStore(h, tmp, windows.CERT_STORE_ADD_REPLACE_EXISTING, &ctx); err != nil {
		return fmt.Errorf("add certificate: %w", err)
	}
	defer windows.CertFreeCertificateContext(ctx) //nolint:errcheck // nothing to do on failure
	fn := windows.StringToUTF16(friendly)
	blob := windows.CryptDataBlob{Size: uint32(len(fn) * 2), Data: (*byte)(unsafe.Pointer(&fn[0]))}
	return setProp(ctx, certFriendlyNamePropID, unsafe.Pointer(&blob))
}
