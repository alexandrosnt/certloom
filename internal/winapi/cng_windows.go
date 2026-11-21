package winapi

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	ncrypt                        = windows.NewLazySystemDLL("ncrypt.dll")
	procNCryptOpenStorageProvider = ncrypt.NewProc("NCryptOpenStorageProvider")
	procNCryptCreatePersistedKey  = ncrypt.NewProc("NCryptCreatePersistedKey")
	procNCryptOpenKey             = ncrypt.NewProc("NCryptOpenKey")
	procNCryptSetProperty         = ncrypt.NewProc("NCryptSetProperty")
	procNCryptFinalizeKey         = ncrypt.NewProc("NCryptFinalizeKey")
	procNCryptExportKey           = ncrypt.NewProc("NCryptExportKey")
	procNCryptSignHash            = ncrypt.NewProc("NCryptSignHash")
	procNCryptDeleteKey           = ncrypt.NewProc("NCryptDeleteKey")
	procNCryptFreeObject          = ncrypt.NewProc("NCryptFreeObject")
)

// KeyStorageProvider is the CNG provider keys are created in.
const KeyStorageProvider = "Microsoft Software Key Storage Provider"

const (
	ncryptMachineKeyFlag = 0x20
	ncryptSilentFlag     = 0x40
	nteBadKeyset         = 0x80090016
	eccP256PublicMagic   = 0x31534345 // BCRYPT_ECDSA_PUBLIC_P256_MAGIC
)

// Scope selects the machine or the current user's key and certificate stores.
type Scope int

// Scopes. The agent service uses ScopeMachine; tests run without elevation
// in ScopeUser.
const (
	ScopeMachine Scope = iota
	ScopeUser
)

// ErrKeyNotFound is returned by OpenKey for a missing key.
var ErrKeyNotFound = errors.New("key not found")

type secStatus uintptr

func (s secStatus) Error() string { return fmt.Sprintf("CNG error %#08x", uintptr(s)) }

func call(p *windows.LazyProc, args ...uintptr) error {
	r, _, _ := p.Call(args...)
	if r != 0 {
		return secStatus(r)
	}
	return nil
}

func (s Scope) keyFlags() uintptr {
	if s == ScopeMachine {
		return ncryptMachineKeyFlag | ncryptSilentFlag
	}
	return ncryptSilentFlag
}

func openProvider() (uintptr, error) {
	var h uintptr
	name, _ := windows.UTF16PtrFromString(KeyStorageProvider)
	if err := call(procNCryptOpenStorageProvider, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(name)), 0); err != nil {
		return 0, fmt.Errorf("open key storage provider: %w", err)
	}
	return h, nil
}

func freeObject(h uintptr) { _ = call(procNCryptFreeObject, h) }

// Key is a persisted CNG ECDSA P-256 key. Its private part never leaves CNG.
type Key struct {
	h   uintptr
	pub *ecdsa.PublicKey
}

// CreateKey creates a non-exportable P-256 key with the given name.
func CreateKey(name string, scope Scope) (*Key, error) {
	prov, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)
	alg, _ := windows.UTF16PtrFromString("ECDSA_P256")
	kn, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var h uintptr
	if err := call(procNCryptCreatePersistedKey, prov, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(alg)),
		uintptr(unsafe.Pointer(kn)), 0, scope.keyFlags()); err != nil {
		return nil, fmt.Errorf("create key %s: %w", name, err)
	}
	// Export policy 0: the key cannot be exported, not even by an administrator.
	policy := uint32(0)
	prop, _ := windows.UTF16PtrFromString("Export Policy")
	if err := call(procNCryptSetProperty, h, uintptr(unsafe.Pointer(prop)), uintptr(unsafe.Pointer(&policy)), 4, 0); err != nil {
		freeObject(h)
		return nil, fmt.Errorf("set export policy: %w", err)
	}
	if err := call(procNCryptFinalizeKey, h, ncryptSilentFlag); err != nil {
		freeObject(h)
		return nil, fmt.Errorf("finalize key: %w", err)
	}
	return newKey(h)
}

// OpenKey opens an existing key.
func OpenKey(name string, scope Scope) (*Key, error) {
	prov, err := openProvider()
	if err != nil {
		return nil, err
	}
	defer freeObject(prov)
	kn, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return nil, err
	}
	var h uintptr
	if err := call(procNCryptOpenKey, prov, uintptr(unsafe.Pointer(&h)), uintptr(unsafe.Pointer(kn)), 0, scope.keyFlags()); err != nil {
		var s secStatus
		if errors.As(err, &s) && uint32(s) == nteBadKeyset {
			return nil, ErrKeyNotFound
		}
		return nil, fmt.Errorf("open key %s: %w", name, err)
	}
	return newKey(h)
}

// DeleteKey removes a key; a missing key is not an error.
func DeleteKey(name string, scope Scope) error {
	k, err := OpenKey(name, scope)
	if errors.Is(err, ErrKeyNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	// NCryptDeleteKey frees the handle, also on failure.
	return call(procNCryptDeleteKey, k.h, ncryptSilentFlag)
}

func newKey(h uintptr) (*Key, error) {
	blobType, _ := windows.UTF16PtrFromString("ECCPUBLICBLOB")
	var n uint32
	if err := call(procNCryptExportKey, h, 0, uintptr(unsafe.Pointer(blobType)), 0, 0, 0, uintptr(unsafe.Pointer(&n)), 0); err != nil {
		freeObject(h)
		return nil, fmt.Errorf("export public key: %w", err)
	}
	buf := make([]byte, n)
	if err := call(procNCryptExportKey, h, 0, uintptr(unsafe.Pointer(blobType)), 0, uintptr(unsafe.Pointer(&buf[0])), uintptr(n),
		uintptr(unsafe.Pointer(&n)), 0); err != nil {
		freeObject(h)
		return nil, fmt.Errorf("export public key: %w", err)
	}
	if n < 8 || binary.LittleEndian.Uint32(buf) != eccP256PublicMagic || binary.LittleEndian.Uint32(buf[4:]) != 32 || n < 8+64 {
		freeObject(h)
		return nil, errors.New("key is not ECDSA P-256")
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append([]byte{4}, buf[8:72]...))
	if err != nil {
		freeObject(h)
		return nil, fmt.Errorf("public key: %w", err)
	}
	k := &Key{h: h, pub: pub}
	runtime.SetFinalizer(k, (*Key).Close)
	return k, nil
}

// Close releases the key handle; the persisted key stays.
func (k *Key) Close() {
	if k.h != 0 {
		freeObject(k.h)
		k.h = 0
	}
}

// Public returns the public key.
func (k *Key) Public() crypto.PublicKey { return k.pub }

// Sign signs a digest inside CNG and returns an ASN.1 ECDSA signature.
func (k *Key) Sign(_ io.Reader, digest []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(digest) == 0 {
		return nil, errors.New("empty digest")
	}
	sig := make([]byte, 64)
	var n uint32
	err := call(procNCryptSignHash, k.h, 0, uintptr(unsafe.Pointer(&digest[0])), uintptr(len(digest)),
		uintptr(unsafe.Pointer(&sig[0])), uintptr(len(sig)), uintptr(unsafe.Pointer(&n)), 0)
	runtime.KeepAlive(k)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}
	if n != 64 {
		return nil, fmt.Errorf("sign: unexpected signature length %d", n)
	}
	// CNG returns r||s; crypto/x509 expects the ASN.1 form.
	return asn1.Marshal(struct{ R, S *big.Int }{new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])})
}
