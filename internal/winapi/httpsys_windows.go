package winapi

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	httpapi                            = windows.NewLazySystemDLL("httpapi.dll")
	procHttpInitialize                 = httpapi.NewProc("HttpInitialize")
	procHttpQueryServiceConfiguration  = httpapi.NewProc("HttpQueryServiceConfiguration")
	procHttpSetServiceConfiguration    = httpapi.NewProc("HttpSetServiceConfiguration")
	procHttpUpdateServiceConfiguration = httpapi.NewProc("HttpUpdateServiceConfiguration")
	procHttpDeleteServiceConfiguration = httpapi.NewProc("HttpDeleteServiceConfiguration")
)

const (
	httpInitializeConfig    = 2
	configSSLCertInfo       = 1 // HttpServiceConfigSSLCertInfo
	configSslSniCertInfo    = 5 // HttpServiceConfigSslSniCertInfo
	queryExact              = 0
	errorFileNotFound       = 2
	errorInsufficientBuffer = 122
)

// IISAppID is the application id IIS uses for the bindings it creates.
var IISAppID = windows.GUID{Data1: 0x4dc3e181, Data2: 0xe14b, Data3: 0x4a21, Data4: [8]byte{0xb0, 0x22, 0x59, 0xfc, 0x66, 0x9b, 0x09, 0x14}}

// sslParam is HTTP_SERVICE_CONFIG_SSL_PARAM.
type sslParam struct {
	HashLength                       uint32
	Hash                             *byte
	AppID                            windows.GUID
	StoreName                        *uint16
	DefaultCertCheckMode             uint32
	DefaultRevocationFreshnessTime   uint32
	DefaultRevocationURLRetrievalTmo uint32
	DefaultSslCtlIdentifier          *uint16
	DefaultSslCtlStoreName           *uint16
	DefaultFlags                     uint32
}

// sniKey is HTTP_SERVICE_CONFIG_SSL_SNI_KEY.
type sniKey struct {
	IPPort [128]byte // SOCKADDR_STORAGE
	Host   *uint16
}

type ipSet struct {
	Key   *byte // PSOCKADDR
	Param sslParam
}

type sniSet struct {
	Key   sniKey
	Param sslParam
}

type ipQuery struct {
	Type  uint32
	Key   *byte
	Token uint32
}

type sniQuery struct {
	Type  uint32
	Key   sniKey
	Token uint32
}

var initOnce = sync.OnceValue(func() error {
	r, _, _ := procHttpInitialize.Call(1, httpInitializeConfig, 0) // HTTPAPI_VERSION 1.0
	if r != 0 {
		return fmt.Errorf("HttpInitialize: %w", windows.Errno(r))
	}
	return nil
})

// SSLBinding addresses an HTTP.sys certificate entry: Host:Port when Host is
// set (SNI), otherwise IP:Port.
type SSLBinding struct {
	IP   string
	Port int
	Host string
}

// SSLCert is the certificate an entry points at.
type SSLCert struct {
	Hash  []byte
	Store string
}

func sockaddr(ip string, port int) ([]byte, error) {
	addr := net.ParseIP(ip)
	if addr == nil {
		return nil, fmt.Errorf("bad ip %q", ip)
	}
	if v4 := addr.To4(); v4 != nil {
		b := make([]byte, 16)
		binary.LittleEndian.PutUint16(b, windows.AF_INET)
		binary.BigEndian.PutUint16(b[2:], uint16(port)) //nolint:gosec // port range checked by the caller
		copy(b[4:], v4)
		return b, nil
	}
	b := make([]byte, 28)
	binary.LittleEndian.PutUint16(b, windows.AF_INET6)
	binary.BigEndian.PutUint16(b[2:], uint16(port)) //nolint:gosec // port range checked by the caller
	copy(b[8:], addr.To16())
	return b, nil
}

// configCall runs one of the HTTP.sys configuration functions on either key
// form, building the input struct for it.
type bindingInput struct {
	id     uintptr
	ptr    unsafe.Pointer
	size   uintptr
	keep   []any
	params *sslParam
}

func (b SSLBinding) input(param sslParam) (*bindingInput, error) {
	if b.Host != "" {
		s := &sniSet{Param: param}
		sa, _ := sockaddr("0.0.0.0", b.Port)
		copy(s.Key.IPPort[:], sa)
		h, err := windows.UTF16PtrFromString(strings.ToLower(b.Host))
		if err != nil {
			return nil, err
		}
		s.Key.Host = h
		return &bindingInput{id: configSslSniCertInfo, ptr: unsafe.Pointer(s), size: unsafe.Sizeof(*s), keep: []any{s, h}, params: &s.Param}, nil
	}
	sa, err := sockaddr(b.IP, b.Port)
	if err != nil {
		return nil, err
	}
	s := &ipSet{Key: &sa[0], Param: param}
	return &bindingInput{id: configSSLCertInfo, ptr: unsafe.Pointer(s), size: unsafe.Sizeof(*s), keep: []any{s, sa}, params: &s.Param}, nil
}

// query returns the raw entry, or nil when there is none. The returned
// buffer holds the SET struct followed by the data its pointers refer to.
func (b SSLBinding) query() ([]uint64, uintptr, error) {
	if err := initOnce(); err != nil {
		return nil, 0, err
	}
	var in unsafe.Pointer
	var inSize, id uintptr
	var keep []any
	if b.Host != "" {
		q := &sniQuery{Type: queryExact}
		sa, _ := sockaddr("0.0.0.0", b.Port)
		copy(q.Key.IPPort[:], sa)
		h, err := windows.UTF16PtrFromString(strings.ToLower(b.Host))
		if err != nil {
			return nil, 0, err
		}
		q.Key.Host = h
		in, inSize, id, keep = unsafe.Pointer(q), unsafe.Sizeof(*q), configSslSniCertInfo, []any{q, h}
	} else {
		sa, err := sockaddr(b.IP, b.Port)
		if err != nil {
			return nil, 0, err
		}
		q := &ipQuery{Type: queryExact, Key: &sa[0]}
		in, inSize, id, keep = unsafe.Pointer(q), unsafe.Sizeof(*q), configSSLCertInfo, []any{q, sa}
	}
	var n uint32
	r, _, _ := procHttpQueryServiceConfiguration.Call(0, id, uintptr(in), inSize, 0, 0, uintptr(unsafe.Pointer(&n)), 0)
	switch r {
	case errorFileNotFound:
		return nil, id, nil
	case errorInsufficientBuffer, 0:
	default:
		return nil, id, fmt.Errorf("query %s: %w", b, windows.Errno(r))
	}
	buf := make([]uint64, (n+7)/8)
	r, _, _ = procHttpQueryServiceConfiguration.Call(0, id, uintptr(in), inSize, uintptr(unsafe.Pointer(&buf[0])), uintptr(n),
		uintptr(unsafe.Pointer(&n)), 0)
	runtime.KeepAlive(keep)
	if r == errorFileNotFound {
		return nil, id, nil
	}
	if r != 0 {
		return nil, id, fmt.Errorf("query %s: %w", b, windows.Errno(r))
	}
	return buf, id, nil
}

func (b SSLBinding) String() string {
	if b.Host != "" {
		return fmt.Sprintf("%s:%d", b.Host, b.Port)
	}
	return net.JoinHostPort(b.IP, fmt.Sprint(b.Port))
}

func paramOf(buf []uint64, id uintptr) *sslParam {
	if id == configSslSniCertInfo {
		return &(*sniSet)(unsafe.Pointer(&buf[0])).Param
	}
	return &(*ipSet)(unsafe.Pointer(&buf[0])).Param
}

// GetSSLCert reads the entry for b; ok is false when HTTP.sys has none.
func GetSSLCert(b SSLBinding) (c SSLCert, ok bool, err error) {
	buf, id, err := b.query()
	if err != nil || buf == nil {
		return SSLCert{}, false, err
	}
	p := paramOf(buf, id)
	c.Hash = bytes.Clone(unsafe.Slice(p.Hash, p.HashLength))
	if p.StoreName != nil {
		c.Store = windows.UTF16PtrToString(p.StoreName)
	}
	runtime.KeepAlive(buf)
	return c, true, nil
}

// SetSSLCert points b at c. An existing entry keeps its application id,
// revocation, CTL and flag settings; a new entry gets IIS's application id.
func SetSSLCert(b SSLBinding, c SSLCert) error {
	buf, id, err := b.query()
	if err != nil {
		return err
	}
	var param sslParam
	exists := buf != nil
	if exists {
		param = *paramOf(buf, id)
	} else {
		param.AppID = IISAppID
	}
	hash := bytes.Clone(c.Hash)
	store, err := windows.UTF16PtrFromString(c.Store)
	if err != nil || len(hash) == 0 {
		return errors.New("certificate hash and store are required")
	}
	param.Hash, param.HashLength, param.StoreName = &hash[0], uint32(len(hash)), store
	in, err := b.input(param)
	if err != nil {
		return err
	}
	defer runtime.KeepAlive([]any{in, buf, hash, store})
	if !exists {
		return httpCall(procHttpSetServiceConfiguration, in, b)
	}
	// Update in place where the system has it (Windows 10 1607 / Server 2016+),
	// so there is no moment without a certificate.
	if procHttpUpdateServiceConfiguration.Find() == nil {
		return httpCall(procHttpUpdateServiceConfiguration, in, b)
	}
	if err := httpCall(procHttpDeleteServiceConfiguration, in, b); err != nil {
		return err
	}
	return httpCall(procHttpSetServiceConfiguration, in, b)
}

func httpCall(p *windows.LazyProc, in *bindingInput, b SSLBinding) error {
	r, _, _ := p.Call(0, in.id, uintptr(in.ptr), in.size, 0)
	if r != 0 {
		return fmt.Errorf("%s %s: %w", strings.TrimPrefix(p.Name, "Http"), b, windows.Errno(r))
	}
	return nil
}

// deleteSSLCert removes an entry; tests use it to clean up.
func deleteSSLCert(b SSLBinding) error {
	in, err := b.input(sslParam{})
	if err != nil {
		return err
	}
	defer runtime.KeepAlive(in)
	return httpCall(procHttpDeleteServiceConfiguration, in, b)
}
