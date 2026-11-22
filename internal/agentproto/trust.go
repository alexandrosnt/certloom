package agentproto

// Trust store types and modes (ADR-0030).
const (
	TrustPEM     = "pem"
	TrustPKCS12  = "pkcs12"
	TrustDebian  = "debian"
	TrustRHEL    = "rhel"
	TrustWindows = "windows"

	TrustManage  = "manage"
	TrustObserve = "observe"
)

// TrustStoreTypes lists the known store types.
var TrustStoreTypes = []string{TrustPEM, TrustPKCS12, TrustDebian, TrustRHEL, TrustWindows}

// TrustStoreInfo describes a declared trust store in the heartbeat.
type TrustStoreInfo struct {
	Name string `json:"name"`
	Type string `json:"type"`
	Mode string `json:"mode"`
}

// TrustAnchor is one certificate found in a trust store.
type TrustAnchor struct {
	SHA256 string `json:"sha256"`
	PEM    string `json:"pem"`
	// Owned is true for anchors certloom wrote (its files, its friendly name).
	Owned bool `json:"owned,omitempty"`
}

// TrustStoreState is what a trust store holds.
type TrustStoreState struct {
	Name    string        `json:"name"`
	Type    string        `json:"type"`
	Mode    string        `json:"mode"`
	Anchors []TrustAnchor `json:"anchors"`
	// Error is set when the store could not be read; Anchors is then empty.
	Error string `json:"error,omitempty"`
}

// TrustApplyPayload asks the agent to make a managed store hold exactly
// these anchors (of certloom's own entries).
type TrustApplyPayload struct {
	Store   string   `json:"store"`
	Bundle  string   `json:"bundle"`
	Version int      `json:"version"`
	Digest  string   `json:"digest"`
	Anchors []string `json:"anchors"` // PEM, one certificate each
}

// TrustApplyOutput reports the store after the write.
type TrustApplyOutput struct {
	Version int             `json:"version"`
	Digest  string          `json:"digest"`
	State   TrustStoreState `json:"state"`
}
