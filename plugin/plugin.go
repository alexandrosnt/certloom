// Package plugin is the certloom agent plugin protocol (ADR-0017, ADR-0027):
// the agent runs a plugin executable with one action argument, writes a
// Request as JSON to its stdin and reads one Response from its stdout.
//
// A plugin implements one or more kinds:
//
//   - dns_solver: create and remove the TXT record of a DNS-01 challenge.
//     The agent resolves CNAMEs, checks propagation and talks to the CA.
//   - deploy_target: install a new key and certificate somewhere the agent
//     has no built-in target for, report what is served, and undo a deploy.
//   - discovery: report certificates found in a system the agent does not
//     read itself.
//
// This package is the public SDK for plugins written in Go: fill a Server and
// call Serve from main. Plugins in other languages only need the JSON
// messages below. Protocol version 1 is stable; incompatible changes get a
// new version number. Fields are only ever added.
package plugin

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Protocol is the version spoken by this package. A plugin that reports a
// different version in Describe is refused.
const Protocol = 1

// Kinds.
const (
	KindDNSSolver    = "dns_solver"
	KindDeployTarget = "deploy_target"
	KindDiscovery    = "discovery"
)

// Actions. Describe applies to every plugin; the others belong to one kind,
// except Inventory, which deploy targets may also implement.
const (
	ActionDescribe  = "describe"
	ActionPresent   = "present"
	ActionCleanup   = "cleanup"
	ActionDeploy    = "deploy"
	ActionVerify    = "verify"
	ActionRollback  = "rollback"
	ActionInventory = "inventory"
)

// Error classes a plugin may report.
const (
	ClassAuth        = "auth"
	ClassRateLimited = "rate_limited"
	ClassTransient   = "transient"
	ClassPermanent   = "permanent"
)

// MaxOutput caps what is read from a plugin's stdout. Inventory answers may
// carry many certificates and get MaxInventoryOutput instead.
const (
	MaxOutput          = 64 << 10
	MaxInventoryOutput = 4 << 20
)

// Request is written to the plugin's stdin.
type Request struct {
	Protocol int `json:"protocol"`
	// Kind is the kind the call is made for. It is empty in calls from
	// agents older than ADR-0027, which only knew dns_solver.
	Kind   string         `json:"kind,omitempty"`
	Config map[string]any `json:"config,omitempty"`
	// Secrets are credentials the control plane delivered for this call
	// (ADR-0018). Plugins configured on the host read their own instead.
	Secrets map[string]string `json:"secrets,omitempty"`

	// dns_solver.

	// FQDN is the TXT record name after CNAME resolution, with a trailing dot.
	FQDN  string `json:"fqdn,omitempty"`
	Value string `json:"value,omitempty"`
	// Zone is the solver zone that matched FQDN, with a trailing dot.
	Zone string `json:"zone,omitempty"`
	// Domain, Token and KeyAuth are the ACME identifier, challenge token and
	// key authorization FQDN and Value were derived from. Plugins that wrap a
	// client computing the record itself (lego providers, acme.sh hooks) use
	// them; none of them is secret.
	Domain  string `json:"domain,omitempty"`
	Token   string `json:"token,omitempty"`
	KeyAuth string `json:"key_auth,omitempty"`

	// deploy_target.

	// Target is the target name from the agent config.
	Target string `json:"target,omitempty"`
	// IdempotencyKey is the same for every call that belongs to one deploy:
	// deploy, verify and rollback, and retries of each. A plugin that sees
	// a deploy with a key it has already completed reports success again.
	IdempotencyKey string `json:"idempotency_key,omitempty"`
	// Files holds paths to the new material, in a directory only the agent
	// user can read. It is removed after the call.
	Files *Files `json:"files,omitempty"`
	// Names are the DNS names of the new certificate.
	Names []string `json:"names,omitempty"`
}

// Files are PEM files the agent writes for a deploy.
type Files struct {
	Key         string `json:"key"`
	Certificate string `json:"certificate"`
	Chain       string `json:"chain"`
	// Fullchain is the certificate followed by the chain.
	Fullchain string `json:"fullchain"`
}

// Response is read from the plugin's stdout.
type Response struct {
	OK         bool   `json:"ok,omitempty"`
	Error      string `json:"error,omitempty"`
	Class      string `json:"class,omitempty"`
	RetryAfter int64  `json:"retry_after,omitempty"` // seconds

	// Describe.
	Protocol int    `json:"protocol,omitempty"`
	Name     string `json:"name,omitempty"`
	Version  string `json:"version,omitempty"`
	// Kinds lists what the plugin implements. Empty means dns_solver, as
	// plugins written before ADR-0027 do not report it.
	Kinds []string `json:"kinds,omitempty"`

	// Verify: the leaf certificate the target serves now, PEM.
	Certificate string `json:"certificate,omitempty"`

	// Inventory.
	Items []Item `json:"items,omitempty"`
}

// Item is one certificate found by Inventory.
type Item struct {
	// Certificate is the leaf, PEM. Chains may follow it.
	Certificate string `json:"certificate"`
	// Location says where it was found, in the plugin's own terms.
	Location string `json:"location"`
	// UsedBy names what serves or references it (virtual servers, listeners).
	UsedBy []string `json:"used_by,omitempty"`
}

// DescribedKinds returns the kinds a describe response declares, with the
// pre-ADR-0027 default applied.
func (r *Response) DescribedKinds() []string {
	if len(r.Kinds) == 0 {
		return []string{KindDNSSolver}
	}
	return r.Kinds
}

// Error is a failure reported by a plugin, or a failure to run it.
type Error struct {
	Plugin     string
	Action     string
	Class      string
	Msg        string
	RetryAfter time.Duration
}

func (e *Error) Error() string {
	return fmt.Sprintf("plugin %s %s: %s (%s)", e.Plugin, e.Action, e.Msg, e.Class)
}

// Plugin is a plugin executable the agent may run.
type Plugin struct {
	Path    string
	SHA256  string            // required; hex digest of the executable
	Env     map[string]string // the whole environment besides PATH
	Timeout time.Duration
	Stderr  io.Writer // where the plugin's stderr goes; nil discards it
}

// Check verifies that the executable is safe to run: an absolute path to a
// regular file that group and others cannot write, with the expected digest.
func (p *Plugin) Check() error {
	if !strings.HasPrefix(p.Path, "/") && !isWindowsAbs(p.Path) {
		return fmt.Errorf("plugin path %q must be absolute", p.Path)
	}
	f, err := os.Open(p.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("plugin %s is not a regular file", p.Path)
	}
	if fi.Mode().Perm()&0o022 != 0 && !skipPermCheck {
		return fmt.Errorf("plugin %s is writable by group or others", p.Path)
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); !strings.EqualFold(got, p.SHA256) {
		return fmt.Errorf("plugin %s has sha256 %s, expected %s", p.Path, got, p.SHA256)
	}
	return nil
}

// Call runs one action. The executable is checked before every call, so a
// binary replaced after the agent started is refused.
func (p *Plugin) Call(ctx context.Context, action string, req Request) (*Response, error) {
	if err := p.Check(); err != nil {
		return nil, &Error{Plugin: p.Path, Action: action, Class: ClassPermanent, Msg: err.Error()}
	}
	req.Protocol = Protocol
	in, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Path, action) //nolint:gosec // path is pinned by digest
	cmd.Stdin = bytes.NewReader(in)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range p.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	limit := MaxOutput
	if action == ActionInventory {
		limit = MaxInventoryOutput
	}
	out := &limitedBuffer{max: limit}
	cmd.Stdout = out
	cmd.Stderr = p.Stderr
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()
	fail := func(class, msg string) (*Response, error) {
		return nil, &Error{Plugin: p.Path, Action: action, Class: class, Msg: msg}
	}
	if ctx.Err() == context.DeadlineExceeded {
		return fail(ClassTransient, fmt.Sprintf("timed out after %s", timeout))
	}
	if out.overflow {
		return fail(ClassPermanent, fmt.Sprintf("output larger than %d bytes", limit))
	}
	var resp Response
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &resp); err != nil {
		if runErr != nil {
			return fail(ClassTransient, runErr.Error())
		}
		return fail(ClassPermanent, "output is not a JSON response")
	}
	if resp.Error != "" || !resp.OK && action != ActionDescribe {
		class := resp.Class
		switch class {
		case ClassAuth, ClassRateLimited, ClassTransient, ClassPermanent:
		default:
			class = ClassTransient
		}
		msg := resp.Error
		if msg == "" {
			msg = "plugin did not report success"
		}
		return nil, &Error{Plugin: p.Path, Action: action, Class: class, Msg: msg,
			RetryAfter: time.Duration(resp.RetryAfter) * time.Second}
	}
	if runErr != nil {
		return fail(ClassTransient, runErr.Error())
	}
	if action == ActionDescribe && resp.Protocol != Protocol {
		return fail(ClassPermanent, fmt.Sprintf("speaks protocol %d, agent speaks %d", resp.Protocol, Protocol))
	}
	return &resp, nil
}

// IsClass reports whether err is a plugin error of the given class.
func IsClass(err error, class string) bool {
	var e *Error
	return errors.As(err, &e) && e.Class == class
}

// limitedBuffer must not embed bytes.Buffer: io.Copy would use the embedded
// ReadFrom and never call Write, so the limit would not apply.
type limitedBuffer struct {
	buf      bytes.Buffer
	max      int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.buf.Len()+len(p) > b.max {
		b.overflow = true
		return 0, errors.New("plugin output too large")
	}
	return b.buf.Write(p)
}

func (b *limitedBuffer) Bytes() []byte { return b.buf.Bytes() }

func isWindowsAbs(p string) bool {
	return len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}
