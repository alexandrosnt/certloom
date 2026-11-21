// Package dnsplugin is the Certloom DNS plugin protocol (ADR-0017): the agent
// runs a plugin executable with one action argument, writes a Request as JSON
// to its stdin and reads one Response from its stdout.
//
// A plugin only creates and removes TXT records. The agent resolves CNAMEs,
// checks propagation and talks to the CA.
//
// This package is the public SDK for plugins written in Go: implement
// Handler and call Serve from main. Plugins in other languages only need the
// JSON messages below. Protocol version 1 is stable; incompatible changes get
// a new version number.
package dnsplugin

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

// Actions.
const (
	ActionDescribe = "describe"
	ActionPresent  = "present"
	ActionCleanup  = "cleanup"
)

// Error classes a plugin may report.
const (
	ClassAuth        = "auth"
	ClassRateLimited = "rate_limited"
	ClassTransient   = "transient"
	ClassPermanent   = "permanent"
)

// MaxOutput caps what is read from a plugin's stdout.
const MaxOutput = 64 << 10

// Request is written to the plugin's stdin.
type Request struct {
	Protocol int `json:"protocol"`
	// FQDN is the TXT record name after CNAME resolution, with a trailing dot.
	FQDN  string `json:"fqdn,omitempty"`
	Value string `json:"value,omitempty"`
	// Zone is the solver zone that matched FQDN, with a trailing dot.
	Zone   string         `json:"zone,omitempty"`
	Config map[string]any `json:"config,omitempty"`
	// Domain, Token and KeyAuth are the ACME identifier, challenge token and
	// key authorization FQDN and Value were derived from. Plugins that wrap a
	// client computing the record itself (lego providers, acme.sh hooks) use
	// them; none of them is secret.
	Domain  string `json:"domain,omitempty"`
	Token   string `json:"token,omitempty"`
	KeyAuth string `json:"key_auth,omitempty"`
}

// Response is read from the plugin's stdout. Describe fills Name and Version.
type Response struct {
	OK         bool   `json:"ok,omitempty"`
	Protocol   int    `json:"protocol,omitempty"`
	Name       string `json:"name,omitempty"`
	Version    string `json:"version,omitempty"`
	Error      string `json:"error,omitempty"`
	Class      string `json:"class,omitempty"`
	RetryAfter int64  `json:"retry_after,omitempty"` // seconds
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
	return fmt.Sprintf("dns plugin %s %s: %s (%s)", e.Plugin, e.Action, e.Msg, e.Class)
}

// Plugin is a configured plugin executable.
type Plugin struct {
	Path    string
	SHA256  string            // required; hex digest of the executable
	Env     map[string]string // the whole environment besides PATH
	Timeout time.Duration
	Stderr  io.Writer // where the plugin's stderr goes; nil discards it
}

// Check verifies that the executable is safe to run: an absolute path to a
// regular file that group and others cannot write, with the pinned digest.
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
		return fmt.Errorf("plugin %s has sha256 %s, config pins %s", p.Path, got, p.SHA256)
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
	cmd := exec.CommandContext(ctx, p.Path, action) //nolint:gosec // path is pinned by digest in the host's own config
	cmd.Stdin = bytes.NewReader(in)
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	for k, v := range p.Env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	out := &limitedBuffer{max: MaxOutput}
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
		return fail(ClassPermanent, fmt.Sprintf("output larger than %d bytes", MaxOutput))
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

type limitedBuffer struct {
	bytes.Buffer
	max      int
	overflow bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.Len()+len(p) > b.max {
		b.overflow = true
		return 0, errors.New("plugin output too large")
	}
	return b.Buffer.Write(p)
}

func isWindowsAbs(p string) bool {
	return len(p) > 2 && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}
