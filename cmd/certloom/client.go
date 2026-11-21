package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Exit codes (stable; documented in `certloom --help`).
const (
	exitOK        = 0
	exitError     = 1
	exitUsage     = 2
	exitAuth      = 3
	exitNotFound  = 4
	exitForbidden = 5
	exitInvalid   = 6
	exitConflict  = 7
)

// config is persisted by `certloom login` with 0600 permissions.
type config struct {
	Server string `json:"server"`
	Token  string `json:"token"`
	CAFile string `json:"ca_file,omitempty"`
}

func configPath() (string, error) {
	if p := os.Getenv("CERTLOOM_CONFIG"); p != "" {
		return p, nil
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "certloom", "config.json"), nil
}

func loadConfig() (config, error) {
	var c config
	p, err := configPath()
	if err != nil {
		return c, err
	}
	if b, err := os.ReadFile(p); err == nil {
		if err := json.Unmarshal(b, &c); err != nil {
			return c, fmt.Errorf("parse %s: %w", p, err)
		}
	}
	// Environment overrides the file (useful in CI).
	if v := os.Getenv("CERTLOOM_SERVER"); v != "" {
		c.Server = v
	}
	if v := os.Getenv("CERTLOOM_TOKEN"); v != "" {
		c.Token = v
	}
	if v := os.Getenv("CERTLOOM_CA_FILE"); v != "" {
		c.CAFile = v
	}
	return c, nil
}

func saveConfig(c config) (string, error) {
	p, err := configPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	b, _ := json.MarshalIndent(c, "", "  ")
	return p, os.WriteFile(p, b, 0o600)
}

// apiError carries an RFC 9457 problem and maps it to an exit code.
type apiError struct {
	Status      int
	Detail      string
	Remediation string
	RequestID   string
}

func (e *apiError) Error() string {
	s := fmt.Sprintf("%s (HTTP %d)", e.Detail, e.Status)
	if e.Remediation != "" {
		s += "\n  hint: " + e.Remediation
	}
	if e.RequestID != "" {
		s += "\n  request id: " + e.RequestID
	}
	return s
}

func exitCode(err error) int {
	var ae *apiError
	if errors.As(err, &ae) {
		switch ae.Status {
		case 401:
			return exitAuth
		case 403:
			return exitForbidden
		case 404:
			return exitNotFound
		case 400, 413:
			return exitInvalid
		case 409:
			return exitConflict
		}
	}
	var ue *usageError
	if errors.As(err, &ue) {
		return exitUsage
	}
	return exitError
}

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }

type client struct {
	base  *url.URL
	token string
	http  *http.Client
}

func newClient() (*client, error) {
	c, err := loadConfig()
	if err != nil {
		return nil, err
	}
	if c.Server == "" || c.Token == "" {
		return nil, &usageError{"not logged in: run `certloom login --server URL` or set CERTLOOM_SERVER and CERTLOOM_TOKEN"}
	}
	return clientFor(c)
}

func clientFor(c config) (*client, error) {
	u, err := url.Parse(strings.TrimRight(c.Server, "/"))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, &usageError{fmt.Sprintf("invalid server URL %q", c.Server)}
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s contains no certificates", c.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	return &client{base: u, token: c.Token, http: &http.Client{Timeout: 60 * time.Second,
		Transport: &http.Transport{TLSClientConfig: tlsCfg, Proxy: http.ProxyFromEnvironment}}}, nil
}

func (c *client) do(method, path string, body, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	u := *c.base
	p, q, _ := strings.Cut(path, "?")
	u.Path += p
	u.RawQuery = q
	req, err := http.NewRequestWithContext(cliCtx, method, u.String(), rd)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "certloom-cli")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w\n  hint: check the server URL and that certloomd is running (`certloom doctor`)", c.base, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode >= 400 {
		var p struct {
			Detail, Remediation string
			RequestID           string `json:"request_id"`
		}
		_ = json.Unmarshal(data, &p)
		if p.Detail == "" {
			p.Detail = strings.TrimSpace(string(data))
		}
		return &apiError{Status: resp.StatusCode, Detail: p.Detail, Remediation: p.Remediation, RequestID: p.RequestID}
	}
	if out != nil && len(data) > 0 {
		if raw, ok := out.(*json.RawMessage); ok {
			*raw = data
			return nil
		}
		return json.Unmarshal(data, out)
	}
	return nil
}

// doRaw sends a non-JSON body (e.g. a YAML policy).
func (c *client) doRaw(method, path, contentType string, body []byte, out any) error {
	u := *c.base
	p, q, _ := strings.Cut(path, "?")
	u.Path += p
	u.RawQuery = q
	req, err := http.NewRequestWithContext(cliCtx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("User-Agent", "certloom-cli")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.base, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode >= 400 {
		var pr struct {
			Detail, Remediation string
			RequestID           string `json:"request_id"`
		}
		_ = json.Unmarshal(data, &pr)
		if pr.Detail == "" {
			pr.Detail = strings.TrimSpace(string(data))
		}
		return &apiError{Status: resp.StatusCode, Detail: pr.Detail, Remediation: pr.Remediation, RequestID: pr.RequestID}
	}
	if raw, ok := out.(*json.RawMessage); ok {
		*raw = data
		return nil
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}
