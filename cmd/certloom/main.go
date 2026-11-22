// Command certloom is the command-line interface for the certloom control plane.
package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alexandrosnt/certloom/internal/version"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2"
	"golang.org/x/term"
)

var output string // "table" or "json"

// cliCtx is cancelled on Ctrl+C so in-flight requests stop cleanly.
var cliCtx = context.Background()

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	cliCtx = ctx
	root := &cobra.Command{
		Use:           "certloom",
		Short:         "Certificate lifecycle management CLI (inventory & monitoring)",
		SilenceUsage:  true,
		SilenceErrors: true,
		Long: `certloom talks to a certloomd control plane.

Exit codes: 0 ok, 1 error, 2 usage, 3 not authenticated, 4 not found,
5 forbidden, 6 invalid request, 7 conflict.

Configuration: ` + "`certloom login`" + ` writes server and token to the user config dir
(0600). CERTLOOM_SERVER, CERTLOOM_TOKEN and CERTLOOM_CA_FILE override it.`,
	}
	root.PersistentFlags().StringVarP(&output, "output", "o", "table", "output format: table or json")
	root.AddCommand(loginCmd(), logoutCmd(), memberCmd(), policyCmd(), agentCmd(), issuerCmd(), templateCmd(), webhookCmd(), dnsSolverCmd(), deploymentCmd(), caCmd(), approvalCmd(), exceptionCmd(), runCmd(), whoamiCmd(), statusCmd(), doctorCmd(), versionCmd(), inventoryCmd(), endpointCmd(),
		scopeCmd(), teamCmd(), lineageCmd(), findingCmd(), alertCmd(), channelCmd(), tokenCmd(), auditCmd(), automationCmd())
	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		stop()
		os.Exit(exitCode(err))
	}
}

func asJSON() bool { return output == "json" }

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func table(header string, rows func(w io.Writer)) {
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, header)
	rows(w)
	_ = w.Flush()
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

func ts(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format("2006-01-02 15:04")
}

func left(t time.Time) string {
	d := time.Until(t)
	if d < 0 {
		return fmt.Sprintf("EXPIRED %dd ago", int(-d.Hours()/24))
	}
	if d < 48*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

func deref(s *string) string {
	if s == nil {
		return "-"
	}
	return *s
}

// run wraps a client call in a cobra RunE.
func run(fn func(c *client, args []string) error) func(*cobra.Command, []string) error {
	return func(_ *cobra.Command, args []string) error {
		c, err := newClient()
		if err != nil {
			return err
		}
		return fn(c, args)
	}
}

// ---------- session ----------

func loginCmd() *cobra.Command {
	var server, caFile, org string
	var tokenStdin, useOIDC bool
	cmd := &cobra.Command{
		Use:   "login",
		Short: "Store server URL and API token (token is read from stdin or a prompt, never from argv)",
		RunE: func(_ *cobra.Command, _ []string) error {
			if server == "" {
				return &usageError{"--server is required"}
			}
			if caFile != "" { // store an absolute path so the config works from any directory
				abs, err := filepath.Abs(caFile)
				if err != nil {
					return err
				}
				caFile = abs
			}
			var tok string
			var err error
			if useOIDC {
				if tok, err = deviceLogin(config{Server: server, CAFile: caFile}, org); err != nil {
					return err
				}
			} else {
				fmt.Fprint(os.Stderr, "API token: ")
				if tok, err = readSecret(); err != nil {
					return err
				}
				if !tokenStdin {
					fmt.Fprintln(os.Stderr)
				}
			}
			cfg := config{Server: server, Token: tok, CAFile: caFile}
			c, err := clientFor(cfg)
			if err != nil {
				return err
			}
			var who map[string]any
			if err := c.do("GET", "/api/v1/whoami", nil, &who); err != nil {
				return err
			}
			p, err := saveConfig(cfg)
			if err != nil {
				return err
			}
			fmt.Printf("Logged in to %s as %v (role %v). Config saved to %s\n", server, who["actor"], who["role"], p)
			return nil
		},
	}
	cmd.Flags().StringVar(&server, "server", "", "control plane URL, e.g. https://certloom.example.internal:8443")
	cmd.Flags().StringVar(&caFile, "ca-file", "", "PEM trust anchor for the server certificate (private CA)")
	cmd.Flags().BoolVar(&tokenStdin, "token-stdin", false, "token is piped on stdin (no prompt newline)")
	cmd.Flags().BoolVar(&useOIDC, "oidc", false, "sign in with single sign-on (OAuth device flow) instead of an API token")
	cmd.Flags().StringVar(&org, "org", "", "organization name, if your identity belongs to several")
	return cmd
}

// deviceLogin runs the OAuth 2.0 device authorization grant against the
// server's IdP and exchanges the resulting ID token for a certloom session.
func deviceLogin(cfg config, org string) (string, error) {
	c, err := clientFor(cfg)
	if err != nil {
		return "", err
	}
	var ac struct {
		OIDC          bool   `json:"oidc"`
		CLIClientID   string `json:"cli_client_id"`
		DeviceAuthURL string `json:"device_authorization_endpoint"`
		TokenURL      string `json:"token_endpoint"`
	}
	if err := c.do("GET", "/api/v1/auth/config", nil, &ac); err != nil {
		return "", err
	}
	if !ac.OIDC || ac.CLIClientID == "" || ac.DeviceAuthURL == "" {
		return "", &usageError{"this server does not offer single sign-on for the CLI; use an API token"}
	}
	oc := oauth2.Config{ClientID: ac.CLIClientID, Scopes: []string{"openid", "email", "profile"},
		Endpoint: oauth2.Endpoint{DeviceAuthURL: ac.DeviceAuthURL, TokenURL: ac.TokenURL}}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	da, err := oc.DeviceAuth(ctx)
	if err != nil {
		return "", fmt.Errorf("device authorization: %w", err)
	}
	uri := da.VerificationURIComplete
	if uri == "" {
		uri = da.VerificationURI
	}
	fmt.Fprintf(os.Stderr, "To sign in, open %s and enter code %s\nWaiting for approval...\n", uri, da.UserCode)
	tok, err := oc.DeviceAccessToken(ctx, da)
	if err != nil {
		return "", fmt.Errorf("device sign-in: %w", err)
	}
	idt, _ := tok.Extra("id_token").(string)
	if idt == "" {
		return "", errors.New("identity provider returned no ID token")
	}
	var sess struct{ Token, Email, Role string }
	if err := c.do("POST", "/api/v1/auth/oidc/session", map[string]string{"id_token": idt, "org": org}, &sess); err != nil {
		return "", err
	}
	return sess.Token, nil
}

func logoutCmd() *cobra.Command {
	return &cobra.Command{Use: "logout", Short: "End the session and remove stored credentials", RunE: func(*cobra.Command, []string) error {
		if c, err := newClient(); err == nil && strings.HasPrefix(c.token, "certlooms_") {
			_ = c.do("DELETE", "/api/v1/auth/session", nil, nil)
		}
		p, err := configPath()
		if err != nil {
			return err
		}
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		fmt.Println("Logged out.")
		return nil
	}}
}

func memberCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "member", Short: "Single sign-on members (owner only)"}
	var role string
	add := &cobra.Command{Use: "add EMAIL", Short: "Allow a verified IdP identity to sign in with a role", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "POST", "/api/v1/members", map[string]string{"email": args[0], "role": role}, func(raw json.RawMessage) {
				var m struct{ ID, Email, Role string }
				_ = json.Unmarshal(raw, &m)
				fmt.Printf("Added %s as %s (%s).\n", m.Email, m.Role, m.ID)
			})
		})}
	add.Flags().StringVar(&role, "role", "viewer", "owner, operator, viewer or auditor")
	rm := &cobra.Command{Use: "remove ID", Short: "Remove a member and end their sessions", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "DELETE", "/api/v1/members/"+url.PathEscape(args[0]), nil, func(json.RawMessage) { fmt.Println("Removed.") })
		})}
	cmd.AddCommand(add, rm, listCmd("list", "List members", "/api/v1/members", "ID\tEMAIL\tROLE\tADDED BY",
		func(w io.Writer, raw json.RawMessage) {
			var m struct {
				ID, Email, Role string
				CreatedBy       string `json:"created_by"`
			}
			_ = json.Unmarshal(raw, &m)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", m.ID, m.Email, m.Role, m.CreatedBy)
		}))
	return cmd
}

func readLine(r io.Reader) (string, error) {
	s, err := bufio.NewReader(r).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return "", &usageError{"empty token"}
	}
	return s, nil
}

func whoamiCmd() *cobra.Command {
	return &cobra.Command{Use: "whoami", Short: "Show the authenticated principal", RunE: run(func(c *client, _ []string) error {
		var v map[string]any
		if err := c.do("GET", "/api/v1/whoami", nil, &v); err != nil {
			return err
		}
		if asJSON() {
			return printJSON(v)
		}
		fmt.Printf("actor: %v\nrole:  %v\norg:   %v\n", v["actor"], v["role"], v["org_id"])
		return nil
	})}
}

type metric struct {
	Key, Label, Definition, Link string
	Value, Denominator           int
}

func statusCmd() *cobra.Command {
	return &cobra.Command{Use: "status", Short: "Show overview metrics", RunE: run(func(c *client, _ []string) error {
		var v struct{ Items []metric }
		if err := c.do("GET", "/api/v1/overview", nil, &v); err != nil {
			return err
		}
		if asJSON() {
			return printJSON(v.Items)
		}
		table("METRIC\tVALUE\tOF", func(w io.Writer) {
			for _, m := range v.Items {
				fmt.Fprintf(w, "%s\t%d\t%d\n", m.Label, m.Value, m.Denominator)
			}
		})
		return nil
	})}
}

func doctorCmd() *cobra.Command {
	return &cobra.Command{Use: "doctor", Short: "Check configuration, connectivity, authentication and clock skew", RunE: func(_ *cobra.Command, _ []string) error {
		cfg, err := loadConfig()
		if err != nil {
			return err
		}
		ok := true
		check := func(name string, err error, hint string) {
			if err != nil {
				ok = false
				fmt.Printf("FAIL  %s: %v\n", name, err)
				if hint != "" {
					fmt.Printf("      hint: %s\n", hint)
				}
				return
			}
			fmt.Printf("ok    %s\n", name)
		}
		if cfg.Server == "" {
			check("config", errors.New("no server configured"), "run `certloom login --server URL`")
			return &usageError{"not configured"}
		}
		check("config", nil, "")
		c, err := clientFor(cfg)
		if err != nil {
			check("server url", err, "")
			return err
		}
		start := time.Now()
		req, err := http.NewRequestWithContext(cliCtx, http.MethodGet, c.base.String()+"/readyz", nil)
		if err != nil {
			return err
		}
		resp, err := c.http.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if d, perr := time.Parse(time.RFC1123, resp.Header.Get("Date")); perr == nil {
				skew := time.Since(d) - time.Since(start)/2
				if skew < 0 {
					skew = -skew
				}
				var serr error
				if skew > 2*time.Minute {
					serr = fmt.Errorf("local clock differs from server by ~%s", skew.Round(time.Second))
				}
				check("clock skew", serr, "fix NTP on this host or the server; expiry math depends on accurate clocks")
			}
			if resp.StatusCode != 200 {
				err = fmt.Errorf("readyz returned %d", resp.StatusCode)
			}
		}
		check("server reachable and ready", err, "check the URL, TLS trust (--ca-file) and that certloomd and its database are running")
		var who map[string]any
		check("authentication", c.do("GET", "/api/v1/whoami", nil, &who), "token may be expired or revoked; run `certloom login` again")
		if !ok {
			return errors.New("one or more checks failed")
		}
		return nil
	}}
}

func versionCmd() *cobra.Command {
	return &cobra.Command{Use: "version", Short: "Print version", Run: func(*cobra.Command, []string) {
		fmt.Println("certloom", version.String())
	}}
}

// ---------- inventory ----------

type certRow struct {
	SHA256             string    `json:"sha256"`
	CommonName         string    `json:"common_name"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	Serial             string    `json:"serial"`
	DNSNames           []string  `json:"dns_names"`
	IPAddresses        []string  `json:"ip_addresses"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	KeyAlgorithm       string    `json:"key_algorithm"`
	KeyBits            int       `json:"key_bits"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	IsCA               bool      `json:"is_ca"`
	Source             string    `json:"source"`
}

func inventoryCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "inventory", Short: "Certificate inventory"}

	var pwFile, lineage, team string
	var pwStdin, dryRun bool
	imp := &cobra.Command{Use: "import FILE...", Short: "Import PEM, DER or PKCS#12 files (private keys are never stored)", Args: cobra.MinimumNArgs(1),
		RunE: run(func(c *client, args []string) error {
			var pw string
			switch {
			case pwFile != "":
				b, err := os.ReadFile(pwFile)
				if err != nil {
					return err
				}
				pw = strings.TrimRight(string(b), "\r\n")
			case pwStdin:
				var err error
				if pw, err = readLine(os.Stdin); err != nil {
					return err
				}
			}
			var results []json.RawMessage
			for _, f := range args {
				data, err := os.ReadFile(f)
				if err != nil {
					return err
				}
				path := "/api/v1/certificates/import"
				if dryRun {
					path += "?dry_run=true"
				}
				var res struct {
					Format         string   `json:"format"`
					Imported       []string `json:"imported"`
					AlreadyKnown   []string `json:"already_known"`
					PrivateKeySeen bool     `json:"private_key_seen"`
					KeyMatchesLeaf *bool    `json:"key_matches_leaf"`
					Warnings       []string `json:"warnings"`
				}
				var raw json.RawMessage
				err = c.do("POST", path, map[string]string{"data": base64.StdEncoding.EncodeToString(data), "password": pw,
					"lineage": lineage, "team": team}, &raw)
				if err != nil {
					return fmt.Errorf("%s: %w", f, err)
				}
				results = append(results, raw)
				if asJSON() {
					continue
				}
				_ = json.Unmarshal(raw, &res)
				prefix := ""
				if dryRun {
					prefix = "[dry run] "
				}
				fmt.Printf("%s%s: %s, %d new, %d already known\n", prefix, f, res.Format, len(res.Imported), len(res.AlreadyKnown))
				for _, w := range res.Warnings {
					fmt.Printf("  note: %s\n", w)
				}
				if res.KeyMatchesLeaf != nil && !*res.KeyMatchesLeaf {
					fmt.Println("  WARNING: the private key in this file does not match its certificate")
				}
			}
			if asJSON() {
				return printJSON(results)
			}
			return nil
		})}
	imp.Flags().StringVar(&pwFile, "password-file", "", "file containing the PKCS#12 password")
	imp.Flags().BoolVar(&pwStdin, "password-stdin", false, "read the PKCS#12 password from stdin")
	imp.Flags().StringVar(&lineage, "lineage", "", "create or update this lineage with the imported leaf as current")
	imp.Flags().StringVar(&team, "team", "", "owning team for a newly created lineage")
	imp.Flags().BoolVar(&dryRun, "dry-run", false, "parse and validate only; store nothing")

	var expiring, search string
	var includeCA bool
	var limit int
	ls := &cobra.Command{Use: "list", Short: "List certificates, soonest expiry first", RunE: run(func(c *client, _ []string) error {
		q := url.Values{}
		if expiring != "" {
			q.Set("expiring", expiring)
		}
		if search != "" {
			q.Set("search", search)
		}
		if includeCA {
			q.Set("include_ca", "true")
		}
		q.Set("limit", strconv.Itoa(limit))
		var v struct {
			Items      []certRow `json:"items"`
			NextCursor string    `json:"next_cursor"`
		}
		if err := c.do("GET", "/api/v1/certificates?"+q.Encode(), nil, &v); err != nil {
			return err
		}
		if asJSON() {
			return printJSON(v)
		}
		table("SHA256\tNAME\tEXPIRES\tLEFT\tKEY\tSOURCE", func(w io.Writer) {
			for _, r := range v.Items {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s %d\t%s\n", short(r.SHA256), r.CommonName, ts(r.NotAfter), left(r.NotAfter), r.KeyAlgorithm, r.KeyBits, r.Source)
			}
		})
		if v.NextCursor != "" {
			fmt.Fprintln(os.Stderr, "(more results; use --limit or --output json for the cursor)")
		}
		return nil
	})}
	ls.Flags().StringVar(&expiring, "expiring", "", "only certificates expiring within this horizon, e.g. 30d, 0d = expired")
	ls.Flags().StringVar(&search, "search", "", "substring of name, subject or SAN")
	ls.Flags().BoolVar(&includeCA, "include-ca", false, "include CA certificates")
	ls.Flags().IntVar(&limit, "limit", 100, "maximum results (<= 500)")

	show := &cobra.Command{Use: "show FINGERPRINT", Short: "Show a certificate (full SHA-256 or unique prefix >= 8)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var v struct {
				certRow
				ServedBy []endpointRow `json:"served_by"`
				Findings []findingRow  `json:"findings"`
			}
			var raw json.RawMessage
			if err := c.do("GET", "/api/v1/certificates/"+url.PathEscape(args[0]), nil, &raw); err != nil {
				return err
			}
			if asJSON() {
				_, err := os.Stdout.Write(raw)
				return err
			}
			_ = json.Unmarshal(raw, &v)
			fmt.Printf("SHA-256:   %s\nSubject:   %s\nIssuer:    %s\nSerial:    %s\nValid:     %s -> %s (%s)\nDNS names: %s\nKey:       %s %d, signed %s\nSource:    %s\n",
				v.SHA256, v.Subject, v.Issuer, v.Serial, ts(v.NotBefore), ts(v.NotAfter), left(v.NotAfter), strings.Join(v.DNSNames, ", "),
				v.KeyAlgorithm, v.KeyBits, v.SignatureAlgorithm, v.Source)
			fmt.Println("\nServed by:")
			if len(v.ServedBy) == 0 {
				fmt.Println("  (no monitored endpoint currently serves it)")
			}
			for _, e := range v.ServedBy {
				fmt.Printf("  %s:%d %s (%s)\n", e.Host, e.Port, e.SNI, e.ID)
			}
			printFindings(v.Findings)
			return nil
		})}

	export := &cobra.Command{Use: "export", Short: "Export the full inventory as JSON (public data only)", RunE: run(func(c *client, _ []string) error {
		var all []json.RawMessage
		cursor := ""
		for {
			q := url.Values{"limit": {"500"}, "include_ca": {"true"}}
			if cursor != "" {
				q.Set("cursor", cursor)
			}
			var v struct {
				Items      []json.RawMessage `json:"items"`
				NextCursor string            `json:"next_cursor"`
			}
			if err := c.do("GET", "/api/v1/certificates?"+q.Encode(), nil, &v); err != nil {
				return err
			}
			all = append(all, v.Items...)
			if v.NextCursor == "" {
				break
			}
			cursor = v.NextCursor
		}
		return printJSON(all)
	})}
	cmd.AddCommand(imp, ls, show, export)
	return cmd
}

type findingRow struct {
	ID          string    `json:"id"`
	SubjectType string    `json:"subject_type"`
	SubjectID   string    `json:"subject_id"`
	Check       string    `json:"check"`
	Severity    string    `json:"severity"`
	Message     string    `json:"message"`
	Remediation string    `json:"remediation"`
	LastSeen    time.Time `json:"last_seen"`
}

func printFindings(fs []findingRow) {
	fmt.Println("\nFindings:")
	if len(fs) == 0 {
		fmt.Println("  (none)")
	}
	for _, f := range fs {
		fmt.Printf("  [%s] %s: %s\n", strings.ToUpper(f.Severity), f.Check, f.Message)
		if f.Remediation != "" {
			fmt.Printf("      -> %s\n", f.Remediation)
		}
	}
}

// readSecret reads a secret without echo when stdin is a terminal,
// otherwise one line from stdin (for piping in CI).
func readSecret() (string, error) {
	fd := int(os.Stdin.Fd())
	if term.IsTerminal(fd) {
		b, err := term.ReadPassword(fd)
		if err != nil {
			return "", err
		}
		s := strings.TrimSpace(string(b))
		if s == "" {
			return "", &usageError{"empty token"}
		}
		return s, nil
	}
	return readLine(os.Stdin)
}
