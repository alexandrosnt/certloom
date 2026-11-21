package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type endpointRow struct {
	ID                  string     `json:"id"`
	Host                string     `json:"host"`
	Port                int        `json:"port"`
	SNI                 string     `json:"sni"`
	ScopeID             string     `json:"scope_id"`
	LineageID           *string    `json:"lineage_id"`
	IntervalSeconds     int        `json:"interval_seconds"`
	LastLeafSHA256      *string    `json:"last_leaf_sha256"`
	ConsecutiveFailures int        `json:"consecutive_failures"`
	LastObservedAt      *time.Time `json:"last_observed_at"`
	NextProbeAt         time.Time  `json:"next_probe_at"`
}

func tsp(t *time.Time) string {
	if t == nil {
		return "never"
	}
	return ts(*t)
}

// listCmd builds a simple "list" command over an items endpoint.
func listCmd(use, short, path, header string, row func(w io.Writer, raw json.RawMessage)) *cobra.Command {
	return &cobra.Command{Use: use, Short: short, RunE: run(func(c *client, _ []string) error {
		var v struct {
			Items []json.RawMessage `json:"items"`
		}
		if err := c.do("GET", path, nil, &v); err != nil {
			return err
		}
		if asJSON() {
			return printJSON(v.Items)
		}
		table(header, func(w io.Writer) {
			for _, r := range v.Items {
				row(w, r)
			}
		})
		return nil
	})}
}

func postAndPrint(c *client, method, path string, body any, human func(raw json.RawMessage)) error {
	var raw json.RawMessage
	if err := c.do(method, path, body, &raw); err != nil {
		return err
	}
	if asJSON() {
		if len(raw) == 0 {
			return printJSON(map[string]string{"status": "ok"})
		}
		_, err := os.Stdout.Write(raw)
		return err
	}
	human(raw)
	return nil
}

// ---------- endpoints ----------

func endpointCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "endpoint", Short: "TLS endpoints to probe"}
	var port, interval int
	var sni, scope, lineage, team string
	add := &cobra.Command{Use: "add HOST", Short: "Add an endpoint (must be allowed by the scope)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			if scope == "" {
				return &usageError{"--scope is required (see `certloom scope list`)"}
			}
			return postAndPrint(c, "POST", "/api/v1/endpoints", map[string]any{"host": args[0], "port": port, "sni": sni, "scope": scope,
				"lineage": lineage, "team": team, "interval_seconds": interval}, func(raw json.RawMessage) {
				var e endpointRow
				_ = json.Unmarshal(raw, &e)
				fmt.Printf("Added %s:%d as %s; first probe within ~10s.\n", e.Host, e.Port, e.ID)
			})
		})}
	add.Flags().IntVar(&port, "port", 443, "TCP port")
	add.Flags().StringVar(&sni, "sni", "", "SNI to send (default: host)")
	add.Flags().StringVar(&scope, "scope", "", "probe scope id or name (required)")
	add.Flags().StringVar(&lineage, "lineage", "", "expected lineage (detects wrong-certificate deployments)")
	add.Flags().StringVar(&team, "team", "", "owning team")
	add.Flags().IntVar(&interval, "interval", 0, "probe interval in seconds (default 21600 = 6h, minimum 60)")

	ls := listCmd("list", "List endpoints", "/api/v1/endpoints", "ID\tENDPOINT\tSERVING\tLAST OBSERVED\tFAILURES",
		func(w io.Writer, raw json.RawMessage) {
			var e endpointRow
			_ = json.Unmarshal(raw, &e)
			name := fmt.Sprintf("%s:%d", e.Host, e.Port)
			if e.SNI != "" {
				name += " (sni " + e.SNI + ")"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\n", e.ID, name, short(deref(e.LastLeafSHA256)), tsp(e.LastObservedAt), e.ConsecutiveFailures)
		})

	show := &cobra.Command{Use: "show ID", Short: "Show an endpoint with observations and findings", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var raw json.RawMessage
			if err := c.do("GET", "/api/v1/endpoints/"+url.PathEscape(args[0]), nil, &raw); err != nil {
				return err
			}
			if asJSON() {
				_, err := os.Stdout.Write(raw)
				return err
			}
			var v struct {
				endpointRow
				Observations []struct {
					ObservedAt time.Time `json:"observed_at"`
					LeafSHA256 *string   `json:"leaf_sha256"`
					TLSVersion string    `json:"tls_version"`
					ErrorClass string    `json:"error_class"`
					Error      string    `json:"error"`
				} `json:"observations"`
				Findings []findingRow `json:"findings"`
			}
			_ = json.Unmarshal(raw, &v)
			fmt.Printf("%s:%d (%s)\nServing:   %s\nObserved:  %s\nNext probe: %s\nFailures:  %d\n", v.Host, v.Port, v.ID,
				deref(v.LastLeafSHA256), tsp(v.LastObservedAt), ts(v.NextProbeAt), v.ConsecutiveFailures)
			printFindings(v.Findings)
			fmt.Println("\nRecent observations:")
			for _, o := range v.Observations {
				if o.ErrorClass != "" {
					fmt.Printf("  %s  %s: %s\n", ts(o.ObservedAt), o.ErrorClass, o.Error)
				} else {
					fmt.Printf("  %s  %s %s\n", ts(o.ObservedAt), short(deref(o.LeafSHA256)), o.TLSVersion)
				}
			}
			return nil
		})}

	probe := &cobra.Command{Use: "probe ID", Short: "Probe an endpoint now", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "POST", "/api/v1/endpoints/"+url.PathEscape(args[0])+"/probe", nil, func(json.RawMessage) {
				fmt.Println("Probe scheduled; results within seconds (`certloom endpoint show " + args[0] + "`).")
			})
		})}

	var bindLineage string
	bind := &cobra.Command{Use: "bind ID", Short: "Set the lineage an endpoint is expected to serve", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "PUT", "/api/v1/endpoints/"+url.PathEscape(args[0])+"/lineage", map[string]string{"lineage": bindLineage},
				func(json.RawMessage) { fmt.Println("Bound.") })
		})}
	bind.Flags().StringVar(&bindLineage, "lineage", "", "lineage id or name")
	_ = bind.MarkFlagRequired("lineage")
	cmd.AddCommand(add, ls, show, probe, bind)
	return cmd
}

// ---------- scopes ----------

func scopeCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "scope", Short: "Probe scopes: which hosts/networks the prober may contact"}
	var cidrs, hosts []string
	var ports []int
	var loopback, private, linkLocal bool
	create := &cobra.Command{Use: "create NAME", Short: "Create a probe scope (owner only)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			if loopback || private || linkLocal {
				fmt.Fprintln(os.Stderr, "note: this scope permits normally-denied address classes; the override is recorded in the audit log")
			}
			cfg := map[string]any{"allow_cidrs": cidrs, "allow_hosts": hosts, "ports": ports,
				"allow_loopback": loopback, "allow_private": private, "allow_link_local": linkLocal}
			return postAndPrint(c, "POST", "/api/v1/scopes", map[string]any{"name": args[0], "config": cfg}, func(raw json.RawMessage) {
				var s struct{ ID, Name string }
				_ = json.Unmarshal(raw, &s)
				fmt.Printf("Created scope %s (%s).\n", s.Name, s.ID)
			})
		})}
	create.Flags().StringSliceVar(&cidrs, "allow-cidr", nil, "permitted destination networks (repeatable); empty = any public address")
	create.Flags().StringSliceVar(&hosts, "allow-host", nil, "permitted hostname patterns, e.g. *.example.com (repeatable)")
	create.Flags().IntSliceVar(&ports, "port", nil, "permitted ports (default 443)")
	create.Flags().BoolVar(&loopback, "allow-loopback", false, "permit loopback addresses (denied by default)")
	create.Flags().BoolVar(&private, "allow-private", false, "permit RFC 1918/4193/CGNAT addresses (denied by default)")
	create.Flags().BoolVar(&linkLocal, "allow-link-local", false, "permit link-local addresses (metadata IPs stay denied)")
	ls := listCmd("list", "List scopes", "/api/v1/scopes", "ID\tNAME\tCONFIG", func(w io.Writer, raw json.RawMessage) {
		var s struct {
			ID, Name string
			Config   json.RawMessage
		}
		_ = json.Unmarshal(raw, &s)
		fmt.Fprintf(w, "%s\t%s\t%s\n", s.ID, s.Name, s.Config)
	})
	cmd.AddCommand(create, ls)
	return cmd
}

// ---------- teams, lineages, findings, alerts ----------

func teamCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "team", Short: "Teams (ownership)"}
	var contact string
	create := &cobra.Command{Use: "create NAME", Short: "Create a team", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		return postAndPrint(c, "POST", "/api/v1/teams", map[string]string{"name": args[0], "contact": contact}, func(raw json.RawMessage) {
			var t struct{ ID, Name string }
			_ = json.Unmarshal(raw, &t)
			fmt.Printf("Created team %s (%s).\n", t.Name, t.ID)
		})
	})}
	create.Flags().StringVar(&contact, "contact", "", "escalation contact (email, channel)")
	cmd.AddCommand(create, listCmd("list", "List teams", "/api/v1/teams", "ID\tNAME\tCONTACT", func(w io.Writer, raw json.RawMessage) {
		var t struct{ ID, Name, Contact string }
		_ = json.Unmarshal(raw, &t)
		fmt.Fprintf(w, "%s\t%s\t%s\n", t.ID, t.Name, t.Contact)
	}))
	return cmd
}

func lineageCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "lineage", Short: "Lineages: the logical slot successive certificates fill"}
	var team, current string
	create := &cobra.Command{Use: "create NAME", Short: "Create a lineage", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		return postAndPrint(c, "POST", "/api/v1/lineages", map[string]string{"name": args[0], "team": team, "current_sha256": current},
			func(raw json.RawMessage) {
				var l struct{ ID, Name string }
				_ = json.Unmarshal(raw, &l)
				fmt.Printf("Created lineage %s (%s).\n", l.Name, l.ID)
			})
	})}
	create.Flags().StringVar(&team, "team", "", "owning team")
	create.Flags().StringVar(&current, "current", "", "fingerprint of the certificate that should currently be served")
	var ownerTeam string
	owner := &cobra.Command{Use: "assign-owner LINEAGE", Short: "Assign the owning team", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		return postAndPrint(c, "PUT", "/api/v1/lineages/"+url.PathEscape(args[0])+"/owner", map[string]string{"team": ownerTeam},
			func(json.RawMessage) { fmt.Println("Owner assigned.") })
	})}
	owner.Flags().StringVar(&ownerTeam, "team", "", "team id or name")
	_ = owner.MarkFlagRequired("team")
	cmd.AddCommand(create, owner, listCmd("list", "List lineages", "/api/v1/lineages", "ID\tNAME\tLEVEL\tTEAM\tCURRENT",
		func(w io.Writer, raw json.RawMessage) {
			var l struct {
				ID, Name        string
				ManagementLevel string  `json:"management_level"`
				TeamID          *string `json:"team_id"`
				Current         *string `json:"current_sha256"`
			}
			_ = json.Unmarshal(raw, &l)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", l.ID, l.Name, l.ManagementLevel, deref(l.TeamID), short(deref(l.Current)))
		}))
	return cmd
}

func findingCmd() *cobra.Command {
	var severity string
	cmd := &cobra.Command{Use: "findings", Short: "List open findings", RunE: run(func(c *client, _ []string) error {
		var v struct{ Items []findingRow }
		if err := c.do("GET", "/api/v1/findings?severity="+url.QueryEscape(severity), nil, &v); err != nil {
			return err
		}
		if asJSON() {
			return printJSON(v.Items)
		}
		table("SEVERITY\tCHECK\tSUBJECT\tMESSAGE", func(w io.Writer) {
			for _, f := range v.Items {
				fmt.Fprintf(w, "%s\t%s\t%s %s\t%s\n", f.Severity, f.Check, f.SubjectType, short(f.SubjectID), f.Message)
			}
		})
		return nil
	})}
	cmd.Flags().StringVar(&severity, "severity", "", "minimum severity: warning or critical")
	return cmd
}

func alertCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "alert", Short: "Alerts"}
	ack := &cobra.Command{Use: "ack ID", Short: "Acknowledge an alert", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		return postAndPrint(c, "POST", "/api/v1/alerts/"+url.PathEscape(args[0])+"/ack", nil, func(json.RawMessage) { fmt.Println("Acknowledged.") })
	})}
	cmd.AddCommand(ack, listCmd("list", "List open and acknowledged alerts", "/api/v1/alerts?state=open,acked", "ID\tSTATE\tSEVERITY\tCHECK\tMESSAGE",
		func(w io.Writer, raw json.RawMessage) {
			var a struct {
				ID, State, Severity string
				Finding             findingRow
			}
			_ = json.Unmarshal(raw, &a)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", a.ID, a.State, a.Severity, a.Finding.Check, a.Finding.Message)
		}))
	return cmd
}

// ---------- channels, tokens, audit, automation ----------

func channelCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "channel", Short: "Notification channels"}
	var whURL, cred, minSev string
	var allowPrivate bool
	webhook := &cobra.Command{Use: "create-webhook NAME", Short: "Create a webhook channel (HMAC-signed payloads)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			cfg, _ := json.Marshal(map[string]any{"url": whURL, "allow_private": allowPrivate})
			return postAndPrint(c, "POST", "/api/v1/channels", map[string]any{"name": args[0], "kind": "webhook", "config": json.RawMessage(cfg),
				"credential_ref": cred, "min_severity": minSev}, func(raw json.RawMessage) {
				var ch struct{ ID string }
				_ = json.Unmarshal(raw, &ch)
				fmt.Printf("Created channel %s. Test it with `certloom channel test %s`.\n", ch.ID, ch.ID)
			})
		})}
	webhook.Flags().StringVar(&whURL, "url", "", "https URL")
	webhook.Flags().StringVar(&cred, "secret-ref", "", "HMAC secret reference on the server, e.g. env:CERTLOOM_WEBHOOK_SECRET")
	webhook.Flags().StringVar(&minSev, "min-severity", "warning", "info, warning or critical")
	webhook.Flags().BoolVar(&allowPrivate, "allow-private", false, "allow private/loopback destinations (internal receivers)")
	_ = webhook.MarkFlagRequired("url")

	var host, from, user, pwRef, tlsMode string
	var smtpPort int
	var to []string
	email := &cobra.Command{Use: "create-email NAME", Short: "Create an email channel (STARTTLS or implicit TLS only)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			cfg, _ := json.Marshal(map[string]any{"host": host, "port": smtpPort, "username": user, "from": from, "to": to, "tls": tlsMode})
			return postAndPrint(c, "POST", "/api/v1/channels", map[string]any{"name": args[0], "kind": "email", "config": json.RawMessage(cfg),
				"credential_ref": pwRef, "min_severity": minSev}, func(raw json.RawMessage) {
				var ch struct{ ID string }
				_ = json.Unmarshal(raw, &ch)
				fmt.Printf("Created channel %s.\n", ch.ID)
			})
		})}
	email.Flags().StringVar(&host, "smtp-host", "", "SMTP server")
	email.Flags().IntVar(&smtpPort, "smtp-port", 587, "SMTP port")
	email.Flags().StringVar(&user, "smtp-user", "", "SMTP username")
	email.Flags().StringVar(&pwRef, "password-ref", "", "SMTP password reference on the server, e.g. env:CERTLOOM_SMTP_PASSWORD")
	email.Flags().StringVar(&tlsMode, "tls", "starttls", "starttls or implicit")
	email.Flags().StringVar(&from, "from", "", "sender address")
	email.Flags().StringSliceVar(&to, "to", nil, "recipient (repeatable)")
	email.Flags().StringVar(&minSev, "min-severity", "warning", "info, warning or critical")

	test := &cobra.Command{Use: "test ID", Short: "Send a test notification", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		return postAndPrint(c, "POST", "/api/v1/channels/"+url.PathEscape(args[0])+"/test", nil, func(json.RawMessage) {
			fmt.Println("Test notification queued; delivery is retried on failure (check server logs).")
		})
	})}
	cmd.AddCommand(webhook, email, test, listCmd("list", "List channels", "/api/v1/channels", "ID\tNAME\tKIND\tMIN SEVERITY",
		func(w io.Writer, raw json.RawMessage) {
			var ch struct {
				ID, Name, Kind string
				MinSeverity    string `json:"min_severity"`
			}
			_ = json.Unmarshal(raw, &ch)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", ch.ID, ch.Name, ch.Kind, ch.MinSeverity)
		}))
	return cmd
}

func tokenCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "token", Short: "API tokens"}
	var role string
	var ttl time.Duration
	create := &cobra.Command{Use: "create NAME", Short: "Create a token; the secret is printed once to stdout", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var v struct {
				Token  struct{ ID string }
				Secret string
			}
			if err := c.do("POST", "/api/v1/tokens", map[string]any{"name": args[0], "role": role, "ttl_seconds": int(ttl.Seconds())}, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v)
			}
			fmt.Fprintf(os.Stderr, "Created token %s (role %s). Store the secret now; it cannot be shown again:\n", v.Token.ID, role)
			fmt.Println(v.Secret)
			return nil
		})}
	create.Flags().StringVar(&role, "role", "viewer", "owner, operator, viewer or auditor")
	create.Flags().DurationVar(&ttl, "ttl", 90*24*time.Hour, "lifetime (0 = no expiry; not recommended)")
	revoke := &cobra.Command{Use: "revoke ID", Short: "Revoke a token", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		return postAndPrint(c, "DELETE", "/api/v1/tokens/"+url.PathEscape(args[0]), nil, func(json.RawMessage) { fmt.Println("Revoked.") })
	})}
	cmd.AddCommand(create, revoke, listCmd("list", "List tokens (metadata only)", "/api/v1/tokens", "ID\tNAME\tROLE\tEXPIRES\tREVOKED\tLAST USED",
		func(w io.Writer, raw json.RawMessage) {
			var t struct {
				ID, Name, Role string
				ExpiresAt      *time.Time `json:"expires_at"`
				RevokedAt      *time.Time `json:"revoked_at"`
				LastUsedAt     *time.Time `json:"last_used_at"`
			}
			_ = json.Unmarshal(raw, &t)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", t.ID, t.Name, t.Role, tsp(t.ExpiresAt), tsp(t.RevokedAt), tsp(t.LastUsedAt))
		}))
	return cmd
}

func auditCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "audit", Short: "Audit trail"}
	var after int64
	var limit int
	query := &cobra.Command{Use: "query", Short: "List audit events", RunE: run(func(c *client, _ []string) error {
		var v struct {
			Items []struct {
				Seq           int64
				At            time.Time
				Actor, Action string
				ResourceType  string `json:"resource_type"`
				ResourceID    string `json:"resource_id"`
				Result        string
				Detail        map[string]any
			}
		}
		if err := c.do("GET", fmt.Sprintf("/api/v1/audit?after_seq=%d&limit=%d", after, limit), nil, &v); err != nil {
			return err
		}
		if asJSON() {
			return printJSON(v.Items)
		}
		table("SEQ\tWHEN\tACTOR\tACTION\tRESOURCE\tRESULT", func(w io.Writer) {
			for _, e := range v.Items {
				fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%s %s\t%s\n", e.Seq, ts(e.At), e.Actor, e.Action, e.ResourceType, short(e.ResourceID), e.Result)
			}
		})
		return nil
	})}
	query.Flags().Int64Var(&after, "after-seq", 0, "only events after this sequence number")
	query.Flags().IntVar(&limit, "limit", 100, "maximum events (<= 1000)")
	verify := &cobra.Command{Use: "verify", Short: "Recompute the audit hash chain", RunE: run(func(c *client, _ []string) error {
		var v struct {
			Checked     int64
			OK          bool
			BrokenAtSeq int64 `json:"broken_at_seq"`
			Reason      string
		}
		if err := c.do("GET", "/api/v1/audit/verify", nil, &v); err != nil {
			return err
		}
		if asJSON() {
			_ = printJSON(v)
		} else if v.OK {
			fmt.Printf("Audit chain consistent (%d events).\nNote: this proves internal consistency only; rely on the external export for tamper evidence.\n", v.Checked)
		} else {
			fmt.Printf("AUDIT CHAIN BROKEN at event %d: %s\n", v.BrokenAtSeq, v.Reason)
		}
		if !v.OK {
			return fmt.Errorf("audit chain verification failed")
		}
		return nil
	})}
	export := listCmd("export-status", "Show external audit export progress", "/api/v1/audit/export-status", "SINK\tEXPORTED\tHEAD\tLAG\tLAST ERROR",
		func(w io.Writer, raw json.RawMessage) {
			var s struct {
				Sink      string
				LastSeq   int64 `json:"last_exported_seq"`
				HeadSeq   int64 `json:"head_seq"`
				Lag       int64
				LastError string `json:"last_error"`
			}
			_ = json.Unmarshal(raw, &s)
			fmt.Fprintf(w, "%s\t%d\t%d\t%d\t%s\n", s.Sink, s.LastSeq, s.HeadSeq, s.Lag, s.LastError)
		})
	cmd.AddCommand(query, verify, export)
	return cmd
}

func automationCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "automation", Short: "Pause or resume automation for your organization (kill switch)"}
	var reason string
	mk := func(name string, paused bool) *cobra.Command {
		c := &cobra.Command{Use: name, Short: strings.ToUpper(name[:1]) + name[1:] + " probing and sweeps", RunE: run(func(c *client, _ []string) error {
			return postAndPrint(c, "POST", "/api/v1/automation/"+name, map[string]string{"reason": reason}, func(json.RawMessage) {
				fmt.Printf("Automation %sd.\n", name)
			})
		})}
		c.Flags().StringVar(&reason, "reason", "", "reason (recorded in the audit log)")
		_ = paused
		return c
	}
	cmd.AddCommand(mk("pause", true), mk("resume", false))
	return cmd
}
