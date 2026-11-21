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

func agentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "agent", Short: "Agents that generate keys, obtain and deploy certificates on hosts"}
	var name string
	var ttl time.Duration
	token := &cobra.Command{Use: "token", Short: "Create a one-time enrollment token (owner); prints the enroll command", RunE: run(func(c *client, _ []string) error {
		var t struct {
			ID, Token, Command string
			CAHash             string    `json:"ca_hash"`
			ExpiresAt          time.Time `json:"expires_at"`
		}
		if err := c.do("POST", "/api/v1/agents/enrollment-tokens", map[string]any{"name": name, "ttl_seconds": int(ttl.Seconds())}, &t); err != nil {
			return err
		}
		if asJSON() {
			return printJSON(t)
		}
		fmt.Fprintf(os.Stderr, "One-time token (expires %s). On the target host run:\n  %s\nand paste the token below when prompted:\n", ts(t.ExpiresAt), t.Command)
		fmt.Println(t.Token)
		return nil
	})}
	token.Flags().StringVar(&name, "name", "", "require the agent to enroll with this name")
	token.Flags().DurationVar(&ttl, "ttl", time.Hour, "token lifetime (max 1h)")
	revoke := &cobra.Command{Use: "revoke AGENT", Short: "Revoke an agent immediately (owner)", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		return postAndPrint(c, "POST", "/api/v1/agents/"+url.PathEscape(args[0])+"/revoke", nil, func(json.RawMessage) { fmt.Println("Revoked.") })
	})}
	inv := &cobra.Command{Use: "inventory AGENT", Short: "Ask an agent to report certificates, renewal clients, IIS bindings or Kubernetes objects on its host", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "POST", "/api/v1/agents/"+url.PathEscape(args[0])+"/inventory", nil, func(json.RawMessage) {
				fmt.Println("Inventory requested; results appear in `certloom inventory list` once the agent reports.")
			})
		})}
	cmd.AddCommand(token, revoke, inv, observationsCmd(), listCmd("list", "List agents", "/api/v1/agents", "ID\tNAME\tHEALTH\tHOST\tVERSION\tTARGETS",
		func(w io.Writer, raw json.RawMessage) {
			var a struct {
				ID, Name, Health, Hostname, Version string
				Capabilities                        struct{ Targets []struct{ Name string } }
			}
			_ = json.Unmarshal(raw, &a)
			var ts []string
			for _, t := range a.Capabilities.Targets {
				ts = append(ts, t.Name)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Name, a.Health, a.Hostname, a.Version, strings.Join(ts, ","))
		}))
	return cmd
}

func issuerCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "issuer", Short: "ACME issuers"}
	var dir, email, profile string
	var agree bool
	create := &cobra.Command{Use: "create NAME", Short: "Register an ACME issuer (owner)", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		if !agree {
			return &usageError{"you must read and accept the CA's terms of service: pass --agree-tos"}
		}
		return postAndPrint(c, "POST", "/api/v1/issuers", map[string]any{"name": args[0], "directory_url": dir, "email": email,
			"agree_tos": agree, "profile": profile}, func(raw json.RawMessage) {
			var i struct{ ID string }
			_ = json.Unmarshal(raw, &i)
			fmt.Printf("Created issuer %s (%s).\n", args[0], i.ID)
		})
	})}
	create.Flags().StringVar(&dir, "directory", "", "ACME directory URL, e.g. https://acme-staging-v02.api.letsencrypt.org/directory")
	create.Flags().StringVar(&email, "email", "", "account contact email (optional)")
	create.Flags().StringVar(&profile, "profile", "", "ACME profile, e.g. shortlived (optional)")
	create.Flags().BoolVar(&agree, "agree-tos", false, "accept the CA's terms of service")
	_ = create.MarkFlagRequired("directory")
	cmd.AddCommand(create, listCmd("list", "List issuers", "/api/v1/issuers", "ID\tNAME\tDIRECTORY\tPROFILE\tEAB",
		func(w io.Writer, raw json.RawMessage) {
			var i struct {
				ID, Name, Profile string
				Dir               string `json:"directory_url"`
				EAB               string `json:"eab_mode"`
			}
			_ = json.Unmarshal(raw, &i)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", i.ID, i.Name, i.Dir, i.Profile, i.EAB)
		}))
	cmd.AddCommand(issuerEABCmds()...)
	return cmd
}

func deploymentCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "deployment", Short: "Deployments: lineage -> agent target -> issuer"}
	var lineage, agent, target, issuer, endpoint, window, emergency, challenge string
	var tmpl, keyAlg string
	var sans []string
	create := &cobra.Command{Use: "create", Short: "Create a deployment, or request one if you may only request", RunE: run(func(c *client, _ []string) error {
		return postAndPrint(c, "POST", "/api/v1/deployments", map[string]any{"lineage": lineage, "agent": agent, "target": target,
			"issuer": issuer, "endpoint": endpoint, "sans": sans, "maintenance_window": window, "window_emergency": emergency, "challenge": challenge, "template": tmpl, "key_algorithm": keyAlg}, func(raw json.RawMessage) {
			var d struct{ ID, Approval string }
			_ = json.Unmarshal(raw, &d)
			if d.Approval != "approved" {
				fmt.Printf("Created deployment %s; it waits for approval by someone else (`certloom approval list`).\n", d.ID)
				return
			}
			fmt.Printf("Created deployment %s. Renew now with `certloom deployment renew %s`.\n", d.ID, d.ID)
		})
	})}
	for _, f := range []struct {
		p    *string
		n, u string
	}{{&lineage, "lineage", "lineage id or name"}, {&agent, "agent", "agent id or name"}, {&target, "target", "target name from the agent's config"}} {
		create.Flags().StringVar(f.p, f.n, "", f.u)
		_ = create.MarkFlagRequired(f.n)
	}
	create.Flags().StringVar(&issuer, "issuer", "", "issuer id or name (not needed with --template)")
	create.Flags().StringVar(&tmpl, "template", "", "certificate template: fixes issuer and challenge, checks the names")
	create.Flags().StringVar(&keyAlg, "key-algorithm", "", "key the agent generates (default: the template's first, or ecdsa-p256)")
	create.Flags().StringVar(&endpoint, "endpoint", "", "endpoint id for external verification (recommended)")
	create.Flags().StringSliceVar(&sans, "san", nil, "DNS name (repeatable)")
	_ = create.MarkFlagRequired("san")
	windowHelp := `maintenance window for activating new certificates, e.g. "Mon-Fri 02:00-05:00 Europe/Athens" (days: Mon..Sun, ranges, lists or daily)`
	emergencyHelp := "when no window is left before the current certificate gets too close to expiry: block (alert and wait) or renew_outside_window"
	create.Flags().StringVar(&window, "window", "", windowHelp)
	create.Flags().StringVar(&emergency, "emergency", "", emergencyHelp)
	create.Flags().StringVar(&challenge, "challenge", "", "how domain control is proven: http-01 (webroot, default) or dns-01 (the agent's dns_solvers; needed for wildcards)")
	setWindow := &cobra.Command{Use: "set-window DEPLOYMENT", Short: "Set or clear (--window \"\") the maintenance window (owner)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "PUT", "/api/v1/deployments/"+url.PathEscape(args[0])+"/window",
				map[string]any{"maintenance_window": window, "window_emergency": emergency}, func(raw json.RawMessage) {
					var d struct {
						ID        string
						Window    string `json:"maintenance_window"`
						Emergency string `json:"window_emergency"`
					}
					_ = json.Unmarshal(raw, &d)
					if d.Window == "" {
						fmt.Printf("Deployment %s has no maintenance window.\n", d.ID)
						return
					}
					fmt.Printf("Deployment %s: window %q, emergency %s.\n", d.ID, d.Window, d.Emergency)
				})
		})}
	setWindow.Flags().StringVar(&window, "window", "", windowHelp)
	setWindow.Flags().StringVar(&emergency, "emergency", "", emergencyHelp)
	_ = setWindow.MarkFlagRequired("window")
	renew := &cobra.Command{Use: "renew DEPLOYMENT", Short: "Start a renewal run now", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		return postAndPrint(c, "POST", "/api/v1/deployments/"+url.PathEscape(args[0])+"/renew", nil, func(raw json.RawMessage) {
			var r struct{ ID string }
			_ = json.Unmarshal(raw, &r)
			fmt.Printf("Started run %s. Follow it with `certloom run show %s`.\n", r.ID, r.ID)
		})
	})}
	requestApproval := &cobra.Command{Use: "request-approval DEPLOYMENT", Short: "Request approval when the current approval does not cover the deployment",
		Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "POST", "/api/v1/deployments/"+url.PathEscape(args[0])+"/request-approval", nil, func(raw json.RawMessage) {
				var a struct{ ID string }
				_ = json.Unmarshal(raw, &a)
				fmt.Printf("Opened approval request %s.\n", a.ID)
			})
		})}
	var revokeReason string
	revokeApproval := &cobra.Command{Use: "revoke-approval DEPLOYMENT", Short: "Revoke a deployment's approval; runs stop before changing the target",
		Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "POST", "/api/v1/deployments/"+url.PathEscape(args[0])+"/revoke-approval",
				map[string]any{"reason": revokeReason}, func(json.RawMessage) {
					fmt.Printf("Approval of deployment %s revoked.\n", args[0])
				})
		})}
	revokeApproval.Flags().StringVar(&revokeReason, "reason", "", "why (required)")
	_ = revokeApproval.MarkFlagRequired("reason")
	cmd.AddCommand(create, renew, setWindow, requestApproval, revokeApproval, listCmd("list", "List deployments", "/api/v1/deployments", "ID\tTARGET\tSANS\tAPPROVAL\tRENEW AT\tWHY",
		func(w io.Writer, raw json.RawMessage) {
			var d struct {
				ID, Target  string
				SANs        []string   `json:"sans"`
				RenewAt     *time.Time `json:"renew_at"`
				RenewReason string     `json:"renew_reason"`
				Approval    string     `json:"approval"`
			}
			_ = json.Unmarshal(raw, &d)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", d.ID, d.Target, strings.Join(d.SANs, ","), d.Approval, tsp(d.RenewAt), d.RenewReason)
		}))
	return cmd
}

func runCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "run", Short: "Renewal runs (workflow executions)"}
	show := &cobra.Command{Use: "show RUN", Short: "Show a run and its timeline", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		var raw json.RawMessage
		if err := c.do("GET", "/api/v1/runs/"+url.PathEscape(args[0]), nil, &raw); err != nil {
			return err
		}
		if asJSON() {
			_, err := os.Stdout.Write(raw)
			return err
		}
		var r struct {
			ID, State, Reason, Error string
			Issued                   *string `json:"issued_sha256"`
			Steps                    []struct {
				State, Detail string
				At            time.Time
			}
		}
		_ = json.Unmarshal(raw, &r)
		fmt.Printf("Run %s: %s (%s)\n", r.ID, strings.ToUpper(r.State), r.Reason)
		if r.Issued != nil {
			fmt.Printf("Issued: %s\n", *r.Issued)
		}
		if r.Error != "" {
			fmt.Printf("Error:  %s\n", r.Error)
		}
		for _, s := range r.Steps {
			fmt.Printf("  %s  %-14s %s\n", ts(s.At), s.State, s.Detail)
		}
		return nil
	})}
	cancel := &cobra.Command{Use: "cancel RUN", Short: "Cancel a run that has not changed the target yet", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "POST", "/api/v1/runs/"+url.PathEscape(args[0])+"/cancel", nil, func(json.RawMessage) { fmt.Println("Cancelled.") })
		})}
	cmd.AddCommand(show, cancel, listCmd("list", "List recent runs", "/api/v1/runs", "ID\tSTATE\tREASON\tUPDATED",
		func(w io.Writer, raw json.RawMessage) {
			var r struct {
				ID, State, Reason string
				UpdatedAt         time.Time `json:"updated_at"`
			}
			_ = json.Unmarshal(raw, &r)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", r.ID, r.State, r.Reason, ts(r.UpdatedAt))
		}))
	return cmd
}
