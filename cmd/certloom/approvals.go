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

type approvalView struct {
	ID           string          `json:"id"`
	ResourceID   string          `json:"resource_id"`
	SpecSHA256   string          `json:"spec_sha256"`
	Spec         json.RawMessage `json:"spec"`
	State        string          `json:"state"`
	RequestedBy  string          `json:"requested_by"`
	RequestedAt  time.Time       `json:"requested_at"`
	ExpiresAt    time.Time       `json:"expires_at"`
	DecidedBy    *string         `json:"decided_by"`
	Reason       string          `json:"reason"`
	RevokedBy    *string         `json:"revoked_by"`
	RevokeReason string          `json:"revoke_reason"`
}

func approvalCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "approval", Short: "Approval requests for deployments (separation of duties)"}
	var state, reason string
	list := listCmdPath("list", "List approval requests", func() string { return "/api/v1/approvals?state=" + url.QueryEscape(state) }, "ID\tSTATE\tDEPLOYMENT\tREQUESTED BY\tEXPIRES",
		func(w io.Writer, raw json.RawMessage) {
			var a approvalView
			_ = json.Unmarshal(raw, &a)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", a.ID, a.State, a.ResourceID, a.RequestedBy, a.ExpiresAt.Local().Format(time.DateTime))
		})
	list.Flags().StringVar(&state, "state", "requested", "requested, approved, denied, expired, revoked, or \"\" for all")

	show := &cobra.Command{Use: "show APPROVAL", Short: "Show a request and the exact spec it covers", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var raw json.RawMessage
			if err := c.do("GET", "/api/v1/approvals/"+url.PathEscape(args[0]), nil, &raw); err != nil {
				return err
			}
			if asJSON() {
				_, err := os.Stdout.Write(raw)
				return err
			}
			var a approvalView
			if err := json.Unmarshal(raw, &a); err != nil {
				return err
			}
			var spec struct {
				V       int
				Lineage string
				SANs    []string `json:"sans"`
				Purpose string
				Key     struct{ Algorithm string }
				Issuer  struct {
					ID, Kind, Profile string
					DirectoryURL      string `json:"directory_url"`
				}
				Target struct {
					Agent, Name, Type string
					Attributes        map[string]string
				}
			}
			_ = json.Unmarshal(a.Spec, &spec)
			fmt.Printf("Request:     %s (%s)\nDeployment:  %s\nRequested:   %s by %s\nExpires:     %s\n",
				a.ID, a.State, a.ResourceID, a.RequestedAt.Local().Format(time.DateTime), a.RequestedBy, a.ExpiresAt.Local().Format(time.DateTime))
			fmt.Printf("SANs:        %s\nPurpose:     %s, key %s\nLineage:     %s\n", strings.Join(spec.SANs, ", "), spec.Purpose, spec.Key.Algorithm, spec.Lineage)
			fmt.Printf("Issuer:      %s %s (%s, profile %q)\n", spec.Issuer.Kind, spec.Issuer.DirectoryURL, spec.Issuer.ID, spec.Issuer.Profile)
			fmt.Printf("Target:      %s on agent %s (%s)\n", spec.Target.Name, spec.Target.Agent, spec.Target.Type)
			for k, v := range spec.Target.Attributes {
				fmt.Printf("             %s = %s\n", k, v)
			}
			fmt.Printf("Spec digest: %s (v%d)\n", a.SpecSHA256, spec.V)
			if a.DecidedBy != nil {
				fmt.Printf("Decided by:  %s\n", *a.DecidedBy)
			}
			if a.Reason != "" {
				fmt.Printf("Reason:      %s\n", a.Reason)
			}
			if a.RevokedBy != nil {
				fmt.Printf("Revoked by:  %s: %s\n", *a.RevokedBy, a.RevokeReason)
			}
			return nil
		})}

	decide := func(verb string) *cobra.Command {
		c := &cobra.Command{Use: verb + " APPROVAL", Short: strings.ToUpper(verb[:1]) + verb[1:] + " a request made by someone else", Args: cobra.ExactArgs(1),
			RunE: run(func(c *client, args []string) error {
				return postAndPrint(c, "POST", "/api/v1/approvals/"+url.PathEscape(args[0])+"/"+verb, map[string]any{"reason": reason},
					func(raw json.RawMessage) {
						var a approvalView
						_ = json.Unmarshal(raw, &a)
						fmt.Printf("Request %s is now %s (deployment %s).\n", a.ID, a.State, a.ResourceID)
					})
			})}
		c.Flags().StringVar(&reason, "reason", "", "why (required to deny)")
		return c
	}
	cmd.AddCommand(list, show, decide("approve"), decide("deny"))
	return cmd
}
