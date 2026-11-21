package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/alexandrosnt/certloom/internal/policy"
	"github.com/spf13/cobra"
)

type exceptionView struct {
	ID                   string     `json:"id"`
	SubjectType          string     `json:"subject_type"`
	SubjectID            string     `json:"subject_id"`
	Check                string     `json:"check"`
	MaxSeverity          string     `json:"max_severity"`
	Rationale            string     `json:"rationale"`
	CompensatingControls string     `json:"compensating_controls"`
	RiskOwner            string     `json:"risk_owner"`
	RemediationOwner     string     `json:"remediation_owner"`
	RemediationDue       *time.Time `json:"remediation_due"`
	TrackingRef          string     `json:"tracking_ref"`
	Fingerprint          string     `json:"fingerprint"`
	ExpiresAt            time.Time  `json:"expires_at"`
	State                string     `json:"state"`
	RequestedBy          string     `json:"requested_by"`
	ApprovedBy           *string    `json:"approved_by"`
	EndedAt              *time.Time `json:"ended_at"`
	EndedBy              *string    `json:"ended_by"`
	EndReason            string     `json:"end_reason"`
}

func exceptionCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "exception", Short: "Policy exceptions: approved, time-bound acceptance of one finding"}
	var subjectType, subjectID, check, rationale, controls, riskOwner, remOwner, remDue, trackingRef, state, reason string
	var forDur string
	request := &cobra.Command{Use: "request", Short: "Request an exception for an open finding; someone else must approve it",
		RunE: run(func(c *client, _ []string) error {
			d, err := policy.ParseDuration(forDur)
			if err != nil {
				return err
			}
			body := map[string]any{"subject_type": subjectType, "subject_id": subjectID, "check": check, "rationale": rationale,
				"compensating_controls": controls, "risk_owner": riskOwner, "remediation_owner": remOwner, "remediation_due": remDue,
				"tracking_ref": trackingRef, "expires_at": time.Now().Add(d).UTC().Format(time.RFC3339)}
			return postAndPrint(c, "POST", "/api/v1/exceptions", body, func(raw json.RawMessage) {
				var v struct {
					Exception exceptionView
					Approval  struct{ ID string }
				}
				_ = json.Unmarshal(raw, &v)
				fmt.Printf("Requested exception %s; approval request %s waits for someone else (`certloom approval show %s`).\n",
					v.Exception.ID, v.Approval.ID, v.Approval.ID)
			})
		})}
	request.Flags().StringVar(&subjectType, "subject-type", "endpoint", "certificate, endpoint or lineage")
	request.Flags().StringVar(&subjectID, "subject", "", "subject id (see `certloom findings`)")
	request.Flags().StringVar(&check, "check", "", "check id, e.g. weak_key")
	request.Flags().StringVar(&rationale, "rationale", "", "why the risk is acceptable for now (required)")
	request.Flags().StringVar(&controls, "compensating-controls", "", "what reduces the risk meanwhile")
	request.Flags().StringVar(&riskOwner, "risk-owner", "", "person accountable for accepting the risk (required)")
	request.Flags().StringVar(&remOwner, "remediation-owner", "", "who fixes it, where a fix is possible")
	request.Flags().StringVar(&remDue, "remediation-due", "", "planned fix date, e.g. 2027-01-31")
	request.Flags().StringVar(&trackingRef, "tracking-ref", "", "ticket or change reference for the fix")
	request.Flags().StringVar(&forDur, "for", "30d", "how long, e.g. 30d (at most policy exceptions.maxDuration)")
	for _, f := range []string{"subject", "check", "rationale", "risk-owner"} {
		_ = request.MarkFlagRequired(f)
	}

	list := listCmdPath("list", "List exceptions", func() string { return "/api/v1/exceptions?state=" + url.QueryEscape(state) },
		"ID\tSTATE\tCHECK\tSUBJECT\tMAX\tEXPIRES", func(w io.Writer, raw json.RawMessage) {
			var e exceptionView
			_ = json.Unmarshal(raw, &e)
			fmt.Fprintf(w, "%s\t%s\t%s\t%s %s\t%s\t%s\n", e.ID, e.State, e.Check, e.SubjectType, e.SubjectID, e.MaxSeverity,
				e.ExpiresAt.Local().Format(time.DateOnly))
		})
	list.Flags().StringVar(&state, "state", "", "requested, active, denied, expired, revoked (default all)")

	show := &cobra.Command{Use: "show EXCEPTION", Short: "Show an exception", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		var raw json.RawMessage
		if err := c.do("GET", "/api/v1/exceptions/"+url.PathEscape(args[0]), nil, &raw); err != nil {
			return err
		}
		if asJSON() {
			_, err := os.Stdout.Write(raw)
			return err
		}
		var e exceptionView
		if err := json.Unmarshal(raw, &e); err != nil {
			return err
		}
		fmt.Printf("Exception:   %s (%s)\nCovers:      %s on %s %s, up to %s\nExpires:     %s\nRequested:   %s\n",
			e.ID, e.State, e.Check, e.SubjectType, e.SubjectID, e.MaxSeverity, e.ExpiresAt.Local().Format(time.DateTime), e.RequestedBy)
		if e.ApprovedBy != nil {
			fmt.Printf("Approved by: %s\n", *e.ApprovedBy)
		}
		fmt.Printf("Rationale:   %s\n", e.Rationale)
		if e.CompensatingControls != "" {
			fmt.Printf("Controls:    %s\n", e.CompensatingControls)
		}
		fmt.Printf("Risk owner:  %s\n", e.RiskOwner)
		if e.RemediationOwner != "" || e.RemediationDue != nil || e.TrackingRef != "" {
			due := "-"
			if e.RemediationDue != nil {
				due = e.RemediationDue.Format(time.DateOnly)
			}
			fmt.Printf("Remediation: %s, due %s, ref %s\n", e.RemediationOwner, due, e.TrackingRef)
		}
		fmt.Printf("Condition:   %s\n", e.Fingerprint)
		if e.EndedAt != nil {
			by := "system"
			if e.EndedBy != nil {
				by = *e.EndedBy
			}
			fmt.Printf("Ended:       %s by %s: %s\n", e.EndedAt.Local().Format(time.DateTime), by, e.EndReason)
		}
		return nil
	})}

	revoke := &cobra.Command{Use: "revoke EXCEPTION", Short: "End an exception early; its alerts open again", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "POST", "/api/v1/exceptions/"+url.PathEscape(args[0])+"/revoke", map[string]any{"reason": reason},
				func(json.RawMessage) { fmt.Printf("Exception %s revoked.\n", args[0]) })
		})}
	revoke.Flags().StringVar(&reason, "reason", "", "why (required)")
	_ = revoke.MarkFlagRequired("reason")

	cmd.AddCommand(request, list, show, revoke)
	return cmd
}
