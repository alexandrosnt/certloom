package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"

	"github.com/alexandrosnt/certloom/internal/certtemplate"
	"github.com/spf13/cobra"
)

type templatePlan struct {
	Applied        bool   `json:"applied"`
	Name           string `json:"name"`
	Version        int    `json:"version"`
	CurrentVersion int    `json:"current_version"`
	Changes        []struct {
		Deployment    string   `json:"deployment"`
		Changed       []string `json:"changed"`
		NeedsApproval bool     `json:"needs_approval"`
	} `json:"changes"`
	Violations []struct {
		Deployment string   `json:"deployment"`
		Problems   []string `json:"problems"`
	} `json:"violations"`
}

func printTemplatePlan(p templatePlan) {
	switch {
	case p.Applied:
		fmt.Printf("Applied template %s version %d (was %d).\n", p.Name, p.Version, p.CurrentVersion)
	case p.CurrentVersion == 0:
		fmt.Printf("Template %s is new.\n", p.Name)
	default:
		fmt.Printf("Template %s, current version %d.\n", p.Name, p.CurrentVersion)
	}
	if len(p.Changes) == 0 && len(p.Violations) == 0 {
		fmt.Println("No deployment changes.")
	}
	for _, c := range p.Changes {
		note := ""
		if c.NeedsApproval {
			note = " (needs a new approval)"
		}
		fmt.Printf("  ~ %s: %s%s\n", c.Deployment, strings.Join(c.Changed, ", "), note)
	}
	for _, v := range p.Violations {
		fmt.Printf("  ! %s: %s\n", v.Deployment, strings.Join(v.Problems, "; "))
	}
	if len(p.Violations) > 0 {
		fmt.Println("Apply is refused until these deployments or the template are fixed.")
	}
}

func templateCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "template", Short: "Certificate templates: issuer, challenge, keys and allowed names (ADR-0020)"}
	validate := &cobra.Command{Use: "validate FILE", Short: "Validate a template file locally (no server needed)", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			src, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			if _, err := certtemplate.Parse(src); err != nil {
				return &usageError{strings.ReplaceAll(err.Error(), "; ", "\n  - ")}
			}
			fmt.Println("valid")
			return nil
		}}
	send := func(apply bool) func(c *client, args []string) error {
		return func(c *client, args []string) error {
			src, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			path := "/api/v1/templates"
			if !apply {
				path += "?dry_run=true"
			}
			var raw json.RawMessage
			if err := c.doRaw("PUT", path, "application/yaml", src, &raw); err != nil {
				return err
			}
			if asJSON() {
				_, err := os.Stdout.Write(raw)
				return err
			}
			var p templatePlan
			if err := json.Unmarshal(raw, &p); err != nil {
				return err
			}
			printTemplatePlan(p)
			return nil
		}
	}
	plan := &cobra.Command{Use: "plan FILE", Short: "Show which deployments applying a template would change (dry run)", Args: cobra.ExactArgs(1), RunE: run(send(false))}
	apply := &cobra.Command{Use: "apply FILE", Short: "Apply a template as a new version (templates:manage)", Args: cobra.ExactArgs(1), RunE: run(send(true))}
	show := &cobra.Command{Use: "show TEMPLATE", Short: "Print a template's current source", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		var t struct {
			Name, Source string
			Version      int
			Deployments  int
		}
		var raw json.RawMessage
		if err := c.do("GET", "/api/v1/templates/"+url.PathEscape(args[0]), nil, &raw); err != nil {
			return err
		}
		if asJSON() {
			return printJSON(raw)
		}
		_ = json.Unmarshal(raw, &t)
		fmt.Printf("# template %s version %d, used by %d deployment(s)\n%s", t.Name, t.Version, t.Deployments, t.Source)
		return nil
	})}
	del := &cobra.Command{Use: "delete TEMPLATE", Short: "Delete a template no deployment uses (templates:manage)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			if err := c.do("DELETE", "/api/v1/templates/"+url.PathEscape(args[0]), nil, nil); err != nil {
				return err
			}
			fmt.Printf("Deleted template %s.\n", args[0])
			return nil
		})}
	list := listCmd("list", "List templates", "/api/v1/templates", "NAME\tVERSION\tISSUER\tCHALLENGE\tDEPLOYMENTS",
		func(w io.Writer, raw json.RawMessage) {
			var t struct {
				Name        string
				Version     int
				Deployments int
				Document    certtemplate.Document
			}
			_ = json.Unmarshal(raw, &t)
			fmt.Fprintf(w, "%s\t%d\t%s\t%s\t%d\n", t.Name, t.Version, t.Document.Spec.Issuer, t.Document.Spec.Challenge, t.Deployments)
		})
	cmd.AddCommand(validate, plan, apply, show, list, del)
	return cmd
}
