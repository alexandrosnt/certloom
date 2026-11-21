package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/alexandrosnt/certloom/internal/policy"
	"github.com/spf13/cobra"
)

type policyPlan struct {
	Applied        bool `json:"applied"`
	Version        int  `json:"version"`
	CurrentVersion int  `json:"current_version"`
	Evaluated      int  `json:"certificates_evaluated"`
	Changes        []struct {
		Check, From, To string
		Count           int
	} `json:"changes"`
}

func printPlan(p policyPlan) {
	fmt.Printf("Evaluated %d certificates against current policy v%d.\n", p.Evaluated, p.CurrentVersion)
	if len(p.Changes) == 0 {
		fmt.Println("No finding would change.")
	}
	for _, c := range p.Changes {
		from, to := c.From, c.To
		if from == "" {
			from = "none"
		}
		if to == "" {
			to = "none"
		}
		fmt.Printf("  %-18s %8s -> %-8s  %d certificate(s)\n", c.Check, from, to, c.Count)
	}
	if p.Applied {
		fmt.Printf("Applied as policy v%d. Findings update on the next probe or sweep.\n", p.Version)
	}
}

func policyCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "policy", Short: "Monitoring policy (versioned YAML)"}
	get := &cobra.Command{Use: "get", Short: "Print the active policy as YAML", RunE: run(func(c *client, _ []string) error {
		var pv struct {
			Version  int             `json:"version"`
			Document json.RawMessage `json:"document"`
		}
		if err := c.do("GET", "/api/v1/policy", nil, &pv); err != nil {
			return err
		}
		if asJSON() {
			return printJSON(pv)
		}
		var d policy.Document
		if err := json.Unmarshal(pv.Document, &d); err != nil {
			return err
		}
		y, err := d.YAML()
		if err != nil {
			return err
		}
		fmt.Printf("# active policy version %d (0 = built-in defaults)\n%s", pv.Version, y)
		return nil
	})}
	validate := &cobra.Command{Use: "validate FILE", Short: "Validate a policy file locally (no server needed)", Args: cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			src, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			if _, err := policy.Parse(src); err != nil {
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
			path := "/api/v1/policy"
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
			var p policyPlan
			if err := json.Unmarshal(raw, &p); err != nil {
				return err
			}
			printPlan(p)
			return nil
		}
	}
	plan := &cobra.Command{Use: "plan FILE", Short: "Show what applying a policy would change (dry run)", Args: cobra.ExactArgs(1), RunE: run(send(false))}
	apply := &cobra.Command{Use: "apply FILE", Short: "Apply a policy as a new version (owner)", Args: cobra.ExactArgs(1), RunE: run(send(true))}
	cmd.AddCommand(get, validate, plan, apply)
	return cmd
}
