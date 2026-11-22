package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/spf13/cobra"
	"sigs.k8s.io/yaml"
)

// trustFile is the YAML form of a trust bundle. Anchor files are read
// relative to the YAML file.
type trustFile struct {
	Name    string `json:"name"`
	Team    string `json:"team,omitempty"`
	Anchors []struct {
		File string `json:"file,omitempty"`
		PEM  string `json:"pem,omitempty"`
	} `json:"anchors"`
	Stores []struct {
		Agent string `json:"agent"`
		Store string `json:"store"`
	} `json:"stores"`
}

type trustPlan struct {
	Bundle      string `json:"bundle"`
	FromVersion int    `json:"from_version"`
	ToVersion   int    `json:"to_version"`
	Added       []struct {
		Subject  string    `json:"subject"`
		NotAfter time.Time `json:"not_after"`
	} `json:"added"`
	Removed []struct {
		Subject string `json:"subject"`
	} `json:"removed"`
	StoresAdded   []map[string]string `json:"stores_added"`
	StoresRemoved []map[string]string `json:"stores_removed"`
	Blockers      []string            `json:"blockers"`
	Applied       bool                `json:"applied"`
	Forced        bool                `json:"forced"`
}

func readTrustFile(path string) (map[string]any, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f trustFile
	if err := yaml.UnmarshalStrict(src, &f); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	anchors := []string{}
	for i, a := range f.Anchors {
		switch {
		case a.File != "" && a.PEM != "":
			return nil, fmt.Errorf("anchor %d: set file or pem, not both", i+1)
		case a.File != "":
			p := a.File
			if !filepath.IsAbs(p) {
				p = filepath.Join(filepath.Dir(path), p)
			}
			b, err := os.ReadFile(p)
			if err != nil {
				return nil, err
			}
			anchors = append(anchors, string(b))
		case a.PEM != "":
			anchors = append(anchors, a.PEM)
		default:
			return nil, fmt.Errorf("anchor %d: file or pem is required", i+1)
		}
	}
	stores := []map[string]string{}
	for _, s := range f.Stores {
		stores = append(stores, map[string]string{"agent": s.Agent, "store": s.Store})
	}
	return map[string]any{"name": f.Name, "team": f.Team, "anchors": anchors, "stores": stores}, nil
}

func printTrustPlan(p trustPlan) {
	verb := "would change"
	if p.Applied {
		verb = "changed"
	}
	fmt.Printf("Bundle %s: version %d -> %d (%s)\n", p.Bundle, p.FromVersion, p.ToVersion, verb)
	for _, a := range p.Added {
		fmt.Printf("  + anchor %s (until %s)\n", a.Subject, ts(a.NotAfter))
	}
	for _, a := range p.Removed {
		fmt.Printf("  - anchor %s\n", a.Subject)
	}
	for _, s := range p.StoresAdded {
		fmt.Printf("  + store %s/%s\n", s["agent"], s["store"])
	}
	for _, s := range p.StoresRemoved {
		fmt.Printf("  - store %s/%s (keeps its anchors)\n", s["agent"], s["store"])
	}
	for _, b := range p.Blockers {
		fmt.Printf("  ! %s\n", b)
	}
	if p.Forced {
		fmt.Println("  Removal forced past the checks above.")
	}
}

// trustCmd manages trust bundles (ADR-0030).
func trustCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "trust-bundle", Short: "Trust bundles pushed to agent trust stores"}

	plan := &cobra.Command{Use: "plan FILE", Short: "Show what applying a bundle file would change", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			body, err := readTrustFile(args[0])
			if err != nil {
				return err
			}
			body["dry_run"] = true
			var p trustPlan
			if err := c.do("PUT", "/api/v1/trust-bundles", body, &p); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(p)
			}
			printTrustPlan(p)
			return nil
		})}

	var force bool
	var reason string
	apply := &cobra.Command{Use: "apply FILE", Short: "Apply a bundle file: new version, store assignments, delivery to the agents (trust:manage)",
		Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
			body, err := readTrustFile(args[0])
			if err != nil {
				return err
			}
			// Plan first so the apply is made against the version shown.
			body["dry_run"] = true
			var p trustPlan
			if err := c.do("PUT", "/api/v1/trust-bundles", body, &p); err != nil {
				return err
			}
			if len(p.Blockers) > 0 && !force {
				printTrustPlan(p)
				return errors.New("removing anchors now is unsafe; fix the blockers or pass --force --reason")
			}
			body["dry_run"], body["base_version"], body["force"], body["reason"] = false, p.FromVersion, force, reason
			if err := c.do("PUT", "/api/v1/trust-bundles", body, &p); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(p)
			}
			printTrustPlan(p)
			return nil
		})}
	apply.Flags().BoolVar(&force, "force", false, "remove anchors even though a CA in use or an unconfirmed store depends on them")
	apply.Flags().StringVar(&reason, "reason", "", "why the removal is forced (audited)")

	ls := listCmd("list", "List trust bundles", "/api/v1/trust-bundles", "NAME\tVERSION\tCREATED", func(w io.Writer, raw json.RawMessage) {
		var b struct {
			Name           string    `json:"name"`
			CurrentVersion int       `json:"current_version"`
			CreatedAt      time.Time `json:"created_at"`
		}
		_ = json.Unmarshal(raw, &b)
		fmt.Fprintf(w, "%s\t%d\t%s\n", b.Name, b.CurrentVersion, ts(b.CreatedAt))
	})

	show := &cobra.Command{Use: "show BUNDLE", Short: "Show a bundle's anchors and stores", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var v struct {
				Name           string `json:"name"`
				CurrentVersion int    `json:"current_version"`
				Digest         string `json:"digest"`
				Anchors        []struct {
					SHA256   string    `json:"sha256"`
					Subject  string    `json:"subject"`
					NotAfter time.Time `json:"not_after"`
				} `json:"anchors"`
				Stores []trustStoreRow `json:"stores"`
			}
			if err := c.do("GET", "/api/v1/trust-bundles/"+url.PathEscape(args[0]), nil, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v)
			}
			fmt.Printf("%s version %d (digest %s)\n\n", v.Name, v.CurrentVersion, short(v.Digest))
			table("ANCHOR\tSUBJECT\tNOT AFTER", func(w io.Writer) {
				for _, a := range v.Anchors {
					fmt.Fprintf(w, "%s\t%s\t%s\n", short(a.SHA256), a.Subject, ts(a.NotAfter))
				}
			})
			fmt.Println()
			printTrustStores(v.Stores)
			return nil
		})}

	status := &cobra.Command{Use: "status", Short: "Show every assigned trust store and the version it confirmed", Args: cobra.NoArgs,
		RunE: run(func(c *client, _ []string) error {
			var v struct {
				Items []trustStoreRow `json:"items"`
			}
			if err := c.do("GET", "/api/v1/trust-bundles/status", nil, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v.Items)
			}
			printTrustStores(v.Items)
			return nil
		})}

	del := &cobra.Command{Use: "delete BUNDLE", Short: "Delete a bundle no store is assigned to", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return c.do("DELETE", "/api/v1/trust-bundles/"+url.PathEscape(args[0]), nil, nil)
		})}

	cmd.AddCommand(plan, apply, ls, show, status, del)
	return cmd
}

type trustStoreRow struct {
	Bundle           string     `json:"bundle"`
	Agent            string     `json:"agent"`
	Store            string     `json:"store"`
	CurrentVersion   int        `json:"current_version"`
	ConfirmedVersion int        `json:"confirmed_version"`
	ConfirmedAt      *time.Time `json:"confirmed_at"`
	LastError        string     `json:"last_error"`
}

func printTrustStores(rows []trustStoreRow) {
	table("BUNDLE\tAGENT/STORE\tVERSION\tCONFIRMED\tSTATE", func(w io.Writer) {
		for _, r := range rows {
			state := "in sync"
			switch {
			case r.LastError != "":
				state = "error: " + r.LastError
			case r.ConfirmedVersion != r.CurrentVersion:
				state = "pending"
			}
			at := "-"
			if r.ConfirmedAt != nil {
				at = ts(*r.ConfirmedAt)
			}
			fmt.Fprintf(w, "%s\t%s/%s\t%d\t%d (%s)\t%s\n", r.Bundle, r.Agent, r.Store, r.CurrentVersion, r.ConfirmedVersion, at, state)
		}
	})
}

// agentTrustStoresCmd lists the trust stores an agent declared in its config.
func agentTrustStoresCmd() *cobra.Command {
	return &cobra.Command{Use: "trust-stores AGENT", Short: "Show the trust stores an agent declared (ADR-0030)",
		Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
			var v struct {
				Items []struct {
					ID           string               `json:"id"`
					Name         string               `json:"name"`
					Capabilities agentproto.Heartbeat `json:"capabilities"`
				} `json:"items"`
			}
			if err := c.do("GET", "/api/v1/agents", nil, &v); err != nil {
				return err
			}
			for _, a := range v.Items {
				if a.ID != args[0] && a.Name != args[0] {
					continue
				}
				if asJSON() {
					return printJSON(a.Capabilities.TrustStores)
				}
				if len(a.Capabilities.TrustStores) == 0 {
					fmt.Println("The agent declares no trust stores (trust_stores in its config).")
					return nil
				}
				table("NAME\tTYPE\tMODE", func(w io.Writer) {
					for _, s := range a.Capabilities.TrustStores {
						fmt.Fprintf(w, "%s\t%s\t%s\n", s.Name, s.Type, s.Mode)
					}
				})
				return nil
			}
			return fmt.Errorf("no agent with id or name %q", args[0])
		})}
}
