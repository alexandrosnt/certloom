package main

import (
	"fmt"
	"io"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type caCopy struct {
	SHA256      string    `json:"sha256"`
	IssuerKey   string    `json:"issuer_key"`
	Issuer      string    `json:"issuer"`
	NotAfter    time.Time `json:"not_after"`
	ChainExpiry time.Time `json:"chain_expiry"`
	SelfSigned  bool      `json:"self_signed"`
}

type caAuthority struct {
	Key      string    `json:"key"`
	Subject  string    `json:"subject"`
	Root     bool      `json:"root"`
	Expiry   time.Time `json:"expiry"`
	Copies   []caCopy  `json:"copies"`
	Parents  []string  `json:"parents"`
	Children []string  `json:"children"`
	InUse    bool      `json:"in_use"`
	Leaves   int       `json:"leaves"`
}

func caKind(root bool) string {
	if root {
		return "root"
	}
	return "intermediate"
}

// caCmd groups the CA inventory and rollover commands (ADR-0029).
func caCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "ca", Short: "Root and intermediate CA inventory and rollover planning"}

	var roots, inters, inUse bool
	ls := &cobra.Command{Use: "list", Short: "List CA authorities, soonest effective expiry first", Args: cobra.NoArgs,
		RunE: run(func(c *client, _ []string) error {
			q := url.Values{}
			switch {
			case roots && inters:
				return fmt.Errorf("use --roots or --intermediates, not both")
			case roots:
				q.Set("kind", "root")
			case inters:
				q.Set("kind", "intermediate")
			}
			if inUse {
				q.Set("in_use", "true")
			}
			var v struct {
				Items []caAuthority `json:"items"`
			}
			if err := c.do("GET", "/api/v1/authorities?"+q.Encode(), nil, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v.Items)
			}
			table("KEY\tKIND\tSUBJECT\tEXPIRY\tLEFT\tCOPIES\tLEAVES\tIN USE", func(w io.Writer) {
				for _, a := range v.Items {
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\t%d\t%t\n", short(a.Key), caKind(a.Root), a.Subject, ts(a.Expiry), left(a.Expiry),
						len(a.Copies), a.Leaves, a.InUse)
				}
			})
			return nil
		})}
	ls.Flags().BoolVar(&roots, "roots", false, "only root CAs")
	ls.Flags().BoolVar(&inters, "intermediates", false, "only intermediate CAs")
	ls.Flags().BoolVar(&inUse, "in-use", false, "only CAs above a lineage's current certificate or a served leaf")

	impact := func(use, help string, full bool) *cobra.Command {
		return &cobra.Command{Use: use + " CA", Short: help, Args: cobra.ExactArgs(1),
			RunE: run(func(c *client, args []string) error {
				var v struct {
					Authority caAuthority `json:"authority"`
					InUse     bool        `json:"in_use"`
					Below     []string    `json:"authorities_below"`
					Lineages  []struct {
						LineageName string    `json:"lineage_name"`
						CommonName  string    `json:"common_name"`
						NotAfter    time.Time `json:"not_after"`
						ChainExpiry time.Time `json:"chain_expiry"`
						Outlives    bool      `json:"outlives_chain"`
						Deployments []struct {
							ID string `json:"id"`
						} `json:"deployments"`
					} `json:"lineages"`
					Endpoints []struct {
						Host     string    `json:"host"`
						Port     int       `json:"port"`
						NotAfter time.Time `json:"not_after"`
					} `json:"endpoints"`
					Issuers []string `json:"issuers"`
				}
				if err := c.do("GET", "/api/v1/authorities/"+url.PathEscape(args[0]), nil, &v); err != nil {
					return err
				}
				if asJSON() {
					return printJSON(v)
				}
				a := v.Authority
				fmt.Printf("%s %s\nkey     %s\nexpiry  %s (%s)\nin use  %t\n", caKind(a.Root), a.Subject, a.Key, ts(a.Expiry), left(a.Expiry), v.InUse)
				if !full {
					fmt.Println()
					table("COPY\tISSUER\tNOT AFTER\tCHAIN EXPIRY", func(w io.Writer) {
						for _, cp := range a.Copies {
							fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", short(cp.SHA256), cp.Issuer, ts(cp.NotAfter), ts(cp.ChainExpiry))
						}
					})
					for _, p := range a.Parents {
						fmt.Printf("parent  %s\n", short(p))
					}
					for _, ch := range a.Children {
						fmt.Printf("child   %s\n", short(ch))
					}
					return nil
				}
				if len(v.Below) > 0 {
					fmt.Printf("below   %d authorities\n", len(v.Below))
				}
				fmt.Printf("\nLineages (%d)\n", len(v.Lineages))
				table("LINEAGE\tCN\tNOT AFTER\tCHAIN EXPIRY\tACTION\tDEPLOYMENTS", func(w io.Writer) {
					for _, l := range v.Lineages {
						action := "renews in time"
						if l.Outlives {
							action = "RENEW BEFORE " + ts(l.ChainExpiry)
						}
						ids := make([]string, 0, len(l.Deployments))
						for _, d := range l.Deployments {
							ids = append(ids, d.ID)
						}
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", l.LineageName, dash(l.CommonName), ts(l.NotAfter), ts(l.ChainExpiry), action,
							dash(strings.Join(ids, ",")))
					}
				})
				fmt.Printf("\nEndpoints (%d)\n", len(v.Endpoints))
				table("ENDPOINT\tLEAF NOT AFTER", func(w io.Writer) {
					for _, e := range v.Endpoints {
						fmt.Fprintf(w, "%s:%d\t%s\n", e.Host, e.Port, ts(e.NotAfter))
					}
				})
				if len(v.Issuers) > 0 {
					fmt.Printf("\nIssuers: %s\n", strings.Join(v.Issuers, ", "))
				}
				return nil
			})}
	}
	show := impact("show", "Show an authority's copies, parents and children (key or 8+ character prefix)", false)
	imp := impact("impact", "List the lineages, deployments, endpoints and issuers that chain through an authority", true)

	var within string
	plan := &cobra.Command{Use: "plan", Short: "List authorities in use that expire within a window, with what must be renewed by when", Args: cobra.NoArgs,
		RunE: run(func(c *client, _ []string) error {
			var v struct {
				Items []struct {
					Key       string     `json:"key"`
					Subject   string     `json:"subject"`
					Root      bool       `json:"root"`
					Expiry    time.Time  `json:"expiry"`
					Lineages  int        `json:"lineages"`
					Outliving int        `json:"outliving_lineages"`
					Endpoints int        `json:"endpoints"`
					RenewBy   *time.Time `json:"renew_by"`
				} `json:"items"`
			}
			if err := c.do("GET", "/api/v1/authorities/plan?within="+url.QueryEscape(within), nil, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v.Items)
			}
			if len(v.Items) == 0 {
				fmt.Printf("No CA in use expires within %s.\n", within)
				return nil
			}
			table("KEY\tKIND\tSUBJECT\tEXPIRY\tLINEAGES\tOUTLIVING\tENDPOINTS\tRENEW BY", func(w io.Writer) {
				for _, it := range v.Items {
					by := "-"
					if it.RenewBy != nil {
						by = ts(*it.RenewBy)
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n", short(it.Key), caKind(it.Root), it.Subject, ts(it.Expiry), it.Lineages,
						it.Outliving, it.Endpoints, by)
				}
			})
			return nil
		})}
	plan.Flags().StringVar(&within, "within", "365d", "planning window, e.g. 180d")

	var all, dry bool
	renew := &cobra.Command{Use: "renew-affected CA", Short: "Start renewal runs for deployments whose certificate outlives this CA's chain (--all: every deployment under it)",
		Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
			var v struct {
				DryRun bool `json:"dry_run"`
				Items  []struct {
					DeploymentID string `json:"deployment_id"`
					Lineage      string `json:"lineage"`
					RunID        string `json:"run_id"`
					Skipped      string `json:"skipped"`
				} `json:"items"`
			}
			body := map[string]bool{"all": all, "dry_run": dry}
			if err := c.do("POST", "/api/v1/authorities/"+url.PathEscape(args[0])+"/renew-affected", body, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v)
			}
			if len(v.Items) == 0 {
				fmt.Println("Nothing to renew.")
				return nil
			}
			table("DEPLOYMENT\tLINEAGE\tRESULT", func(w io.Writer) {
				for _, it := range v.Items {
					res := "run " + it.RunID
					switch {
					case it.Skipped != "":
						res = "skipped: " + it.Skipped
					case v.DryRun:
						res = "would renew"
					}
					fmt.Fprintf(w, "%s\t%s\t%s\n", it.DeploymentID, it.Lineage, res)
				}
			})
			return nil
		})}
	renew.Flags().BoolVar(&all, "all", false, "renew every deployment under the CA, not only those that outlive the chain")
	renew.Flags().BoolVar(&dry, "dry-run", false, "list what would be renewed without starting runs")

	cmd.AddCommand(ls, show, imp, plan, renew)
	return cmd
}
