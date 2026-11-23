package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/spf13/cobra"
)

// observationsCmd prints what an agent last reported: IIS bindings, win-acme
// renewals, Certbot lineages and Kubernetes objects.
func observationsCmd() *cobra.Command {
	return &cobra.Command{Use: "observations AGENT", Short: "Show the IIS bindings, win-acme and Certbot renewals or Kubernetes objects an agent last reported",
		Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
			var v struct {
				ReportedAt *time.Time `json:"reported_at"`
				Inventory  *struct {
					Certbot    []agentproto.CertbotLineage `json:"certbot"`
					IIS        []agentproto.IISBinding     `json:"iis"`
					WinACME    []agentproto.WinACMERenewal `json:"win_acme"`
					Kubernetes *agentproto.KubeInventory   `json:"kubernetes"`
					Cloud      *agentproto.CloudInventory  `json:"cloud"`
				} `json:"inventory"`
			}
			if err := c.do("GET", "/api/v1/agents/"+url.PathEscape(args[0])+"/inventory", nil, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v)
			}
			if v.Inventory == nil {
				fmt.Println("No observations yet. Ask for one with `certloom agent inventory " + args[0] + "`.")
				return nil
			}
			fmt.Printf("Reported %s\n", ts(*v.ReportedAt))
			inv := v.Inventory
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			section := func(title, header string) {
				fmt.Fprintf(w, "\n%s\n%s\n", title, header)
			}
			if len(inv.IIS) > 0 {
				section("IIS bindings", "SITE\tBINDING\tSSL_FLAGS\tTHUMBPRINT\tSTORE")
				for _, b := range inv.IIS {
					fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", b.Site, b.Binding, b.SSLFlags, dash(b.CertHash), dash(b.CertStore))
				}
			}
			if len(inv.WinACME) > 0 {
				section("win-acme renewals", "ID\tHOSTS\tLAST\tOK\tINSTALLATION")
				for _, r := range inv.WinACME {
					fmt.Fprintf(w, "%s\t%s\t%s\t%t\t%s\n", r.ID, strings.Join(r.Hosts, ","), dash(r.LastRenewal), r.LastRenewalOK, strings.Join(r.Installation, ","))
				}
			}
			if len(inv.Certbot) > 0 {
				section("Certbot lineages", "NAME\tAUTHENTICATOR\tVERSION\tARI")
				for _, l := range inv.Certbot {
					fmt.Fprintf(w, "%s\t%s\t%s\t%t\n", l.Name, dash(l.Authenticator), dash(l.Version), l.ARIAware)
				}
			}
			if k := inv.Kubernetes; k != nil {
				section("Kubernetes certificates (cluster "+k.Cluster+")", "NAMESPACE\tNAME\tISSUER\tREADY\tNOT_AFTER\tRENEWAL")
				for _, ct := range k.Certificates {
					ready := "?"
					for _, cond := range ct.Conditions {
						if cond.Type == "Ready" {
							ready = cond.Status
						}
					}
					fmt.Fprintf(w, "%s\t%s\t%s/%s\t%s\t%s\t%s\n", ct.Namespace, ct.Name, ct.IssuerKind, ct.IssuerName, ready, dash(ct.NotAfter), dash(ct.RenewalTime))
				}
				if len(k.Bundles) > 0 {
					section("trust-manager bundles", "NAME\tTARGET")
					for _, b := range k.Bundles {
						fmt.Fprintf(w, "%s\t%s\n", b.Name, b.Target)
					}
				}
				for _, e := range k.Errors {
					fmt.Fprintf(w, "\nnot listed: %s\n", e)
				}
			}
			if inv.Cloud != nil {
				printCloud(w, inv.Cloud)
			}
			return w.Flush()
		})}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
