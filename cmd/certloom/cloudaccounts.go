package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// cloudAccountFlags holds the settings flags shared by create and update.
type cloudAccountFlags struct {
	regions, vaults, locations, zones []string
	roleARN, externalID               string
	tenantID, clientID, project       string
	privateCA, cas, originCA          bool
	noCertManager                     bool
	interval                          time.Duration
}

func (f *cloudAccountFlags) add(cmd *cobra.Command) {
	fl := cmd.Flags()
	fl.StringSliceVar(&f.regions, "region", nil, "aws: region to read (repeatable)")
	fl.StringVar(&f.roleARN, "assume-role-arn", "", "aws: role to assume for this account")
	fl.StringVar(&f.externalID, "external-id", "", "aws: external id the role's trust policy requires")
	fl.BoolVar(&f.privateCA, "private-ca", false, "aws: also list AWS Private CA authorities")
	fl.StringSliceVar(&f.vaults, "vault", nil, "azure: Key Vault URL, e.g. https://corp-tls.vault.azure.net (repeatable)")
	fl.StringVar(&f.tenantID, "tenant-id", "", "azure: tenant of the service principal")
	fl.StringVar(&f.clientID, "client-id", "", "azure: application (client) id of the service principal")
	fl.StringVar(&f.project, "project", "", "gcp: project id")
	fl.StringSliceVar(&f.locations, "location", nil, "gcp: location (repeatable; default global)")
	fl.BoolVar(&f.cas, "cas", false, "gcp: also list CA Service authorities")
	fl.BoolVar(&f.noCertManager, "no-certificate-manager", false, "gcp: do not read Certificate Manager")
	fl.StringSliceVar(&f.zones, "zone", nil, "cloudflare: zone name (repeatable; default every zone the token sees)")
	fl.BoolVar(&f.originCA, "origin-ca", false, "cloudflare: also list Origin CA certificates")
	fl.DurationVar(&f.interval, "interval", time.Hour, "how often to scan (at least 5m)")
}

func (f *cloudAccountFlags) settings(provider string) (map[string]any, error) {
	switch provider {
	case "aws":
		return map[string]any{"regions": f.regions, "assume_role_arn": f.roleARN, "external_id": f.externalID, "private_ca": f.privateCA}, nil
	case "azure":
		return map[string]any{"vaults": f.vaults, "tenant_id": f.tenantID, "client_id": f.clientID}, nil
	case "gcp":
		s := map[string]any{"project": f.project, "locations": f.locations, "cas": f.cas}
		if f.noCertManager {
			s["certificate_manager"] = false
		}
		return s, nil
	case "cloudflare":
		return map[string]any{"zones": f.zones, "origin_ca": f.originCA}, nil
	}
	return nil, &usageError{"--provider must be aws, azure, gcp or cloudflare"}
}

// cloudSecretFlags reads a stored credential. Secrets never come from
// arguments: stdin or a file only.
type cloudSecretFlags struct {
	accessKeyID string
	stdin       bool
	keyFile     string
}

func (f *cloudSecretFlags) add(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.accessKeyID, "access-key-id", "", "aws: access key id; the secret access key is read from stdin")
	cmd.Flags().BoolVar(&f.stdin, "secret-stdin", false, "read the secret from stdin: azure client secret, cloudflare API token, aws secret access key")
	cmd.Flags().StringVar(&f.keyFile, "key-file", "", "gcp: service account key file (JSON)")
}

// read returns the secret object for provider, or nil when none was given.
func (f *cloudSecretFlags) read(provider string) (map[string]string, error) {
	if f.keyFile != "" {
		if provider != "gcp" {
			return nil, &usageError{"--key-file is for gcp"}
		}
		b, err := os.ReadFile(f.keyFile)
		if err != nil {
			return nil, err
		}
		return map[string]string{"service_account_key": string(b)}, nil
	}
	if !f.stdin {
		if f.accessKeyID != "" {
			return nil, &usageError{"--access-key-id needs --secret-stdin for the secret access key"}
		}
		return nil, nil
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	v := strings.TrimSpace(line)
	switch provider {
	case "aws":
		if f.accessKeyID == "" {
			return nil, &usageError{"aws needs --access-key-id with --secret-stdin"}
		}
		return map[string]string{"access_key_id": f.accessKeyID, "secret_access_key": v}, nil
	case "azure":
		return map[string]string{"client_secret": v}, nil
	case "cloudflare":
		return map[string]string{"api_token": v}, nil
	}
	return nil, &usageError{"for gcp use --key-file"}
}

func cloudAccountCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "cloud-account", Short: "Cloud accounts certloomd reads itself, without an agent (ADR-0034)"}
	var provider string
	var cf cloudAccountFlags
	var sf cloudSecretFlags
	create := &cobra.Command{Use: "create NAME", Short: "Add a cloud account (cloud:manage); the first scan starts at once", Args: cobra.ExactArgs(1),
		Example: `  certloom cloud-account create prod --provider aws --region us-east-1 --region eu-west-1
  certloom cloud-account create corp --provider azure --vault https://corp-tls.vault.azure.net
  certloom cloud-account create shop --provider gcp --project shop-prod --key-file key.json
  echo "$CF_TOKEN" | certloom cloud-account create cf --provider cloudflare --secret-stdin`,
		RunE: run(func(c *client, args []string) error {
			settings, err := cf.settings(provider)
			if err != nil {
				return err
			}
			sec, err := sf.read(provider)
			if err != nil {
				return err
			}
			body := map[string]any{"name": args[0], "provider": provider, "settings": settings,
				"interval_seconds": int(cf.interval.Seconds()), "credential": "ambient"}
			if sec != nil {
				body["credential"], body["secret"] = "stored", sec
			}
			return postAndPrint(c, "POST", "/api/v1/cloud-accounts", body, func(raw json.RawMessage) {
				var a struct{ ID string }
				_ = json.Unmarshal(raw, &a)
				fmt.Printf("Created cloud account %s (%s). The first scan is running; see it with `certloom cloud-account show %s`.\n", args[0], a.ID, args[0])
			})
		})}
	create.Flags().StringVar(&provider, "provider", "", "aws, azure, gcp or cloudflare")
	_ = create.MarkFlagRequired("provider")
	cf.add(create)
	sf.add(create)

	var uf cloudAccountFlags
	update := &cobra.Command{Use: "update NAME", Short: "Replace a cloud account's settings (cloud:manage); give every setting again", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var a struct{ Provider string }
			if err := c.do("GET", "/api/v1/cloud-accounts/"+url.PathEscape(args[0]), nil, &a); err != nil {
				return err
			}
			settings, err := uf.settings(a.Provider)
			if err != nil {
				return err
			}
			if err := c.do("PATCH", "/api/v1/cloud-accounts/"+url.PathEscape(args[0]), map[string]any{"settings": settings,
				"interval_seconds": int(uf.interval.Seconds())}, nil); err != nil {
				return err
			}
			fmt.Println("Updated; scanning again.")
			return nil
		})}
	uf.add(update)

	var rf cloudSecretFlags
	setSecret := &cobra.Command{Use: "set-secret NAME", Short: "Replace (rotate) a stored credential (cloud:manage)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var a struct{ Provider string }
			if err := c.do("GET", "/api/v1/cloud-accounts/"+url.PathEscape(args[0]), nil, &a); err != nil {
				return err
			}
			sec, err := rf.read(a.Provider)
			if err != nil {
				return err
			}
			if sec == nil {
				return &usageError{"pass --secret-stdin (with --access-key-id for aws) or --key-file"}
			}
			if err := c.do("PUT", "/api/v1/cloud-accounts/"+url.PathEscape(args[0])+"/secret", map[string]any{"secret": sec}, nil); err != nil {
				return err
			}
			fmt.Println("Secret replaced; scanning again.")
			return nil
		})}
	rf.add(setSecret)

	scan := &cobra.Command{Use: "scan NAME", Short: "Scan a cloud account now", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		if err := c.do("POST", "/api/v1/cloud-accounts/"+url.PathEscape(args[0])+"/scan", nil, nil); err != nil {
			return err
		}
		fmt.Printf("Scan queued; see the result with `certloom cloud-account show %s`.\n", args[0])
		return nil
	})}
	show := &cobra.Command{Use: "show NAME", Short: "Show what the last scan of a cloud account saw", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var v struct {
				ScannedAt *time.Time                 `json:"scanned_at"`
				Cloud     *agentproto.CloudInventory `json:"cloud"`
			}
			if err := c.do("GET", "/api/v1/cloud-accounts/"+url.PathEscape(args[0])+"/inventory", nil, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v)
			}
			if v.Cloud == nil || v.ScannedAt == nil {
				fmt.Println("Not scanned yet; the first scan takes up to a minute.")
				return nil
			}
			fmt.Printf("Scanned %s\n", ts(*v.ScannedAt))
			w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			printCloud(w, v.Cloud)
			return w.Flush()
		})}
	del := &cobra.Command{Use: "delete NAME", Short: "Delete a cloud account and its stored credential (cloud:manage)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			if err := c.do("DELETE", "/api/v1/cloud-accounts/"+url.PathEscape(args[0]), nil, nil); err != nil {
				return err
			}
			fmt.Println("Deleted.")
			return nil
		})}
	cmd.AddCommand(create, update, setSecret, scan, show, del,
		listCmd("list", "List cloud accounts", "/api/v1/cloud-accounts", "ID\tNAME\tPROVIDER\tCREDENTIAL\tLAST SCAN\tNEXT SCAN",
			func(w io.Writer, raw json.RawMessage) {
				var a struct {
					ID, Name, Provider, Credential string
					HasSecret                      bool       `json:"has_secret"`
					LastScanAt                     *time.Time `json:"last_scan_at"`
					NextScanAt                     time.Time  `json:"next_scan_at"`
				}
				_ = json.Unmarshal(raw, &a)
				cred := a.Credential
				if cred == "stored" && !a.HasSecret {
					cred = "stored (missing)"
				}
				last := "-"
				if a.LastScanAt != nil {
					last = ts(*a.LastScanAt)
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", a.ID, a.Name, a.Provider, cred, last, ts(a.NextScanAt))
			}))
	return cmd
}

// printCloud writes the objects and scope errors of a cloud inventory.
func printCloud(w io.Writer, c *agentproto.CloudInventory) {
	fmt.Fprintf(w, "\nCloud certificates\nPROVIDER\tSCOPE\tNAME\tNAMES\tNOT_AFTER\tSTATUS\tRENEWAL\n")
	for _, o := range c.Objects {
		name := o.Name
		if name == "" {
			name = o.ID
		}
		renewal := o.Renewal
		if o.RenewalReason != "" {
			renewal += " (" + o.RenewalReason + ")"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", o.Provider, o.Scope, name, dash(strings.Join(o.DNSNames, ",")),
			dash(o.NotAfter), dash(o.Status), dash(renewal))
	}
	for _, e := range c.Errors {
		fmt.Fprintf(w, "\nnot read: %s %s: %s\n", e.Provider, e.Scope, e.Error)
	}
}
