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

	"github.com/spf13/cobra"
)

// Secrets are never taken from arguments, which end up in shell history and
// process listings: they come from stdin or from a file.
type secretFlags struct {
	stdin, tokenStdin bool
	tsigFile          string
}

func (f *secretFlags) add(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.stdin, "secret-stdin", false, `read the secret as a JSON object from stdin, e.g. {"api_token":"..."}`)
	cmd.Flags().BoolVar(&f.tokenStdin, "api-token-stdin", false, "cloudflare: read the API token from stdin")
	cmd.Flags().StringVar(&f.tsigFile, "tsig-key-file", "", "rfc2136: BIND key file written by tsig-keygen")
}

// read returns the secret object, or nil when no secret flag was given.
func (f *secretFlags) read() (map[string]string, error) {
	n := 0
	for _, set := range []bool{f.stdin, f.tokenStdin, f.tsigFile != ""} {
		if set {
			n++
		}
	}
	switch {
	case n == 0:
		return nil, nil
	case n > 1:
		return nil, &usageError{"use only one of --secret-stdin, --api-token-stdin and --tsig-key-file"}
	case f.tsigFile != "":
		b, err := os.ReadFile(f.tsigFile)
		if err != nil {
			return nil, err
		}
		return map[string]string{"tsig_key": string(b)}, nil
	case f.tokenStdin:
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return nil, err
		}
		return map[string]string{"api_token": strings.TrimSpace(line)}, nil
	}
	var m map[string]string
	if err := json.NewDecoder(os.Stdin).Decode(&m); err != nil {
		return nil, fmt.Errorf("secret on stdin must be a JSON object of strings: %w", err)
	}
	return m, nil
}

func dnsSolverCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "dns-solver", Short: "Central DNS-01 solvers and their credentials (ADR-0018)"}
	var provider, plugin, pluginSHA, credential string
	var zones, config []string
	var sf secretFlags
	create := &cobra.Command{Use: "create NAME", Short: "Define a DNS-01 solver (dns:manage)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			cfg := map[string]any{}
			for _, kv := range config {
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					return &usageError{"--config takes key=value, got " + kv}
				}
				cfg[k] = v
			}
			sec, err := sf.read()
			if err != nil {
				return err
			}
			if sec == nil && credential != "ambient" {
				return &usageError{"a stored credential needs --tsig-key-file, --api-token-stdin or --secret-stdin (or use --credential ambient for plugins)"}
			}
			body := map[string]any{"name": args[0], "provider": provider, "plugin": plugin, "plugin_sha256": pluginSHA,
				"zones": zones, "config": cfg, "credential": credential}
			if sec != nil {
				body["secret"] = sec
			}
			return postAndPrint(c, "POST", "/api/v1/dns-solvers", body, func(raw json.RawMessage) {
				var d struct{ ID string }
				_ = json.Unmarshal(raw, &d)
				fmt.Printf("Created DNS solver %s (%s). Assign it with `certloom dns-solver assign %s AGENT`.\n", args[0], d.ID, args[0])
			})
		})}
	create.Flags().StringVar(&provider, "provider", "", "rfc2136, cloudflare or plugin")
	create.Flags().StringSliceVar(&zones, "zone", nil, "zone this solver may write (repeatable)")
	create.Flags().StringArrayVar(&config, "config", nil, "non-secret setting key=value, e.g. nameserver=10.0.0.53:53 (repeatable)")
	create.Flags().StringVar(&plugin, "plugin", "", "plugin: absolute path of the executable on the agent hosts")
	create.Flags().StringVar(&pluginSHA, "plugin-sha256", "", "plugin: SHA-256 the executable must match")
	create.Flags().StringVar(&credential, "credential", "stored", "stored, or ambient (the host's cloud identity; plugins only)")
	sf.add(create)
	_ = create.MarkFlagRequired("provider")
	_ = create.MarkFlagRequired("zone")

	var rf secretFlags
	setSecret := &cobra.Command{Use: "set-secret SOLVER", Short: "Replace (rotate) a stored secret (dns:manage)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			sec, err := rf.read()
			if err != nil {
				return err
			}
			if sec == nil {
				return &usageError{"pass --tsig-key-file, --api-token-stdin or --secret-stdin"}
			}
			if err := c.do("PUT", "/api/v1/dns-solvers/"+url.PathEscape(args[0])+"/secret", map[string]any{"secret": sec}, nil); err != nil {
				return err
			}
			fmt.Println("Secret replaced; the next issuance uses it.")
			return nil
		})}
	rf.add(setSecret)

	assign := func(use, short, method, done string) *cobra.Command {
		return &cobra.Command{Use: use + " SOLVER AGENT", Short: short, Args: cobra.ExactArgs(2), RunE: run(func(c *client, args []string) error {
			if err := c.do(method, "/api/v1/dns-solvers/"+url.PathEscape(args[0])+"/agents/"+url.PathEscape(args[1]), nil, nil); err != nil {
				return err
			}
			fmt.Printf(done+"\n", args[0], args[1])
			return nil
		})}
	}
	show := &cobra.Command{Use: "show SOLVER", Short: "Show a solver (never its secret)", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		var raw json.RawMessage
		if err := c.do("GET", "/api/v1/dns-solvers/"+url.PathEscape(args[0]), nil, &raw); err != nil {
			return err
		}
		return printJSON(raw)
	})}
	del := &cobra.Command{Use: "delete SOLVER", Short: "Delete a solver and its stored secret (dns:manage)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			if err := c.do("DELETE", "/api/v1/dns-solvers/"+url.PathEscape(args[0]), nil, nil); err != nil {
				return err
			}
			fmt.Println("Deleted.")
			return nil
		})}
	cmd.AddCommand(create, setSecret, show, del,
		assign("assign", "Make a solver available to an agent (dns:manage)", "PUT", "Assigned %s to %s."),
		assign("unassign", "Remove a solver from an agent (dns:manage)", "DELETE", "Removed %s from %s."),
		listCmd("list", "List DNS solvers", "/api/v1/dns-solvers", "ID\tNAME\tPROVIDER\tZONES\tCREDENTIAL\tAGENTS",
			func(w io.Writer, raw json.RawMessage) {
				var d struct {
					ID, Name, Provider, Credential string
					Zones, Agents                  []string
					HasSecret                      bool `json:"has_secret"`
				}
				_ = json.Unmarshal(raw, &d)
				cred := d.Credential
				if cred == "stored" && !d.HasSecret {
					cred = "stored (missing)"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%d\n", d.ID, d.Name, d.Provider, strings.Join(d.Zones, ","), cred, len(d.Agents))
			}))
	return cmd
}
