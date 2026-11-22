package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// agentPluginsCmd lists the plugins an agent reported in its last heartbeat
// (ADR-0027). Plugins are installed on the host; the control plane only
// shows them.
func agentPluginsCmd() *cobra.Command {
	return &cobra.Command{Use: "plugins AGENT", Short: "Show the plugins an agent can run (installed and signed, or pinned by path)",
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
					return printJSON(a.Capabilities.Plugins)
				}
				if len(a.Capabilities.Plugins) == 0 {
					fmt.Println("The agent reports no plugins.")
					return nil
				}
				table("NAME\tVERSION\tKINDS\tTRUST\tSIGNER\tSHA256", func(w io.Writer) {
					for _, p := range a.Capabilities.Plugins {
						trust, signer := p.Trust, p.Signer
						if p.Pinned {
							trust, signer = "pinned", "-"
						}
						fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, dash(p.Version), strings.Join(p.Kinds, ","), trust, signer, short(p.SHA256))
					}
				})
				return nil
			}
			return fmt.Errorf("no agent with id or name %q", args[0])
		})}
}
