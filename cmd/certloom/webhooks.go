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

func webhookCmd() *cobra.Command {
	cmd := &cobra.Command{Use: "webhook", Short: "Event webhooks: typed events signed per Standard Webhooks (ADR-0021)"}
	var urlFlag string
	var events []string
	var allowPrivate bool
	printSecret := func(raw json.RawMessage, what string) {
		var v struct{ Secret string }
		_ = json.Unmarshal(raw, &v)
		fmt.Fprintf(os.Stderr, "%s. Store the signing secret now; it is not shown again:\n", what)
		fmt.Println(v.Secret)
	}
	create := &cobra.Command{Use: "create NAME", Short: "Register an endpoint and print its signing secret once (owner)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "POST", "/api/v1/webhooks", map[string]any{"name": args[0], "url": urlFlag, "event_types": events,
				"allow_private": allowPrivate}, func(raw json.RawMessage) { printSecret(raw, "Created webhook "+args[0]) })
		})}
	create.Flags().StringVar(&urlFlag, "url", "", "receiver URL (https)")
	create.Flags().StringSliceVar(&events, "event", nil, "event type or prefix.* to subscribe to, e.g. renewal.* (repeatable; see docs/events.md)")
	create.Flags().BoolVar(&allowPrivate, "allow-private", false, "allow a private or loopback receiver")
	_ = create.MarkFlagRequired("url")
	_ = create.MarkFlagRequired("event")

	rotate := &cobra.Command{Use: "rotate-secret WEBHOOK", Short: "Issue a new secret; the old one also signs for 24 hours", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			return postAndPrint(c, "POST", "/api/v1/webhooks/"+url.PathEscape(args[0])+"/rotate-secret", nil,
				func(raw json.RawMessage) { printSecret(raw, "New secret for "+args[0]) })
		})}
	simple := func(use, short, method, suffix, done string) *cobra.Command {
		return &cobra.Command{Use: use + " WEBHOOK", Short: short, Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
			if err := c.do(method, "/api/v1/webhooks/"+url.PathEscape(args[0])+suffix, nil, nil); err != nil {
				return err
			}
			fmt.Printf(done+"\n", args[0])
			return nil
		})}
	}
	show := &cobra.Command{Use: "show WEBHOOK", Short: "Show an endpoint (never its secret)", Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
		var raw json.RawMessage
		if err := c.do("GET", "/api/v1/webhooks/"+url.PathEscape(args[0]), nil, &raw); err != nil {
			return err
		}
		return printJSON(raw)
	})}
	var limit int
	deliveries := &cobra.Command{Use: "deliveries WEBHOOK", Short: "Recent deliveries with state and last error", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var v struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := c.do("GET", fmt.Sprintf("/api/v1/webhooks/%s/deliveries?limit=%d", url.PathEscape(args[0]), limit), nil, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v.Items)
			}
			table("ID\tEVENT\tTYPE\tSTATE\tATTEMPTS\tSTATUS\tERROR", func(w io.Writer) {
				for _, raw := range v.Items {
					var d struct {
						ID       int64
						Event    string `json:"event_id"`
						Type     string `json:"event_type"`
						State    string
						Attempts int
						Status   *int `json:"last_status"`
						Error    string
					}
					_ = json.Unmarshal(raw, &d)
					st := ""
					if d.Status != nil {
						st = fmt.Sprint(*d.Status)
					}
					fmt.Fprintf(w, "%d\t%s\t%s\t%s\t%d\t%s\t%s\n", d.ID, d.Event, d.Type, d.State, d.Attempts, st, d.Error)
				}
			})
			return nil
		})}
	deliveries.Flags().IntVar(&limit, "limit", 50, "number of deliveries")
	redeliver := &cobra.Command{Use: "redeliver WEBHOOK DELIVERY", Short: "Send a delivery again (same webhook-id)", Args: cobra.ExactArgs(2),
		RunE: run(func(c *client, args []string) error {
			if err := c.do("POST", "/api/v1/webhooks/"+url.PathEscape(args[0])+"/deliveries/"+url.PathEscape(args[1])+"/redeliver", nil, nil); err != nil {
				return err
			}
			fmt.Printf("Delivery %s queued again.\n", args[1])
			return nil
		})}
	list := listCmd("list", "List endpoints", "/api/v1/webhooks", "NAME\tURL\tEVENTS\tENABLED\tFAILING SINCE",
		func(w io.Writer, raw json.RawMessage) {
			var e struct {
				Name, URL string
				Events    []string   `json:"event_types"`
				Enabled   bool       `json:"enabled"`
				Failing   *time.Time `json:"failing_since"`
			}
			_ = json.Unmarshal(raw, &e)
			f := ""
			if e.Failing != nil {
				f = e.Failing.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%v\t%s\n", e.Name, e.URL, strings.Join(e.Events, ","), e.Enabled, f)
		})
	cmd.AddCommand(create, list, show, rotate, deliveries, redeliver,
		simple("enable", "Enable an endpoint", "POST", "/enable", "Enabled webhook %s."),
		simple("disable", "Disable an endpoint", "POST", "/disable", "Disabled webhook %s."),
		simple("delete", "Delete an endpoint and its delivery log", "DELETE", "", "Deleted webhook %s."))
	return cmd
}
