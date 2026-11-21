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

// hmacFlags reads an EAB HMAC key from stdin or a file, never from an argument.
type hmacFlags struct {
	stdin bool
	file  string
}

func (f *hmacFlags) add(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.stdin, "hmac-stdin", false, "read the base64url HMAC key from stdin")
	cmd.Flags().StringVar(&f.file, "hmac-file", "", "read the base64url HMAC key from a file")
}

// read returns the key, or "" when no flag was given.
func (f *hmacFlags) read() (string, error) {
	switch {
	case f.stdin && f.file != "":
		return "", &usageError{"use only one of --hmac-stdin and --hmac-file"}
	case f.file != "":
		b, err := os.ReadFile(f.file)
		return strings.TrimSpace(string(b)), err
	case f.stdin:
		return readSecret()
	}
	return "", nil
}

func issuerEABCmds() []*cobra.Command {
	var mode, kid string
	var hf hmacFlags
	setEAB := &cobra.Command{Use: "set-eab ISSUER", Short: "Set External Account Binding: none, reusable (one key) or single_use (key pool) (ADR-0019)",
		Args: cobra.ExactArgs(1), RunE: run(func(c *client, args []string) error {
			hmac, err := hf.read()
			if err != nil {
				return err
			}
			body := map[string]any{"mode": mode, "kid": kid}
			if hmac != "" {
				body["hmac"] = hmac
			}
			return postAndPrint(c, "PUT", "/api/v1/issuers/"+url.PathEscape(args[0])+"/eab", body, func(json.RawMessage) {
				fmt.Printf("Issuer %s now uses EAB mode %s.\n", args[0], mode)
			})
		})}
	setEAB.Flags().StringVar(&mode, "mode", "", "none, reusable or single_use")
	setEAB.Flags().StringVar(&kid, "kid", "", "reusable: key id from the CA")
	hf.add(setEAB)
	_ = setEAB.MarkFlagRequired("mode")

	keys := &cobra.Command{Use: "eab-key", Short: "Single-use EAB keys of an issuer (one key registers one agent's account)"}
	var akid, expiresIn, expiresAt string
	var ahf hmacFlags
	add := &cobra.Command{Use: "add ISSUER", Short: "Add a single-use key to the pool (issuers:manage)", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			hmac, err := ahf.read()
			if err != nil {
				return err
			}
			if hmac == "" {
				return &usageError{"pass --hmac-stdin or --hmac-file"}
			}
			body := map[string]any{"kid": akid, "hmac": hmac}
			switch {
			case expiresIn != "" && expiresAt != "":
				return &usageError{"use only one of --expires-in and --expires-at"}
			case expiresIn != "":
				d, err := time.ParseDuration(expiresIn)
				if err != nil {
					return &usageError{"--expires-in: " + err.Error()}
				}
				body["expires_at"] = time.Now().Add(d).UTC()
			case expiresAt != "":
				t, err := time.Parse(time.RFC3339, expiresAt)
				if err != nil {
					return &usageError{"--expires-at must be RFC 3339, e.g. 2026-12-01T00:00:00Z"}
				}
				body["expires_at"] = t
			}
			return postAndPrint(c, "POST", "/api/v1/issuers/"+url.PathEscape(args[0])+"/eab-keys", body, func(raw json.RawMessage) {
				var k struct{ ID string }
				_ = json.Unmarshal(raw, &k)
				fmt.Printf("Added EAB key %s (%s).\n", akid, k.ID)
			})
		})}
	add.Flags().StringVar(&akid, "kid", "", "key id from the CA")
	add.Flags().StringVar(&expiresIn, "expires-in", "", "validity left, e.g. 168h for a key Google Trust Services issued just now")
	add.Flags().StringVar(&expiresAt, "expires-at", "", "expiry time (RFC 3339)")
	ahf.add(add)
	_ = add.MarkFlagRequired("kid")

	list := &cobra.Command{Use: "list ISSUER", Short: "List the pool and each key's state", Args: cobra.ExactArgs(1),
		RunE: run(func(c *client, args []string) error {
			var v struct {
				Items []json.RawMessage `json:"items"`
			}
			if err := c.do("GET", "/api/v1/issuers/"+url.PathEscape(args[0])+"/eab-keys", nil, &v); err != nil {
				return err
			}
			if asJSON() {
				return printJSON(v.Items)
			}
			table("ID\tKID\tSTATE\tAGENT\tEXPIRES", func(w io.Writer) {
				for _, raw := range v.Items {
					var k struct {
						ID, KID, State string
						Agent          string     `json:"agent_id"`
						Expires        *time.Time `json:"expires_at"`
					}
					_ = json.Unmarshal(raw, &k)
					exp := ""
					if k.Expires != nil {
						exp = k.Expires.UTC().Format(time.RFC3339)
					}
					fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", k.ID, k.KID, k.State, k.Agent, exp)
				}
			})
			return nil
		})}
	del := &cobra.Command{Use: "delete ISSUER KEY", Short: "Remove an available or failed key (issuers:manage)", Args: cobra.ExactArgs(2),
		RunE: run(func(c *client, args []string) error {
			if err := c.do("DELETE", "/api/v1/issuers/"+url.PathEscape(args[0])+"/eab-keys/"+url.PathEscape(args[1]), nil, nil); err != nil {
				return err
			}
			fmt.Printf("Removed EAB key %s.\n", args[1])
			return nil
		})}
	keys.AddCommand(add, list, del)
	return []*cobra.Command{setEAB, keys}
}
