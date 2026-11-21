package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"time"

	"github.com/alexandrosnt/certloom/dnsplugin"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/miekg/dns"
)

// CheckDNSSolver exercises one configured solver against a real zone, the
// way issuance would use it: present a random value for name (twice, to
// check idempotency), wait until it resolves, clean up (twice) and wait until
// it is gone. It is both the plugin conformance test and an operator's
// connection check. Other values at the record name are left alone.
func CheckDNSSolver(ctx context.Context, cfg *Config, solver, name string, out io.Writer, log *slog.Logger) error {
	var sc *DNSSolverConfig
	for i := range cfg.DNSSolvers {
		if cfg.DNSSolvers[i].Name == solver {
			sc = &cfg.DNSSolvers[i]
		}
	}
	if sc == nil {
		return fmt.Errorf("no dns solver named %q in the config", solver)
	}
	setDNSResolvers(cfg.Resolvers)
	failed := false
	step := func(what string, err error) bool {
		if err != nil {
			failed = true
			fmt.Fprintf(out, "FAIL  %s: %v\n", what, err)
			return false
		}
		fmt.Fprintf(out, "PASS  %s\n", what)
		return true
	}
	if sc.Plugin != "" {
		p := &dnsplugin.Plugin{Path: sc.Plugin, SHA256: sc.SHA256, Timeout: time.Duration(sc.TimeoutSeconds) * time.Second}
		d, err := p.Call(ctx, dnsplugin.ActionDescribe, dnsplugin.Request{})
		if !step("describe (pinned digest, protocol version)", err) {
			return errors.New("dns solver check failed")
		}
		fmt.Fprintf(out, "      plugin %s %s\n", d.Name, d.Version)
	}
	m, err := newDNSMux([]DNSSolverConfig{*sc}, log)
	if !step("load solver and credentials", err) {
		return errors.New("dns solver check failed")
	}
	tok := make([]byte, 16)
	_, _ = rand.Read(tok)
	token := hex.EncodeToString(tok)
	keyAuth := token + ".certloom-dns-test"
	info := dns01.GetChallengeInfo(ctx, name, keyAuth)
	fmt.Fprintf(out, "      record %s (value %s)\n", info.EffectiveFQDN, info.Value)
	timeout := sc.propagationTimeout()

	if step("present", m.Present(ctx, name, token, keyAuth)) {
		step("present again (idempotent)", m.Present(ctx, name, token, keyAuth))
		step("record visible", waitTXT(ctx, cfg.Resolvers, info.EffectiveFQDN, info.Value, true, timeout))
	}
	// Always try to clean up, even after a failed present.
	if step("cleanup", m.CleanUp(ctx, name, token, keyAuth)) {
		// Built-in lego providers forget a record once it is removed; only
		// solvers that address records by value can be asked twice.
		if sc.Provider != ProviderCloudflare {
			step("cleanup again (idempotent)", m.CleanUp(ctx, name, token, keyAuth))
		}
		step("record removed", waitTXT(ctx, cfg.Resolvers, info.EffectiveFQDN, info.Value, false, timeout))
	}
	if failed {
		return errors.New("dns solver check failed")
	}
	return nil
}

// waitTXT polls until value is (or is no longer) published at fqdn.
func waitTXT(ctx context.Context, resolvers []string, fqdn, value string, present bool, timeout time.Duration) error {
	if len(resolvers) == 0 {
		cc, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return fmt.Errorf("no resolvers configured and none in /etc/resolv.conf: %w", err)
		}
		for _, s := range cc.Servers {
			resolvers = append(resolvers, net.JoinHostPort(s, cc.Port))
		}
	}
	deadline := time.Now().Add(timeout)
	for {
		found, err := lookupTXT(ctx, resolvers, fqdn, value)
		if err == nil && found == present {
			return nil
		}
		if time.Now().After(deadline) {
			if err != nil {
				return err
			}
			return fmt.Errorf("not seen within %s", timeout)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

func lookupTXT(ctx context.Context, resolvers []string, fqdn, value string) (bool, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	m.RecursionDesired = true
	c := &dns.Client{Timeout: 5 * time.Second}
	var lastErr error
	for _, r := range resolvers {
		resp, _, err := c.ExchangeContext(ctx, m, r)
		if err != nil {
			lastErr = err
			continue
		}
		for _, rr := range resp.Answer {
			if t, ok := rr.(*dns.TXT); ok && slices.Contains(t.Txt, value) {
				return true, nil
			}
		}
		return false, nil
	}
	return false, lastErr
}
