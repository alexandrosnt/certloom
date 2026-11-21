// Command certloom-agent runs next to deployment targets. It dials out
// to the control plane over mutual TLS, executes signed tasks it is locally
// allowed to run, and never sends private keys anywhere.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/alexandrosnt/certloom/internal/agent"
	"github.com/alexandrosnt/certloom/internal/version"
)

const usage = `certloom-agent: certificate lifecycle agent

Usage:
  certloom-agent enroll --ca-hash sha256:... [--config FILE] [--token-stdin]
  certloom-agent run [--config FILE]
  certloom-agent check-config [--config FILE]
  certloom-agent dns-test --solver NAME --name DOMAIN [--config FILE]
  certloom-agent version

dns-test writes and removes a random TXT record for _acme-challenge.DOMAIN
through one of the config's dns_solvers and checks that it resolves. Use it to
verify credentials and permissions, and as the conformance test for plugins.

The enrollment token is read from stdin (never from argv).
Default config: /etc/certloom-agent/config.yaml
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	cfgPath := fs.String("config", "/etc/certloom-agent/config.yaml", "config file")
	caHash := fs.String("ca-hash", "", "control plane CA fingerprint printed by `certloom agent token`")
	server := fs.String("server", "", "override the config's server URL")
	_ = fs.Bool("token-stdin", true, "read the token from stdin (always on)")
	solver := fs.String("solver", "", "dns-test: name of the dns solver to check")
	name := fs.String("name", "", "dns-test: domain to prove control of, e.g. www.example.com")
	_ = fs.Parse(os.Args[2:])

	var err error
	switch os.Args[1] {
	case "version", "--version":
		fmt.Println("certloom-agent", version.String())
		return
	case "check-config":
		_, err = agent.LoadConfig(*cfgPath)
		if err == nil {
			fmt.Println("config OK")
		}
	case "dns-test":
		var cfg *agent.Config
		if cfg, err = agent.LoadConfig(*cfgPath); err != nil {
			break
		}
		if *solver == "" || *name == "" {
			err = errors.New("--solver and --name are required")
			break
		}
		err = agent.CheckDNSSolver(ctx, cfg, *solver, *name, os.Stdout, log)
	case "enroll":
		err = enroll(ctx, *cfgPath, *caHash, *server)
	case "run":
		var cfg *agent.Config
		if cfg, err = agent.LoadConfig(*cfgPath); err != nil {
			break
		}
		var a *agent.Agent
		if a, err = agent.New(cfg, log); err != nil {
			break
		}
		defer a.Close()
		log.Info("certloom-agent running", "agent_id", a.ID(), "server", cfg.Server, "targets", len(cfg.Targets))
		a.Run(ctx)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

func enroll(ctx context.Context, cfgPath, caHash, server string) error {
	if caHash == "" {
		return errors.New("--ca-hash is required (printed by `certloom agent token`)")
	}
	cfg, err := agent.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	if server != "" {
		cfg.Server = server
	}
	fmt.Fprint(os.Stderr, "Enrollment token: ")
	tok, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && strings.TrimSpace(tok) == "" {
		return errors.New("no token on stdin")
	}
	host, _ := os.Hostname()
	id, err := agent.Enroll(ctx, cfg, strings.TrimSpace(tok), caHash, host)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "\nEnrolled as %s. Start the agent with `certloom-agent run`.\n", id)
	return nil
}
