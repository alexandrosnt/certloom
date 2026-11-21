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
	"io"
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
  certloom-agent run [--config FILE] [--enroll-token-file FILE --ca-hash sha256:...]
  certloom-agent check-config [--config FILE]
  certloom-agent dns-test --solver NAME --name DOMAIN [--config FILE]
  certloom-agent service install|uninstall [--config FILE]   (Windows)
  certloom-agent version

dns-test writes and removes a random TXT record for _acme-challenge.DOMAIN
through one of the config's dns_solvers and checks that it resolves. Use it to
verify credentials and permissions, and as the conformance test for plugins.

The enrollment token is read from stdin (never from argv).
Default config: /etc/certloom-agent/config.yaml, on Windows
%ProgramData%\certloom-agent\config.yaml.
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
	cfgPath := fs.String("config", defaultConfigPath(), "config file")
	caHash := fs.String("ca-hash", "", "control plane CA fingerprint printed by `certloom agent token`")
	server := fs.String("server", "", "override the config's server URL")
	_ = fs.Bool("token-stdin", true, "read the token from stdin (always on)")
	solver := fs.String("solver", "", "dns-test: name of the dns solver to check")
	name := fs.String("name", "", "dns-test: domain to prove control of, e.g. www.example.com")
	tokenFile := fs.String("enroll-token-file", "", "run: enroll first with the token in this file if not enrolled yet (containers)")
	args := os.Args[2:]
	var action string
	if os.Args[1] == "service" && len(args) > 0 {
		action, args = args[0], args[1:] // service install --config FILE
	}
	_ = fs.Parse(args)

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
	case "service":
		err = serviceCommand(action, *cfgPath)
	case "run":
		if isService() {
			var closer io.Closer
			if log, closer, err = serviceLog(*cfgPath); err != nil {
				break
			}
			defer closer.Close()
			svcLog := log
			err = runService(func(ctx context.Context) error { return runAgent(ctx, *cfgPath, *tokenFile, *caHash, svcLog) })
			break
		}
		err = runAgent(ctx, *cfgPath, *tokenFile, *caHash, log)
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err != nil {
		log.Error("fatal", "error", err)
		os.Exit(1)
	}
}

// runAgent runs until ctx is cancelled. With a token file it enrolls first
// when the state directory has no identity yet, so a container can start
// without a separate enrollment step.
func runAgent(ctx context.Context, cfgPath, tokenFile, caHash string, log *slog.Logger) error {
	cfg, err := agent.LoadConfig(cfgPath)
	if err != nil {
		return err
	}
	if tokenFile != "" && !agent.Enrolled(cfg) {
		tok, err := os.ReadFile(tokenFile)
		if err != nil {
			return fmt.Errorf("not enrolled and no token: %w", err)
		}
		if caHash == "" {
			return errors.New("--ca-hash is required to enroll")
		}
		host, _ := os.Hostname()
		id, err := agent.Enroll(ctx, cfg, strings.TrimSpace(string(tok)), caHash, host)
		if err != nil {
			return err
		}
		log.Info("enrolled", "agent_id", id)
	}
	a, err := agent.New(cfg, log)
	if err != nil {
		return err
	}
	defer a.Close()
	log.Info("certloom-agent running", "agent_id", a.ID(), "server", cfg.Server, "targets", len(cfg.Targets))
	a.Run(ctx)
	return nil
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
