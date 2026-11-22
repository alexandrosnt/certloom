// Command certloom-plugin packs, verifies and installs certloom agent plugins
// (ADR-0027). It is separate from certloom-agent so that the Sigstore
// libraries it needs are not linked into the long-running agent.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/alexandrosnt/certloom/internal/pluginstore"
	"github.com/alexandrosnt/certloom/internal/version"
)

const usage = `certloom-plugin: pack, verify and install certloom agent plugins

Usage:
  certloom-plugin pack DIR [--out DIR] [--os OS --arch ARCH]
  certloom-plugin verify PACKAGE [--bundle FILE|URL] [--config FILE]
  certloom-plugin install PACKAGE [--bundle FILE|URL] [--config FILE]
  certloom-plugin list [--config FILE]
  certloom-plugin remove NAME@VERSION [--config FILE]
  certloom-plugin version

PACKAGE is a file or an https URL. The signature bundle defaults to
PACKAGE.sigstore.json. Packages are verified against plugins.trust in the
agent config and refused unless a trusted publisher signed them. Sign a
package with cosign:

  cosign sign-blob --bundle PACKAGE.sigstore.json PACKAGE            (keyless, in CI)
  cosign sign-blob --key cosign.key --bundle PACKAGE.sigstore.json PACKAGE

Default config: /etc/certloom-agent/config.yaml, on Windows
%ProgramData%\certloom-agent\config.yaml.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1], os.Args[2:]); err != nil {
		if errors.Is(err, errUsage) {
			fmt.Fprint(os.Stderr, usage)
			os.Exit(2)
		}
		fmt.Fprintln(os.Stderr, "certloom-plugin:", err)
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(ctx context.Context, cmd string, args []string) error {
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	cfgPath := fs.String("config", defaultConfigPath(), "agent config file")
	bundleFlag := fs.String("bundle", "", "signature bundle (default PACKAGE.sigstore.json)")
	outDir := fs.String("out", ".", "pack: directory to write the package to")
	goos := fs.String("os", runtime.GOOS, "pack: operating system the plugin is built for")
	goarch := fs.String("arch", runtime.GOARCH, "pack: architecture the plugin is built for")
	// Flags may follow the positional argument: certloom-plugin install pkg --config f.
	var pos []string
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			return errUsage
		}
		if fs.NArg() == 0 {
			break
		}
		pos, args = append(pos, fs.Arg(0)), fs.Args()[1:]
	}
	one := func() (string, error) {
		if len(pos) != 1 {
			return "", errUsage
		}
		return pos[0], nil
	}

	switch cmd {
	case "version", "--version":
		fmt.Println("certloom-plugin", version.String())
		return nil
	case "pack":
		dir, err := one()
		if err != nil {
			return err
		}
		var buf bytes.Buffer
		m, err := pack(dir, &buf)
		if err != nil {
			return err
		}
		out := filepath.Join(*outDir, packageName(m, *goos, *goarch))
		if err := os.WriteFile(out, buf.Bytes(), 0o644); err != nil { //nolint:gosec // a package is a public artifact
			return err
		}
		fmt.Println(out)
		return nil
	case "verify", "install":
		src, err := one()
		if err != nil {
			return err
		}
		cfg, err := loadAgentConfig(*cfgPath)
		if err != nil {
			return err
		}
		v, err := verifyPackage(ctx, &trustPolicy{cfg: cfg.Plugins}, src, bundleSource(src, *bundleFlag))
		if err != nil {
			return err
		}
		m := v.manifest
		fmt.Printf("%s %s (%s) signed by %s [trust %s]\n", m.Name, m.Version, strings.Join(m.Kinds, ", "), v.signer.Identity, v.signer.Trust)
		for _, p := range m.Permissions {
			fmt.Println("  needs:", p)
		}
		if cmd == "verify" {
			return nil
		}
		r, err := install(v, cfg.pluginsDir(), time.Now())
		if err != nil {
			return err
		}
		fmt.Printf("installed %s\n", filepath.Dir(r.Executable))
		return nil
	case "list":
		if len(pos) != 0 {
			return errUsage
		}
		cfg, err := loadAgentConfig(*cfgPath)
		if err != nil {
			return err
		}
		recs, err := pluginstore.Load(cfg.pluginsDir())
		if err != nil {
			return err
		}
		w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tVERSION\tKINDS\tTRUST\tSIGNER")
		for _, r := range recs {
			trust := r.Trust
			if _, ok := cfg.Plugins.Publisher(r.Trust); !ok {
				trust += " (not in plugins.trust: the agent ignores it)"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", r.Name, r.Version, strings.Join(r.Kinds, ","), trust, r.Signer)
		}
		return w.Flush()
	case "remove":
		ref, err := one()
		if err != nil {
			return err
		}
		cfg, err := loadAgentConfig(*cfgPath)
		if err != nil {
			return err
		}
		if err := remove(cfg.pluginsDir(), ref); err != nil {
			return err
		}
		fmt.Println("removed", ref)
		return nil
	}
	return errUsage
}

func defaultConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "certloom-agent", "config.yaml")
	}
	return "/etc/certloom-agent/config.yaml"
}
