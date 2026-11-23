package agent

import (
	"bufio"
	"context"
	"encoding/pem"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	"github.com/alexandrosnt/certloom/internal/cloudobs"
)

// handleInventory reports certificate files (public certificates only; PEM
// blocks that are not CERTIFICATE are dropped) and Certbot lineages, which
// are read, never modified.
func (a *Agent) handleInventory(ctx context.Context, _ *agentproto.Task) (any, error) {
	out := agentproto.InventoryOutput{Certificates: []agentproto.FoundCert{}}
	seen := map[string]bool{}
	add := func(path string) {
		if seen[path] || len(out.Certificates) >= 2000 {
			return
		}
		seen[path] = true
		fi, err := os.Stat(path)
		if err != nil || fi.IsDir() || fi.Size() > 1<<20 {
			return
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return
		}
		var certs []byte
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			if blk.Type == "CERTIFICATE" {
				certs = append(certs, pem.EncodeToMemory(blk)...)
			}
		}
		if len(certs) > 0 {
			out.Certificates = append(out.Certificates, agentproto.FoundCert{Path: path, ChainPEM: string(certs)})
		}
	}
	for _, g := range a.cfg.DiscoveryPaths {
		matches, _ := filepath.Glob(g)
		for _, m := range matches {
			add(m)
		}
	}
	cb := a.cfg.CertbotDir
	if cb == "" {
		cb = "/etc/letsencrypt"
	}
	confs, _ := filepath.Glob(filepath.Join(cb, "renewal", "*.conf"))
	for _, conf := range confs {
		l := readCertbotConf(conf)
		if l.CertPath != "" {
			add(l.CertPath)
		}
		out.Certbot = append(out.Certbot, l)
	}
	if a.win != nil {
		b, err := a.inventoryIIS(ctx)
		if err != nil {
			a.log.Warn("IIS inventory failed", "error", err)
		}
		out.IIS = b
		dir := a.cfg.WinACMEDir
		if dir == "" {
			dir = filepath.Join(os.Getenv("ProgramData"), "win-acme")
		}
		out.WinACME = readWinACME(dir)
	}
	if a.cfg.Kubernetes != nil {
		k, err := a.inventoryKube(ctx)
		if err != nil {
			return nil, err
		}
		out.Kubernetes = k
	}
	if a.cfg.Cloud != nil {
		out.Cloud = cloudobs.Collect(ctx, a.cfg.Cloud, a.cloudTest, a.log)
	}
	out.Plugins = a.inventoryPlugins(ctx)
	out.TrustStores = a.inventoryTrust()
	return out, nil
}

func readCertbotConf(path string) agentproto.CertbotLineage {
	l := agentproto.CertbotLineage{Name: strings.TrimSuffix(filepath.Base(path), ".conf")}
	f, err := os.Open(path)
	if err != nil {
		return l
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), "=")
		if !ok {
			continue
		}
		k, v = strings.TrimSpace(k), strings.TrimSpace(v)
		switch k {
		case "cert":
			l.CertPath = v
		case "authenticator":
			l.Authenticator = v
		case "server":
			l.Server = v
		case "version":
			l.Version = v
		}
	}
	l.ARIAware = versionAtLeast(l.Version, 4, 1)
	return l
}

// versionAtLeast compares "major.minor[.patch]" (Certbot gained ARI in 4.1.0).
func versionAtLeast(v string, major, minor int) bool {
	parts := strings.SplitN(v, ".", 3)
	if len(parts) < 2 {
		return false
	}
	ma, err1 := strconv.Atoi(parts[0])
	mi, err2 := strconv.Atoi(parts[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return ma > major || (ma == major && mi >= minor)
}
