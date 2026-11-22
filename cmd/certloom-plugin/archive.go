package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/pluginstore"
)

// Limits for package contents; plugins are single executables plus a few
// small files.
const (
	maxArchiveBytes = 256 << 20
	maxFileBytes    = 200 << 20
	maxEntries      = 1000
)

// packageName is the file name pack writes and install expects.
func packageName(m *pluginstore.Manifest, goos, goarch string) string {
	return fmt.Sprintf("certloom-plugin-%s_%s_%s_%s.tar.gz", m.Name, m.Version, goos, goarch)
}

// pack writes dir as a gzip tar. The output depends only on the file
// contents: entries are sorted, owners and times are zeroed, and modes are
// 0755 for the manifest's executable and directories, 0644 for the rest.
func pack(dir string, out io.Writer) (*pluginstore.Manifest, error) {
	mb, err := os.ReadFile(filepath.Join(dir, pluginstore.ManifestFile))
	if err != nil {
		return nil, err
	}
	m, err := pluginstore.ParseManifest(mb)
	if err != nil {
		return nil, err
	}
	var paths []string
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil || rel == "." {
			return err
		}
		if d.Type()&fs.ModeSymlink != 0 || !d.IsDir() && !d.Type().IsRegular() {
			return fmt.Errorf("%s: only regular files and directories can be packed", rel)
		}
		paths = append(paths, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return nil, err
	}
	if !slices.Contains(paths, m.Executable) {
		return nil, fmt.Errorf("executable %s from %s is not in %s", m.Executable, pluginstore.ManifestFile, dir)
	}
	slices.Sort(paths)
	gz := gzip.NewWriter(out)
	tw := tar.NewWriter(gz)
	for _, rel := range paths {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		fi, err := os.Stat(full)
		if err != nil {
			return nil, err
		}
		h := &tar.Header{Name: rel, ModTime: time.Unix(0, 0), Format: tar.FormatPAX, Mode: 0o644, Typeflag: tar.TypeReg}
		switch {
		case fi.IsDir():
			h.Name, h.Mode, h.Typeflag = rel+"/", 0o755, tar.TypeDir
		case rel == m.Executable:
			h.Mode = 0o755
		}
		if !fi.IsDir() {
			h.Size = fi.Size()
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if !fi.IsDir() {
			f, err := os.Open(full)
			if err != nil {
				return nil, err
			}
			_, err = io.Copy(tw, f)
			_ = f.Close() // read-only; a failed read already shows in err
			if err != nil {
				return nil, err
			}
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return m, gz.Close()
}

// entry is one checked file or directory of a package.
type entry struct {
	name string // slash-separated, relative, clean
	dir  bool
	exec bool
	data []byte
}

// readPackage reads and checks a package: a gzip tar of directories and
// regular files with clean relative names, a valid plugin.yaml, and the
// executable it names.
func readPackage(archive []byte) (*pluginstore.Manifest, []entry, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, nil, fmt.Errorf("not a gzip file: %w", err)
	}
	tr := tar.NewReader(gz)
	var entries []entry
	seen := map[string]bool{}
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("bad archive: %w", err)
		}
		if len(entries) == maxEntries {
			return nil, nil, fmt.Errorf("more than %d entries", maxEntries)
		}
		name := strings.TrimSuffix(h.Name, "/")
		if !fs.ValidPath(name) || name == "." || strings.Contains(name, `\`) || path.Clean(name) != name {
			return nil, nil, fmt.Errorf("unsafe path %q in package", h.Name)
		}
		if seen[name] {
			return nil, nil, fmt.Errorf("duplicate entry %q", name)
		}
		seen[name] = true
		switch h.Typeflag {
		case tar.TypeDir:
			entries = append(entries, entry{name: name, dir: true})
		case tar.TypeReg:
			if h.Size > maxFileBytes {
				return nil, nil, fmt.Errorf("%s is larger than %d bytes", name, maxFileBytes)
			}
			data, err := io.ReadAll(io.LimitReader(tr, maxFileBytes+1))
			if err != nil {
				return nil, nil, err
			}
			entries = append(entries, entry{name: name, exec: h.Mode&0o111 != 0, data: data})
		default:
			return nil, nil, fmt.Errorf("%s: only regular files and directories are allowed (no links or devices)", name)
		}
	}
	var m *pluginstore.Manifest
	for _, e := range entries {
		if e.name == pluginstore.ManifestFile && !e.dir {
			if m, err = pluginstore.ParseManifest(e.data); err != nil {
				return nil, nil, err
			}
		}
	}
	if m == nil {
		return nil, nil, fmt.Errorf("package has no %s at its root", pluginstore.ManifestFile)
	}
	if !slices.ContainsFunc(entries, func(e entry) bool { return e.name == m.Executable && !e.dir }) {
		return nil, nil, fmt.Errorf("executable %s named in %s is not in the package", m.Executable, pluginstore.ManifestFile)
	}
	return m, entries, nil
}

// extract writes entries below dest, which must not exist yet.
func extract(entries []entry, m *pluginstore.Manifest, dest string) error {
	// Plugin files are readable by the agent user and writable only by the
	// installer (root or an administrator), hence 0755 and 0644.
	if err := os.Mkdir(dest, 0o755); err != nil { //nolint:gosec // see above
		return err
	}
	for _, e := range entries {
		p := filepath.Join(dest, filepath.FromSlash(e.name))
		if e.dir {
			if err := os.MkdirAll(p, 0o755); err != nil { //nolint:gosec // readable by the agent user
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil { //nolint:gosec // readable by the agent user
			return err
		}
		mode := os.FileMode(0o644)
		if e.exec || e.name == m.Executable {
			mode = 0o755
		}
		f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, err = f.Write(e.data)
		if cerr := f.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		// The umask may have taken bits away; the agent refuses executables
		// writable by group or others, so never add those.
		if err := os.Chmod(p, mode); err != nil {
			return err
		}
	}
	return nil
}
