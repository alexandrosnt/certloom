package pluginstore

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseManifest(t *testing.T) {
	good := "name: corp-f5\nversion: 1.2.0\nprotocol: 1\nkinds: [deploy_target, discovery]\nexecutable: bin/corp-f5\n"
	m, err := ParseManifest([]byte(good))
	if err != nil || m.Name != "corp-f5" || len(m.Kinds) != 2 {
		t.Fatalf("%+v %v", m, err)
	}
	for name, doc := range map[string]string{
		"bad name":      strings.Replace(good, "corp-f5\n", "Corp_F5\n", 1),
		"bad version":   strings.Replace(good, "1.2.0", "latest", 1),
		"protocol":      strings.Replace(good, "protocol: 1", "protocol: 2", 1),
		"unknown kind":  strings.Replace(good, "discovery", "issuer", 1),
		"no kinds":      strings.Replace(good, "kinds: [deploy_target, discovery]\n", "", 1),
		"escaping exec": strings.Replace(good, "bin/corp-f5", "../corp-f5", 1),
		"absolute exec": strings.Replace(good, "bin/corp-f5", "/usr/bin/corp-f5", 1),
		"unknown key":   good + "run_as: root\n",
	} {
		if _, err := ParseManifest([]byte(doc)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestValidateTrust(t *testing.T) {
	key := filepath.Join(t.TempDir(), "corp.pub")
	ok := Config{Trust: []Publisher{
		{Name: "certloom", Keyless: &Keyless{Issuer: "https://token.actions.githubusercontent.com",
			IdentityRegexp: `^https://github\.com/alexandrosnt/certloom-plugin-[a-z0-9-]+/`}},
		{Name: "corp", PublicKey: key},
	}}
	if p := ok.Validate(); len(p) != 0 {
		t.Fatal(p)
	}
	for name, pub := range map[string]Publisher{
		"both":        {Name: "x", PublicKey: key, Keyless: &Keyless{Issuer: "https://i", Identity: "a"}},
		"neither":     {Name: "x"},
		"relative":    {Name: "x", PublicKey: "k.pub"},
		"http issuer": {Name: "x", Keyless: &Keyless{Issuer: "http://i", Identity: "a"}},
		"no identity": {Name: "x", Keyless: &Keyless{Issuer: "https://i"}},
		"unanchored":  {Name: "x", Keyless: &Keyless{Issuer: "https://i", IdentityRegexp: "github.com/org/"}},
		"bad regexp":  {Name: "x", Keyless: &Keyless{Issuer: "https://i", IdentityRegexp: "^("}},
		"bad name":    {Name: "X Y", PublicKey: key},
	} {
		c := Config{Trust: []Publisher{pub}}
		if len(c.Validate()) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
	dup := Config{Trust: []Publisher{{Name: "a", PublicKey: key}, {Name: "a", PublicKey: key}}}
	if len(dup.Validate()) == 0 {
		t.Error("duplicate accepted")
	}
}

func writeRecord(t *testing.T, dir string, r Record) {
	t.Helper()
	d := VersionDir(dir, r.Name, r.Version)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(r)
	if err := os.WriteFile(filepath.Join(d, RecordFile), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadAndFind(t *testing.T) {
	dir := t.TempDir()
	if recs, err := Load(filepath.Join(dir, "missing")); err != nil || recs != nil {
		t.Fatalf("missing dir: %v %v", recs, err)
	}
	for _, v := range []string{"1.2.0", "1.10.0", "1.10.0-rc.1"} {
		writeRecord(t, dir, Record{Name: "f5", Version: v})
	}
	writeRecord(t, dir, Record{Name: "dns-corp", Version: "0.1.0"})
	_ = os.MkdirAll(filepath.Join(dir, "f5", "2.0.0"), 0o755) // unfinished install: no record
	recs, err := Load(dir)
	if err != nil || len(recs) != 4 {
		t.Fatalf("%v %v", recs, err)
	}
	r, err := Find(recs, "f5")
	if err != nil || r.Version != "1.10.0" {
		t.Fatalf("newest: %+v %v", r, err)
	}
	if r, err := Find(recs, "f5@1.2.0"); err != nil || r.Version != "1.2.0" {
		t.Fatalf("pinned version: %+v %v", r, err)
	}
	if _, err := Find(recs, "f5@9.9.9"); err == nil {
		t.Fatal("missing version found")
	}
	if _, err := Find(recs, "nope"); err == nil {
		t.Fatal("missing plugin found")
	}

	// A record copied into the wrong directory is refused.
	writeRecord(t, dir, Record{Name: "dns-corp", Version: "0.2.0"})
	b, _ := json.Marshal(Record{Name: "f5", Version: "0.2.0"})
	_ = os.WriteFile(filepath.Join(dir, "dns-corp", "0.2.0", RecordFile), b, 0o644)
	if _, err := Load(dir); err == nil {
		t.Fatal("mismatched record accepted")
	}
}

func TestCompareVersions(t *testing.T) {
	for _, c := range []struct {
		a, b string
		sign int
	}{
		{"1.10.0", "1.9.0", 1}, {"1.0.0", "1.0.0", 0}, {"1.0.0-rc.1", "1.0.0", -1}, {"2.0.0", "10.0.0", -1},
	} {
		got := CompareVersions(c.a, c.b)
		if got > 0 && c.sign <= 0 || got < 0 && c.sign >= 0 || got == 0 && c.sign != 0 {
			t.Errorf("%s vs %s: %d", c.a, c.b, got)
		}
	}
}
