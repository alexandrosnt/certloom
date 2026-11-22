package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as the plugin: with TEST_PLUGIN_MODE set it
// behaves as one and never runs the tests.
func TestMain(m *testing.M) {
	if mode := os.Getenv("TEST_PLUGIN_MODE"); mode != "" {
		os.Exit(fakePlugin(mode))
	}
	os.Exit(m.Run())
}

type recorder struct{ fail error }

func (r recorder) Present(_ context.Context, req Request) error {
	if r.fail != nil {
		return r.fail
	}
	if req.Config["zone_id"] != "z1" {
		return errors.New("config not passed")
	}
	return nil
}

func (r recorder) Cleanup(context.Context, Request) error { return r.fail }

func fakePlugin(mode string) int {
	switch mode {
	case "ok":
		return (&Server{Name: "fake", Version: "1.0.0", DNS: recorder{}}).Serve(context.Background(), os.Args[1:], os.Stdin, os.Stdout)
	case "auth":
		h := recorder{fail: &Classified{Class: ClassAuth, Err: errors.New("token rejected")}}
		return (&Server{Name: "fake", Version: "1.0.0", DNS: h}).Serve(context.Background(), os.Args[1:], os.Stdin, os.Stdout)
	case "ratelimit":
		h := recorder{fail: &Classified{Class: ClassRateLimited, RetryAfter: 30 * time.Second, Err: errors.New("slow down")}}
		return (&Server{Name: "fake", Version: "1.0.0", DNS: h}).Serve(context.Background(), os.Args[1:], os.Stdin, os.Stdout)
	case "proto2":
		fmt.Println(`{"ok":true,"protocol":2,"name":"future"}`)
	case "garbage":
		fmt.Println("not json")
	case "crash":
		fmt.Fprintln(os.Stderr, "boom")
		return 3
	case "huge":
		// Valid JSON, so only the size limit can reject it.
		fmt.Printf(`{"ok":true,"name":"%s"}`, strings.Repeat("x", MaxOutput))
	case "inventory":
		// Larger than MaxOutput, which only inventory answers may be.
		items := make([]Item, 200)
		for i := range items {
			items[i] = Item{Certificate: strings.Repeat("c", 1000), Location: fmt.Sprint("slot ", i)}
		}
		_ = json.NewEncoder(os.Stdout).Encode(Response{OK: true, Items: items})
	case "slow":
		time.Sleep(10 * time.Second)
	case "env":
		if os.Getenv("SECRET_FROM_AGENT") != "" || os.Getenv("ALLOWED") != "yes" {
			fmt.Println(`{"error":"unexpected environment","class":"permanent"}`)
			return 1
		}
		fmt.Println(`{"ok":true}`)
	}
	return 0
}

func testPlugin(t *testing.T, mode string) *Plugin {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Plugin{Path: exe, SHA256: digest(t, exe), Env: map[string]string{"TEST_PLUGIN_MODE": mode}, Timeout: 5 * time.Second}
}

func digest(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	_, _ = io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil))
}

var req = Request{FQDN: "_acme-challenge.example.test.", Value: "v", Zone: "example.test.", Config: map[string]any{"zone_id": "z1"}}

func TestPluginSuccess(t *testing.T) {
	p := testPlugin(t, "ok")
	d, err := p.Call(context.Background(), ActionDescribe, Request{})
	if err != nil || d.Name != "fake" || d.Version != "1.0.0" || d.Protocol != Protocol {
		t.Fatalf("describe: %+v %v", d, err)
	}
	for _, a := range []string{ActionPresent, ActionCleanup} {
		if _, err := p.Call(context.Background(), a, req); err != nil {
			t.Fatalf("%s: %v", a, err)
		}
	}
}

func TestPluginErrors(t *testing.T) {
	for _, c := range []struct {
		mode, class string
		retry       time.Duration
	}{
		{"auth", ClassAuth, 0},
		{"ratelimit", ClassRateLimited, 30 * time.Second},
		{"garbage", ClassPermanent, 0},
		{"crash", ClassTransient, 0},
		{"huge", ClassPermanent, 0},
	} {
		_, err := testPlugin(t, c.mode).Call(context.Background(), ActionPresent, req)
		var e *Error
		if !errors.As(err, &e) || e.Class != c.class || e.RetryAfter != c.retry {
			t.Errorf("%s: got %v, want class %s retry %s", c.mode, err, c.class, c.retry)
		}
	}
}

func TestPluginProtocolMismatch(t *testing.T) {
	_, err := testPlugin(t, "proto2").Call(context.Background(), ActionDescribe, Request{})
	if !IsClass(err, ClassPermanent) || !strings.Contains(err.Error(), "protocol 2") {
		t.Fatalf("got %v", err)
	}
}

func TestPluginTimeout(t *testing.T) {
	p := testPlugin(t, "slow")
	p.Timeout = 200 * time.Millisecond
	start := time.Now()
	_, err := p.Call(context.Background(), ActionPresent, req)
	if !IsClass(err, ClassTransient) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("got %v", err)
	}
	if time.Since(start) > 8*time.Second {
		t.Fatal("timeout not enforced")
	}
}

func TestPluginEnvironmentIsMinimal(t *testing.T) {
	t.Setenv("SECRET_FROM_AGENT", "leak")
	p := testPlugin(t, "env")
	p.Env["ALLOWED"] = "yes"
	if _, err := p.Call(context.Background(), ActionPresent, req); err != nil {
		t.Fatal(err)
	}
}

func TestPluginPinnedDigest(t *testing.T) {
	p := testPlugin(t, "ok")
	p.SHA256 = strings.Repeat("0", 64)
	if _, err := p.Call(context.Background(), ActionPresent, req); err == nil || !strings.Contains(err.Error(), "expected") {
		t.Fatalf("got %v", err)
	}
	p.Path = "relative/plugin"
	if err := p.Check(); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestPluginWritableRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no group/other mode bits on Windows")
	}
	path := filepath.Join(t.TempDir(), "plugin")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o777); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0o777) // umask may have cleared bits
	p := &Plugin{Path: path, SHA256: digest(t, path)}
	if err := p.Check(); err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("got %v", err)
	}
}

func TestServeRejectsBadRequests(t *testing.T) {
	for _, c := range []struct {
		args []string
		in   string
	}{
		{nil, ""},
		{[]string{"present"}, "{"},
		{[]string{"present"}, `{"protocol":9,"fqdn":"a.","value":"v"}`},
		{[]string{"present"}, `{"protocol":1}`},
		{[]string{"rename"}, `{"protocol":1,"fqdn":"a.","value":"v"}`},
	} {
		var out strings.Builder
		if code := (&Server{Name: "x", Version: "1", DNS: recorder{}}).Serve(context.Background(), c.args, strings.NewReader(c.in), &out); code == 0 {
			t.Errorf("%v %q: exit 0", c.args, c.in)
		}
		var r Response
		if err := json.Unmarshal([]byte(out.String()), &r); err != nil || r.Class != ClassPermanent {
			t.Errorf("%v %q: %s", c.args, c.in, out.String())
		}
	}
}
