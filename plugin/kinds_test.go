package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
)

type fakeTarget struct {
	deployed map[string]string // idempotency key -> certificate path
}

func (f *fakeTarget) Deploy(_ context.Context, req Request) error {
	if req.Target != "app1" {
		return &Classified{Class: ClassPermanent, Err: errors.New("unknown target")}
	}
	f.deployed[req.IdempotencyKey] = req.Files.Certificate
	return nil
}

func (f *fakeTarget) Verify(_ context.Context, req Request) (string, error) {
	if _, ok := f.deployed[req.IdempotencyKey]; !ok {
		return "", errors.New("nothing deployed")
	}
	return "-----BEGIN CERTIFICATE-----\n", nil
}

func (f *fakeTarget) Rollback(_ context.Context, req Request) error {
	delete(f.deployed, req.IdempotencyKey)
	return nil
}

func (f *fakeTarget) Inventory(context.Context, Request) ([]Item, error) {
	return []Item{{Certificate: "pem", Location: "vs1", UsedBy: []string{"listener 443"}}}, nil
}

type fakeDiscovery struct{}

func (fakeDiscovery) Inventory(context.Context, Request) ([]Item, error) {
	return []Item{{Certificate: "pem", Location: "store"}}, nil
}

func call(t *testing.T, s *Server, action string, req Request) Response {
	t.Helper()
	req.Protocol = Protocol
	in, _ := json.Marshal(req)
	var out strings.Builder
	s.Serve(context.Background(), []string{action}, strings.NewReader(string(in)), &out)
	var r Response
	if err := json.Unmarshal([]byte(out.String()), &r); err != nil {
		t.Fatalf("%s: %v: %s", action, err, out.String())
	}
	return r
}

func TestDescribeKinds(t *testing.T) {
	s := &Server{Name: "multi", Version: "2.0.0", DNS: recorder{}, Deploy: &fakeTarget{}, Discovery: fakeDiscovery{}}
	r := call(t, s, ActionDescribe, Request{})
	want := []string{KindDNSSolver, KindDeployTarget, KindDiscovery}
	if !r.OK || !slices.Equal(r.Kinds, want) || !slices.Equal(r.DescribedKinds(), want) {
		t.Fatalf("got %+v", r)
	}
	// Plugins written before kinds existed are DNS solvers.
	if old := (&Response{}).DescribedKinds(); !slices.Equal(old, []string{KindDNSSolver}) {
		t.Fatalf("default kinds %v", old)
	}
}

func TestDeployTargetActions(t *testing.T) {
	ft := &fakeTarget{deployed: map[string]string{}}
	s := &Server{Name: "t", Version: "1", Deploy: ft}
	files := &Files{Key: "/tmp/k", Certificate: "/tmp/c", Chain: "/tmp/ch", Fullchain: "/tmp/f"}
	base := Request{Kind: KindDeployTarget, Target: "app1", IdempotencyKey: "run-1/deploy"}

	d := base
	d.Files = files
	if r := call(t, s, ActionDeploy, d); !r.OK {
		t.Fatalf("deploy: %+v", r)
	}
	if r := call(t, s, ActionVerify, base); !r.OK || !strings.HasPrefix(r.Certificate, "-----BEGIN") {
		t.Fatalf("verify: %+v", r)
	}
	if r := call(t, s, ActionInventory, base); !r.OK || len(r.Items) != 1 || r.Items[0].UsedBy[0] != "listener 443" {
		t.Fatalf("inventory: %+v", r)
	}
	if r := call(t, s, ActionRollback, base); !r.OK || len(ft.deployed) != 0 {
		t.Fatalf("rollback: %+v", r)
	}
	if r := call(t, s, ActionVerify, base); r.OK || r.Class != ClassTransient {
		t.Fatalf("verify after rollback: %+v", r)
	}
	bad := d
	bad.Target = "other"
	if r := call(t, s, ActionDeploy, bad); r.Class != ClassPermanent || r.Error != "unknown target" {
		t.Fatalf("classified error: %+v", r)
	}
}

func TestDeployTargetRejectsBadRequests(t *testing.T) {
	s := &Server{Name: "t", Version: "1", Deploy: &fakeTarget{deployed: map[string]string{}}}
	for name, c := range map[string]struct {
		action string
		req    Request
	}{
		"no idempotency key": {ActionDeploy, Request{Kind: KindDeployTarget, Files: &Files{Key: "k", Certificate: "c"}}},
		"no files":           {ActionDeploy, Request{Kind: KindDeployTarget, IdempotencyKey: "x"}},
		"dns action":         {ActionPresent, Request{Kind: KindDeployTarget, FQDN: "a.", Value: "v"}},
		"kind not served":    {ActionPresent, Request{FQDN: "a.", Value: "v"}},
		"discovery missing":  {ActionInventory, Request{Kind: KindDiscovery}},
	} {
		if r := call(t, s, c.action, c.req); r.OK || r.Class != ClassPermanent {
			t.Errorf("%s: %+v", name, r)
		}
	}
}

func TestDiscoveryInventory(t *testing.T) {
	s := &Server{Name: "d", Version: "1", Discovery: fakeDiscovery{}}
	if r := call(t, s, ActionInventory, Request{Kind: KindDiscovery}); !r.OK || r.Items[0].Location != "store" {
		t.Fatalf("got %+v", r)
	}
}

func TestInventoryOutputLimit(t *testing.T) {
	p := testPlugin(t, "inventory")
	r, err := p.Call(context.Background(), ActionInventory, Request{Kind: KindDiscovery})
	if err != nil || len(r.Items) != 200 {
		t.Fatalf("inventory: %v", err)
	}
	// The same output is too large for any other action.
	if _, err := p.Call(context.Background(), ActionVerify, Request{Kind: KindDeployTarget}); !IsClass(err, ClassPermanent) {
		t.Fatalf("verify: %v", err)
	}
}
