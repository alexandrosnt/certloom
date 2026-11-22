package dnsplugin_test

import (
	"context"
	"errors"
	"os"

	"github.com/alexandrosnt/certloom/dnsplugin"
)

// memoryDNS stands in for a DNS provider's API client.
type memoryDNS struct{ records map[string]string }

func (m *memoryDNS) Present(_ context.Context, req dnsplugin.Request) error {
	if req.Config["api"] == nil {
		return &dnsplugin.Classified{Class: dnsplugin.ClassPermanent, Err: errors.New("config.api is required")}
	}
	m.records[req.FQDN] = req.Value
	return nil
}

func (m *memoryDNS) Cleanup(_ context.Context, req dnsplugin.Request) error {
	delete(m.records, req.FQDN) // removing a missing record is not an error
	return nil
}

// A plugin's main: one invocation per action, the request on stdin and the
// response on stdout.
func Example() {
	h := &memoryDNS{records: map[string]string{}}
	code := dnsplugin.Serve(context.Background(), "memory", "1.0.0", h, []string{"describe"}, os.Stdin, os.Stdout)
	_ = code // os.Exit(code) in a real plugin
	// Output: {"ok":true,"protocol":1,"name":"memory","version":"1.0.0","kinds":["dns_solver"]}
}
