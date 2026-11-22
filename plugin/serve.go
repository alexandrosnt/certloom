package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// DNSSolver implements the dns_solver kind.
type DNSSolver interface {
	Present(ctx context.Context, req Request) error
	Cleanup(ctx context.Context, req Request) error
}

// DeployTarget implements the deploy_target kind. Verify returns the leaf
// certificate the target serves now, PEM. Rollback restores whatever the
// deploy with req.IdempotencyKey replaced; the plugin keeps that itself.
type DeployTarget interface {
	Deploy(ctx context.Context, req Request) error
	Verify(ctx context.Context, req Request) (string, error)
	Rollback(ctx context.Context, req Request) error
}

// Inventorier implements the discovery kind. A DeployTarget may implement
// it too, to report what the target holds.
type Inventorier interface {
	Inventory(ctx context.Context, req Request) ([]Item, error)
}

// Server is a plugin written in Go. Set the handlers for the kinds the
// plugin implements and leave the others nil.
type Server struct {
	Name, Version string
	DNS           DNSSolver
	Deploy        DeployTarget
	Discovery     Inventorier
}

// Classified lets a handler choose the error class reported to the agent.
type Classified struct {
	Class      string
	RetryAfter time.Duration
	Err        error
}

func (c *Classified) Error() string { return c.Err.Error() }
func (c *Classified) Unwrap() error { return c.Err }

// Kinds returns the kinds s implements, in a fixed order.
func (s *Server) Kinds() []string {
	var k []string
	if s.DNS != nil {
		k = append(k, KindDNSSolver)
	}
	if s.Deploy != nil {
		k = append(k, KindDeployTarget)
	}
	if s.Discovery != nil {
		k = append(k, KindDiscovery)
	}
	return k
}

// Serve runs one plugin invocation: action is the first argument, the
// request is read from stdin and the response written to stdout. It returns
// the process exit code.
func (s *Server) Serve(ctx context.Context, args []string, stdin io.Reader, stdout io.Writer) int {
	resp := s.serve(ctx, args, stdin)
	if err := json.NewEncoder(stdout).Encode(resp); err != nil {
		return 2
	}
	if resp.Error != "" {
		return 1
	}
	return 0
}

func permanent(format string, a ...any) Response {
	return Response{Error: fmt.Sprintf(format, a...), Class: ClassPermanent}
}

func (s *Server) serve(ctx context.Context, args []string, stdin io.Reader) Response {
	if len(args) != 1 {
		return permanent("usage: <plugin> %s", strings.Join(s.actions(), "|"))
	}
	action := args[0]
	if action == ActionDescribe {
		return Response{OK: true, Protocol: Protocol, Name: s.Name, Version: s.Version, Kinds: s.Kinds()}
	}
	var req Request
	if err := json.NewDecoder(io.LimitReader(stdin, MaxOutput)).Decode(&req); err != nil {
		return permanent("bad request: %v", err)
	}
	if req.Protocol != Protocol {
		return permanent("protocol %d not supported, want %d", req.Protocol, Protocol)
	}
	kind := req.Kind
	if kind == "" {
		kind = KindDNSSolver // agents older than ADR-0027
	}
	var resp Response
	var err error
	switch {
	case kind == KindDNSSolver && s.DNS != nil && (action == ActionPresent || action == ActionCleanup):
		if req.FQDN == "" || req.Value == "" {
			return permanent("fqdn and value are required")
		}
		if action == ActionPresent {
			err = s.DNS.Present(ctx, req)
		} else {
			err = s.DNS.Cleanup(ctx, req)
		}
	case kind == KindDeployTarget && s.Deploy != nil && (action == ActionDeploy || action == ActionVerify || action == ActionRollback):
		if req.IdempotencyKey == "" {
			return permanent("idempotency_key is required")
		}
		switch action {
		case ActionDeploy:
			if req.Files == nil || req.Files.Key == "" || req.Files.Certificate == "" {
				return permanent("files.key and files.certificate are required")
			}
			err = s.Deploy.Deploy(ctx, req)
		case ActionVerify:
			resp.Certificate, err = s.Deploy.Verify(ctx, req)
		default:
			err = s.Deploy.Rollback(ctx, req)
		}
	case action == ActionInventory && s.inventorier(kind) != nil:
		resp.Items, err = s.inventorier(kind).Inventory(ctx, req)
	default:
		return permanent("action %s not supported for kind %s", action, kind)
	}
	if err == nil {
		resp.OK = true
		return resp
	}
	resp = Response{Error: err.Error(), Class: ClassTransient}
	var c *Classified
	if errors.As(err, &c) {
		resp.Class = c.Class
		resp.RetryAfter = int64(c.RetryAfter / time.Second)
	}
	return resp
}

func (s *Server) inventorier(kind string) Inventorier {
	switch kind {
	case KindDiscovery:
		return s.Discovery
	case KindDeployTarget:
		inv, _ := s.Deploy.(Inventorier)
		return inv
	}
	return nil
}

func (s *Server) actions() []string {
	a := []string{ActionDescribe}
	if s.DNS != nil {
		a = append(a, ActionPresent, ActionCleanup)
	}
	if s.Deploy != nil {
		a = append(a, ActionDeploy, ActionVerify, ActionRollback)
	}
	if s.Discovery != nil || s.inventorier(KindDeployTarget) != nil {
		a = append(a, ActionInventory)
	}
	return a
}
