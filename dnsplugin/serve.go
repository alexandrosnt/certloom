package dnsplugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Handler implements a plugin in Go.
type Handler interface {
	Present(ctx context.Context, req Request) error
	Cleanup(ctx context.Context, req Request) error
}

// Classified lets a Handler choose the error class reported to the agent.
type Classified struct {
	Class      string
	RetryAfter time.Duration
	Err        error
}

func (c *Classified) Error() string { return c.Err.Error() }
func (c *Classified) Unwrap() error { return c.Err }

// Serve runs one plugin invocation: action is the first argument, the
// request is read from stdin and the response written to stdout. It returns
// the process exit code.
func Serve(ctx context.Context, name, version string, h Handler, args []string, stdin io.Reader, stdout io.Writer) int {
	resp := serve(ctx, name, version, h, args, stdin)
	if err := json.NewEncoder(stdout).Encode(resp); err != nil {
		return 2
	}
	if resp.Error != "" {
		return 1
	}
	return 0
}

func serve(ctx context.Context, name, version string, h Handler, args []string, stdin io.Reader) Response {
	if len(args) != 1 {
		return Response{Error: "usage: <plugin> describe|present|cleanup", Class: ClassPermanent}
	}
	if args[0] == ActionDescribe {
		return Response{OK: true, Protocol: Protocol, Name: name, Version: version}
	}
	var req Request
	if err := json.NewDecoder(io.LimitReader(stdin, MaxOutput)).Decode(&req); err != nil {
		return Response{Error: "bad request: " + err.Error(), Class: ClassPermanent}
	}
	if req.Protocol != Protocol {
		return Response{Error: fmt.Sprintf("protocol %d not supported, want %d", req.Protocol, Protocol), Class: ClassPermanent}
	}
	if req.FQDN == "" || req.Value == "" {
		return Response{Error: "fqdn and value are required", Class: ClassPermanent}
	}
	var err error
	switch args[0] {
	case ActionPresent:
		err = h.Present(ctx, req)
	case ActionCleanup:
		err = h.Cleanup(ctx, req)
	default:
		return Response{Error: "unknown action " + args[0], Class: ClassPermanent}
	}
	if err == nil {
		return Response{OK: true}
	}
	resp := Response{Error: err.Error(), Class: ClassTransient}
	var c *Classified
	if errors.As(err, &c) {
		resp.Class = c.Class
		resp.RetryAfter = int64(c.RetryAfter / time.Second)
	}
	return resp
}
