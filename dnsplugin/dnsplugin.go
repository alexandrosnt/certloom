// Package dnsplugin is the DNS solver part of the certloom plugin protocol
// (ADR-0017). It is kept for plugins written against it before the protocol
// grew other kinds; new plugins should use package plugin, which this
// package only re-exports.
package dnsplugin

import (
	"context"
	"io"

	"github.com/alexandrosnt/certloom/plugin"
)

// Protocol is the version spoken by this package.
const Protocol = plugin.Protocol

// Actions.
const (
	ActionDescribe = plugin.ActionDescribe
	ActionPresent  = plugin.ActionPresent
	ActionCleanup  = plugin.ActionCleanup
)

// Error classes a plugin may report.
const (
	ClassAuth        = plugin.ClassAuth
	ClassRateLimited = plugin.ClassRateLimited
	ClassTransient   = plugin.ClassTransient
	ClassPermanent   = plugin.ClassPermanent
)

// MaxOutput caps what is read from a plugin's stdout.
const MaxOutput = plugin.MaxOutput

type (
	// Request is written to the plugin's stdin.
	Request = plugin.Request
	// Response is read from the plugin's stdout.
	Response = plugin.Response
	// Error is a failure reported by a plugin, or a failure to run it.
	Error = plugin.Error
	// Plugin is a configured plugin executable.
	Plugin = plugin.Plugin
	// Classified lets a Handler choose the error class reported to the agent.
	Classified = plugin.Classified
	// Handler implements a DNS plugin in Go.
	Handler = plugin.DNSSolver
)

// IsClass reports whether err is a plugin error of the given class.
func IsClass(err error, class string) bool { return plugin.IsClass(err, class) }

// Serve runs one plugin invocation; see plugin.Server.Serve.
func Serve(ctx context.Context, name, version string, h Handler, args []string, stdin io.Reader, stdout io.Writer) int {
	s := &plugin.Server{Name: name, Version: version, DNS: h}
	return s.Serve(ctx, args, stdin, stdout)
}
