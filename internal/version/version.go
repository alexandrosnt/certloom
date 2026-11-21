// Package version exposes build metadata injected at link time.
package version

// Set via -ldflags "-X github.com/alexandrosnt/certloom/internal/version.Version=..." in release builds.
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
)

// String returns a human-readable version string.
func String() string { return Version + " (" + Commit + ")" }
