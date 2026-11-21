package secret

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// Resolve dereferences a credential reference. Supported forms:
//
//	env:NAME        value of environment variable NAME
//	file:/path      contents of a file (trailing newline trimmed), e.g. systemd credentials
//
// The reference itself is not secret and may be stored; the value never is.
func Resolve(ref string) (Value, error) {
	kind, arg, ok := strings.Cut(ref, ":")
	if !ok || arg == "" {
		return Value{}, fmt.Errorf("invalid credential reference %q (want env:NAME or file:/path)", ref)
	}
	switch kind {
	case "env":
		v, ok := os.LookupEnv(arg)
		if !ok {
			return Value{}, fmt.Errorf("credential reference %q: environment variable not set", ref)
		}
		return FromString(v), nil
	case "file":
		b, err := os.ReadFile(arg)
		if err != nil {
			return Value{}, fmt.Errorf("credential reference %q: %w", ref, errors.Unwrap(err))
		}
		return New([]byte(strings.TrimRight(string(b), "\r\n"))), nil
	}
	return Value{}, fmt.Errorf("unsupported credential provider %q", kind)
}

// ValidRef reports whether ref is syntactically valid (it may still be unresolvable).
func ValidRef(ref string) bool {
	kind, arg, ok := strings.Cut(ref, ":")
	return ok && arg != "" && (kind == "env" || kind == "file")
}
