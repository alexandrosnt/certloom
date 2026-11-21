// Package secret provides a value type that refuses to reveal its contents
// through formatting, logging or JSON encoding.
package secret

import (
	"fmt"
	"log/slog"
)

const redacted = "[REDACTED]"

// Value holds sensitive bytes. The zero value is an empty secret.
// Read the contents only via Reveal, so every use is easy to audit.
type Value struct{ b []byte }

// New wraps b. The caller should not retain or log b afterwards.
func New(b []byte) Value { return Value{b: append([]byte(nil), b...)} }

// FromString wraps s.
func FromString(s string) Value { return Value{b: []byte(s)} }

// Reveal returns the secret bytes. Every call site must be justified in review.
func (v Value) Reveal() []byte { return v.b }

// RevealString returns the secret as a string.
func (v Value) RevealString() string { return string(v.b) }

// IsEmpty reports whether the secret has no content.
func (v Value) IsEmpty() bool { return len(v.b) == 0 }

// String implements fmt.Stringer.
func (Value) String() string { return redacted }

// GoString implements fmt.GoStringer (%#v).
func (Value) GoString() string { return redacted }

// Format implements fmt.Formatter so every verb (%s %v %q %x %d ...) is redacted.
func (Value) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redacted)) }

// MarshalJSON implements json.Marshaler.
func (Value) MarshalJSON() ([]byte, error) { return []byte(`"` + redacted + `"`), nil }

// MarshalText implements encoding.TextMarshaler (covers YAML/TOML/some loggers).
func (Value) MarshalText() ([]byte, error) { return []byte(redacted), nil }

// LogValue implements slog.LogValuer.
func (Value) LogValue() slog.Value { return slog.StringValue(redacted) }
