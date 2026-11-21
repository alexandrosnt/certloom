// Package ids generates prefixed, time-sortable identifiers,
// e.g. "ept_01jd8k3w5x7y9z0a1b2c3d4e5f".
package ids

import (
	"crypto/rand"
	"strings"
	"time"

	"github.com/oklog/ulid/v2"
)

// Prefixes for resource types.
const (
	Org      = "org"
	Team     = "team"
	Lineage  = "lin"
	Scope    = "scp"
	Endpoint = "ept"
	Finding  = "fnd"
	Alert    = "alr"
	Channel  = "chn"
	Token    = "tok"
)

// New returns a new identifier with the given prefix.
func New(prefix string) string {
	u := ulid.MustNew(ulid.Timestamp(time.Now()), rand.Reader)
	return prefix + "_" + strings.ToLower(u.String())
}

// HasPrefix reports whether id is of the given type.
func HasPrefix(id, prefix string) bool { return strings.HasPrefix(id, prefix+"_") }
