package store

import (
	"strconv"
	"strings"
)

// replaceN substitutes the placeholder $N with $<n> (for dynamic filters).
func replaceN(s string, n int) string { return strings.ReplaceAll(s, "$N", "$"+strconv.Itoa(n)) }

func itoa(n int) string { return strconv.Itoa(n) }
