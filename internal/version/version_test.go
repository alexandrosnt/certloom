package version

import "testing"

func TestString(t *testing.T) {
	if got, want := String(), "0.0.0-dev (unknown)"; got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
}
