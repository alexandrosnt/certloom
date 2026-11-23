package kek

import (
	"bytes"
	"testing"
)

func TestDerive(t *testing.T) {
	raw := bytes.Repeat([]byte{7}, 32)
	a, err := New(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := New(raw)
	if !bytes.Equal(a.Derive("x"), b.Derive("x")) {
		t.Fatal("same KEK and label must derive the same key")
	}
	if bytes.Equal(a.Derive("x"), a.Derive("y")) {
		t.Fatal("different labels must derive different keys")
	}
	other, _ := New(bytes.Repeat([]byte{8}, 32))
	if bytes.Equal(a.Derive("x"), other.Derive("x")) {
		t.Fatal("different KEKs must derive different keys")
	}
	raw[0] = 0 // New must not keep the caller's slice
	if !bytes.Equal(a.Derive("x"), b.Derive("x")) {
		t.Fatal("derived key changed after the caller modified its buffer")
	}
}
