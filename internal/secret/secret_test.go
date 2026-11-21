package secret

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

const canary = "hunter2-CANARY-7f3a"

func TestRedactionEverywhere(t *testing.T) {
	v := FromString(canary)
	type wrapper struct {
		Pass Value
		Ptr  *Value
	}
	w := wrapper{Pass: v, Ptr: &v}

	outputs := []string{
		fmt.Sprint(v), fmt.Sprintf("%v %+v %#v %s %q %x %X %d", v, v, v, v, v, v, v, v),
		fmt.Sprintf("%v %+v %#v", w, w, w),
		fmt.Sprintf("%v", []Value{v}),
		fmt.Sprintf("%v", map[string]Value{"k": v}),
	}
	j, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	outputs = append(outputs, string(j))

	var buf bytes.Buffer
	l := slog.New(slog.NewJSONHandler(&buf, nil))
	l.Info("msg", "secret", v, "w", w)
	tl := slog.New(slog.NewTextHandler(&buf, nil))
	tl.Info("msg", "secret", v, "ptr", &v)
	outputs = append(outputs, buf.String())

	for _, o := range outputs {
		if strings.Contains(o, canary) {
			t.Fatalf("secret leaked in output: %s", o)
		}
		if strings.Contains(o, fmt.Sprintf("%x", canary)) {
			t.Fatalf("secret leaked hex-encoded: %s", o)
		}
	}
	if v.RevealString() != canary {
		t.Fatal("Reveal must return the original value")
	}
}

func TestNewCopies(t *testing.T) {
	b := []byte("abc")
	v := New(b)
	b[0] = 'x'
	if v.RevealString() != "abc" {
		t.Fatal("New must copy its input")
	}
}
