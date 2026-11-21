package ari

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/testpki"
)

func TestCertIDMatchesRFCExample(t *testing.T) {
	// RFC 9773 section 4.1 example: AKI 69:88:5B:6B:87:46:40:41:E1:B3:7B:84:7B:A0:AE:2C:DE:01:C8:D4,
	// serial 00:87:65:43:21 -> "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE".
	aki := []byte{0x69, 0x88, 0x5B, 0x6B, 0x87, 0x46, 0x40, 0x41, 0xE1, 0xB3, 0x7B, 0x84, 0x7B, 0xA0, 0xAE, 0x2C, 0xDE, 0x01, 0xC8, 0xD4}
	c := &x509.Certificate{AuthorityKeyId: aki, SerialNumber: big.NewInt(0x87654321)}
	id, err := CertID(c)
	if err != nil {
		t.Fatal(err)
	}
	if id != "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" {
		t.Fatalf("CertID = %s", id)
	}
	if serialFromID(id).Cmp(c.SerialNumber) != 0 {
		t.Fatal("serial round trip")
	}
}

func TestFetchAndChoose(t *testing.T) {
	h := testpki.NewHierarchy(t, "ari.example.test")
	start := time.Now().Add(10 * 24 * time.Hour).UTC().Truncate(time.Second)
	end := start.Add(48 * time.Hour)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/dir":
			_ = json.NewEncoder(w).Encode(map[string]string{"renewalInfo": srv.URL + "/ari"})
		case strings.HasPrefix(r.URL.Path, "/ari/"):
			id, _ := CertID(h.Leaf.Cert)
			if r.URL.Path != "/ari/"+id {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Retry-After", "21600")
			_ = json.NewEncoder(w).Encode(map[string]any{"suggestedWindow": map[string]time.Time{"start": start, "end": end}})
		case r.URL.Path == "/nodir":
			_ = json.NewEncoder(w).Encode(map[string]string{"newOrder": "x"})
		}
	}))
	defer srv.Close()
	c := &Client{}
	u, err := c.RenewalInfoURL(context.Background(), srv.URL+"/dir")
	if err != nil {
		t.Fatal(err)
	}
	w, err := c.Fetch(context.Background(), u, h.Leaf.Cert)
	if err != nil {
		t.Fatal(err)
	}
	if !w.Start.Equal(start) || !w.End.Equal(end) || w.RetryAfter != 6*time.Hour {
		t.Fatalf("%+v", w)
	}
	r := rand.New(rand.NewPCG(1, 2))
	for range 100 {
		at := ChooseTime(w, time.Now(), r)
		if at.Before(start) || !at.Before(end) {
			t.Fatalf("chosen time %v outside window", at)
		}
	}
	// Window already passed -> now.
	now := time.Now()
	if got := ChooseTime(&Window{Start: now.Add(-48 * time.Hour), End: now.Add(-time.Hour)}, now, r); !got.Equal(now) {
		t.Fatalf("past window: %v", got)
	}
	if _, err := c.RenewalInfoURL(context.Background(), srv.URL+"/nodir"); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("no ARI: %v", err)
	}
}

func TestFallbackAndClamp(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	c90 := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(90 * 24 * time.Hour)}
	if got := Fallback(c90); !got.Equal(nb.Add(60 * 24 * time.Hour)) {
		t.Fatalf("90d: %v", got)
	}
	c6 := &x509.Certificate{NotBefore: nb, NotAfter: nb.Add(160 * time.Hour)} // shortlived
	got := Fallback(c6)
	if !got.Equal(nb.Add(160*time.Hour*2/3)) || !got.Before(c6.NotAfter) {
		t.Fatalf("6d: %v", got)
	}
	if ClampRetry(0) != 6*time.Hour || ClampRetry(time.Minute) != time.Hour || ClampRetry(72*time.Hour) != 24*time.Hour {
		t.Fatal("clamp")
	}
	_ = base64.RawURLEncoding
}
