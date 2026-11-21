// Command hookrecv is a webhook receiver for the e2e tests: it appends each
// request's Standard Webhooks headers and body as a JSON line to a file.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatal("usage: hookrecv FILE")
	}
	var mu sync.Mutex
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		line, _ := json.Marshal(map[string]any{"headers": map[string]string{
			"webhook-id":        r.Header.Get("webhook-id"),
			"webhook-timestamp": r.Header.Get("webhook-timestamp"),
			"webhook-signature": r.Header.Get("webhook-signature"),
		}, "body": string(b)})
		mu.Lock()
		defer mu.Unlock()
		f, err := os.OpenFile(os.Args[1], os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644) //nolint:gosec // written as root in the container, read by the test on the host
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		defer f.Close()
		_, _ = f.Write(append(line, '\n'))
	})
	srv := &http.Server{Addr: ":8080", ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
