// Package auditexport ships audit events somewhere the DB admin can't touch,
// so a rewritten audit table shows up as a mismatch (see CompareWithDB).
package auditexport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/alexandrosnt/certloom/internal/audit"
	"github.com/alexandrosnt/certloom/internal/notify"
	"github.com/alexandrosnt/certloom/internal/secret"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/jackc/pgx/v5"
)

// Sink receives batches of events for one org, in sequence order.
// Delivery is at-least-once: a sink may see an event again after a crash.
type Sink interface {
	ID() string
	Write(ctx context.Context, events []audit.Event) error
}

// FileSink appends JSON Lines to a file and fsyncs each batch. Point it at a
// location the database administrator cannot modify (separate host mount,
// append-only/immutable attribute, log shipper pickup).
type FileSink struct {
	Path string
	mu   sync.Mutex
}

// ID implements Sink.
func (s *FileSink) ID() string { return "file:" + s.Path }

// Write implements Sink.
func (s *FileSink) Write(_ context.Context, events []audit.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := os.OpenFile(s.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for i := range events {
		if err := enc.Encode(&events[i]); err != nil {
			return err
		}
	}
	if _, err := f.Write(buf.Bytes()); err != nil {
		return err
	}
	return f.Sync()
}

// WebhookSink POSTs {"events":[...]} with an HMAC signature (same scheme as
// notification webhooks). Receivers should dedupe on (org_id, seq).
type WebhookSink struct {
	URL    string
	Key    secret.Value
	Client *http.Client
}

// ID implements Sink.
func (s *WebhookSink) ID() string { return "webhook:" + s.URL }

// Write implements Sink.
func (s *WebhookSink) Write(ctx context.Context, events []audit.Event) error {
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "certloom-audit-export")
	if !s.Key.IsEmpty() {
		req.Header.Set("X-Certloom-Signature", notify.Sign(s.Key.Reveal(), body))
	}
	c := s.Client
	if c == nil {
		c = &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("audit webhook returned %d", resp.StatusCode)
	}
	return nil
}

// ParseSink builds a sink from "file:/path" or "webhook:https://..." and an
// optional credential reference for the webhook HMAC key.
func ParseSink(spec, keyRef string) (Sink, error) {
	kind, arg, ok := strings.Cut(spec, ":")
	if !ok || arg == "" {
		return nil, fmt.Errorf("invalid audit export sink %q (want file:/path or webhook:https://...)", spec)
	}
	switch kind {
	case "file":
		return &FileSink{Path: arg}, nil
	case "webhook":
		if !strings.HasPrefix(arg, "https://") && !strings.HasPrefix(arg, "http://127.0.0.1") && !strings.HasPrefix(arg, "http://localhost") {
			return nil, errors.New("audit webhook must use https (http only for localhost)")
		}
		ws := &WebhookSink{URL: arg}
		if keyRef != "" {
			k, err := secret.Resolve(keyRef)
			if err != nil {
				return nil, err
			}
			ws.Key = k
		}
		return ws, nil
	}
	return nil, fmt.Errorf("unsupported audit export sink %q", kind)
}

// Exporter moves events from the database to a sink.
type Exporter struct {
	DB    *store.DB
	Sink  Sink
	Batch int // default 500
	Log   *slog.Logger
}

// Status is the export state for one org.
type Status struct {
	OrgID     string    `json:"org_id"`
	Sink      string    `json:"sink"`
	LastSeq   int64     `json:"last_exported_seq"`
	HeadSeq   int64     `json:"head_seq"`
	Lag       int64     `json:"lag"`
	LastError string    `json:"last_error,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

// RunOnce exports pending events for every org. Each org's cursor row is
// locked (SKIP LOCKED) so concurrent replicas never export the same org at once.
func (x *Exporter) RunOnce(ctx context.Context) (int, error) {
	rows, err := x.DB.Pool.Query(ctx, `SELECT id FROM organizations ORDER BY id`)
	if err != nil {
		return 0, err
	}
	orgs, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return 0, err
	}
	total := 0
	var errs []error
	for _, org := range orgs {
		n, err := x.exportOrg(ctx, org)
		total += n
		if err != nil {
			errs = append(errs, fmt.Errorf("org %s: %w", org, err))
		}
	}
	return total, errors.Join(errs...)
}

func (x *Exporter) exportOrg(ctx context.Context, org string) (int, error) {
	batch := x.Batch
	if batch <= 0 {
		batch = 500
	}
	n := 0
	var sinkErr error
	err := x.DB.WithOrg(ctx, org, func(tx *store.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO audit_export_cursors (org_id, sink) VALUES ($1,$2) ON CONFLICT DO NOTHING`, org, x.Sink.ID()); err != nil {
			return err
		}
		var last int64
		err := tx.QueryRow(ctx, `SELECT last_seq FROM audit_export_cursors WHERE org_id = $1 AND sink = $2 FOR UPDATE SKIP LOCKED`,
			org, x.Sink.ID()).Scan(&last)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // another replica is exporting this org
		}
		if err != nil {
			return err
		}
		for {
			events, err := audit.Query(ctx, tx, org, last, batch)
			if err != nil {
				return err
			}
			if len(events) == 0 {
				break
			}
			if err := x.Sink.Write(ctx, events); err != nil {
				sinkErr = err
				_, uerr := tx.Exec(ctx, `UPDATE audit_export_cursors SET last_error = $3, updated_at = now() WHERE org_id = $1 AND sink = $2`,
					org, x.Sink.ID(), truncate(err.Error(), 500))
				return uerr
			}
			last = events[len(events)-1].Seq
			n += len(events)
			if _, err := tx.Exec(ctx, `UPDATE audit_export_cursors SET last_seq = $3, last_error = '', updated_at = now() WHERE org_id = $1 AND sink = $2`,
				org, x.Sink.ID(), last); err != nil {
				return err
			}
			if len(events) < batch {
				break
			}
		}
		return nil
	})
	if err == nil {
		err = sinkErr
	}
	return n, err
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// GetStatus returns export state for the org visible in tx.
func GetStatus(ctx context.Context, tx *store.Tx) ([]Status, error) {
	var head int64
	if err := tx.QueryRow(ctx, `SELECT COALESCE(max(seq),0) FROM audit_events WHERE org_id = $1`, tx.OrgID).Scan(&head); err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, `SELECT sink, last_seq, last_error, updated_at FROM audit_export_cursors WHERE org_id = $1 ORDER BY sink`, tx.OrgID)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Status, error) {
		s := Status{OrgID: tx.OrgID, HeadSeq: head}
		err := r.Scan(&s.Sink, &s.LastSeq, &s.LastError, &s.UpdatedAt)
		s.Lag = head - s.LastSeq
		return s, err
	})
}

// StreamReport is the result of verifying an exported JSONL stream.
type StreamReport struct {
	Orgs       map[string]OrgReport `json:"orgs"`
	OK         bool                 `json:"ok"`
	Problems   []string             `json:"problems,omitempty"`
	Duplicates int                  `json:"duplicates"` // identical re-deliveries (expected with at-least-once)
}

// OrgReport summarizes one org's exported chain.
type OrgReport struct {
	Events   int64  `json:"events"`
	LastSeq  int64  `json:"last_seq"`
	LastHash []byte `json:"last_hash"`
}

// VerifyStream checks an exported JSONL stream on its own: each org's chain
// must start at seq 1, be contiguous, link prev_hash to the previous hash and
// have correct hashes. A re-delivered event must be byte-identical; the same
// sequence number with different content is reported as tampering.
func VerifyStream(r io.Reader) (*StreamReport, error) {
	rep := &StreamReport{Orgs: map[string]OrgReport{}, OK: true}
	seen := map[string]map[int64][]byte{}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	line := 0
	for sc.Scan() {
		line++
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, fmt.Errorf("line %d: %w", line, err)
		}
		problem := func(format string, a ...any) {
			rep.OK = false
			rep.Problems = append(rep.Problems, fmt.Sprintf("org %s seq %d (line %d): ", e.OrgID, e.Seq, line)+fmt.Sprintf(format, a...))
		}
		h, err := audit.ComputeHash(&e)
		if err != nil {
			return nil, err
		}
		if !bytes.Equal(h, e.Hash) {
			problem("content does not match its hash")
			continue
		}
		if seen[e.OrgID] == nil {
			seen[e.OrgID] = map[int64][]byte{}
		}
		if prev, dup := seen[e.OrgID][e.Seq]; dup {
			if bytes.Equal(prev, e.Hash) {
				rep.Duplicates++
			} else {
				problem("two different events exported with the same sequence number")
			}
			continue
		}
		o := rep.Orgs[e.OrgID]
		switch {
		case e.Seq != o.LastSeq+1:
			problem("expected seq %d (gap or reorder)", o.LastSeq+1)
		case o.LastSeq == 0 && !bytes.Equal(e.PrevHash, make([]byte, 32)):
			problem("first event does not start a chain")
		case o.LastSeq > 0 && !bytes.Equal(e.PrevHash, o.LastHash):
			problem("prev_hash does not link to previous event")
		}
		seen[e.OrgID][e.Seq] = e.Hash
		o.Events++
		o.LastSeq, o.LastHash = e.Seq, e.Hash
		rep.Orgs[e.OrgID] = o
	}
	return rep, sc.Err()
}

// Mismatch is a difference between the export and the database.
type Mismatch struct {
	Seq    int64  `json:"seq"`
	Reason string `json:"reason"`
}

// CompareWithDB checks that every exported event of the org in tx exists in
// the database unchanged. This detects a database rewrite even when the
// attacker recomputed the database hash chain.
func CompareWithDB(ctx context.Context, tx *store.Tx, exported []audit.Event) ([]Mismatch, error) {
	var out []Mismatch
	for i := 0; i < len(exported); {
		end := min(i+1000, len(exported))
		chunk := exported[i:end]
		dbEvents, err := audit.Query(ctx, tx, tx.OrgID, chunk[0].Seq-1, len(chunk)+1)
		if err != nil {
			return nil, err
		}
		bySeq := map[int64][]byte{}
		for _, e := range dbEvents {
			bySeq[e.Seq] = e.Hash
		}
		for _, e := range chunk {
			h, ok := bySeq[e.Seq]
			switch {
			case !ok:
				out = append(out, Mismatch{e.Seq, "exported event missing from database (deleted?)"})
			case !bytes.Equal(h, e.Hash):
				out = append(out, Mismatch{e.Seq, "database event differs from exported copy (rewritten?)"})
			}
		}
		i = end
	}
	return out, nil
}

// ReadStream loads all events for one org from a JSONL stream, deduplicated, in seq order.
func ReadStream(r io.Reader, org string) ([]audit.Event, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 16<<20)
	seen := map[int64]bool{}
	var out []audit.Event
	for sc.Scan() {
		if len(bytes.TrimSpace(sc.Bytes())) == 0 {
			continue
		}
		var e audit.Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			return nil, err
		}
		if e.OrgID != org || seen[e.Seq] {
			continue
		}
		seen[e.Seq] = true
		out = append(out, e)
	}
	for i := 1; i < len(out); i++ { // insertion sort; streams are nearly sorted
		for j := i; j > 0 && out[j].Seq < out[j-1].Seq; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out, sc.Err()
}
