package agent

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"path/filepath"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
	bolt "go.etcd.io/bbolt"
)

// State is the agent's durable local store (survives restarts and offline
// periods): task results for idempotent redelivery, seen nonces, per-target
// sequence fences, deploy rollback records, and results not yet acknowledged.
type State struct{ db *bolt.DB }

var (
	bResults  = []byte("results")  // task id -> agentproto.Result
	bUnsent   = []byte("unsent")   // task id -> 1 (result not yet acknowledged)
	bNonces   = []byte("nonces")   // nonce -> expiry unix
	bSeq      = []byte("seq")      // target -> last executed seq
	bPrevious = []byte("previous") // target/run -> previous live link destination
)

// OpenState opens (or creates) the state database.
func OpenState(dir string) (*State, error) {
	db, err := bolt.Open(filepath.Join(dir, "state.db"), 0o600, &bolt.Options{Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bResults, bUnsent, bNonces, bSeq, bPrevious} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	return &State{db: db}, err
}

// Close closes the database.
func (s *State) Close() error { return s.db.Close() }

// Result returns a stored result for a task.
func (s *State) Result(taskID string) (*agentproto.Result, error) {
	var out *agentproto.Result
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bResults).Get([]byte(taskID))
		if v == nil {
			return nil
		}
		out = &agentproto.Result{}
		return json.Unmarshal(v, out)
	})
	return out, err
}

// ErrReplay is returned for a reused nonce.
var ErrReplay = errors.New("task nonce already used (replay)")

// Admit checks the nonce and sequence fence before execution and records
// the nonce, so a replayed or stale task is never executed.
func (s *State) Admit(t *agentproto.Task) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		nb := tx.Bucket(bNonces)
		if nb.Get([]byte(t.Nonce)) != nil {
			return ErrReplay
		}
		if t.Target != "" {
			if v := tx.Bucket(bSeq).Get([]byte(t.Target)); v != nil && t.Seq < getInt(v) {
				return agentproto.ErrStaleSequence
			}
		}
		return nb.Put([]byte(t.Nonce), putInt(t.NotAfter.Unix()))
	})
}

// Record stores a result (and advances the target fence) atomically, and
// marks it unsent until the control plane acknowledges it.
func (s *State) Record(t *agentproto.Task, r agentproto.Result) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		if err := tx.Bucket(bResults).Put([]byte(t.ID), b); err != nil {
			return err
		}
		if t.Target != "" {
			// The fence only moves forward: recording a rejected stale task
			// must never lower it.
			sb := tx.Bucket(bSeq)
			if cur := sb.Get([]byte(t.Target)); cur == nil || getInt(cur) < t.Seq {
				if err := sb.Put([]byte(t.Target), putInt(t.Seq)); err != nil {
					return err
				}
			}
		}
		return tx.Bucket(bUnsent).Put([]byte(t.ID), []byte{1})
	})
}

// Unsent lists task ids whose results are not yet acknowledged.
func (s *State) Unsent() ([]string, error) {
	var out []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bUnsent).ForEach(func(k, _ []byte) error {
			out = append(out, string(k))
			return nil
		})
	})
	return out, err
}

// Acked removes a task from the unsent set.
func (s *State) Acked(taskID string) error {
	return s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(bUnsent).Delete([]byte(taskID)) })
}

// Previous returns (and if absent, sets via init) the pre-deploy link target
// for target/run. Recording it before switching makes a re-executed deploy
// (crash mid-task) roll back to the right place.
func (s *State) Previous(target, run string, init func() (string, error)) (string, error) {
	key := []byte(target + "/" + run)
	var out string
	err := s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bPrevious)
		if v := b.Get(key); v != nil {
			out = string(v)
			return nil
		}
		v, err := init()
		if err != nil {
			return err
		}
		out = v
		return b.Put(key, []byte(v))
	})
	return out, err
}

// LookupPrevious returns a recorded pre-deploy link target.
func (s *State) LookupPrevious(target, run string) (string, bool) {
	var out []byte
	_ = s.db.View(func(tx *bolt.Tx) error {
		out = append([]byte(nil), tx.Bucket(bPrevious).Get([]byte(target+"/"+run))...)
		return nil
	})
	return string(out), out != nil
}

// PruneNonces drops nonces whose tasks have expired.
func (s *State) PruneNonces(now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bNonces)
		c := b.Cursor()
		for k, v := c.First(); k != nil; k, v = c.Next() {
			if getInt(v) < now.Unix() {
				if err := c.Delete(); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

// putInt and getInt store sequence numbers and Unix times as 8 big-endian
// bytes. Both are never negative, so the uint64 round trip is exact.
func putInt(n int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(n)) //nolint:gosec // non-negative by construction
	return b
}

func getInt(b []byte) int64 {
	return int64(binary.BigEndian.Uint64(b)) //nolint:gosec // written by putInt
}
