// Package cagraph models certificate authorities as a graph (ADR-0029).
//
// An authority is a subject plus a public key. Cross-signed copies of a CA
// share both, so they are one authority with several certificates, each of
// which may have a different parent authority.
package cagraph

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"slices"
	"time"
)

// maxDepth bounds walks up and down the graph; real hierarchies are 2-4 deep.
const maxDepth = 8

// Key returns the authority key of a CA certificate.
func Key(c *x509.Certificate) string {
	h := sha256.New()
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(c.RawSubject))) //nolint:gosec // DER subjects are far below 4 GiB
	h.Write(n[:])
	h.Write(c.RawSubject)
	h.Write(c.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(h.Sum(nil))
}

// Cert is one stored CA certificate.
type Cert struct {
	SHA256    string    `json:"sha256"`
	Key       string    `json:"-"`
	IssuerKey string    `json:"issuer_key,omitempty"` // empty when the parent is not in the inventory
	Subject   string    `json:"-"`
	Issuer    string    `json:"issuer"`
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	// ChainExpiry is the end of this copy's path upward: the earliest
	// not_after along it.
	ChainExpiry time.Time `json:"chain_expiry"`
	SelfSigned  bool      `json:"self_signed"`
}

// Authority groups the copies of one CA.
type Authority struct {
	Key      string   `json:"key"`
	Subject  string   `json:"subject"`
	Root     bool     `json:"root"`
	Copies   []*Cert  `json:"copies"`
	Parents  []string `json:"parents,omitempty"`
	Children []string `json:"children,omitempty"`
	// Expiry is the latest ChainExpiry of any copy: after it no path through
	// this authority is valid.
	Expiry time.Time `json:"expiry"`
}

// Graph is the set of authorities in one organization.
type Graph struct {
	byKey map[string]*Authority
}

// Build groups certs into authorities and computes their expiry.
func Build(certs []Cert) *Graph {
	g := &Graph{byKey: map[string]*Authority{}}
	for i := range certs {
		c := &certs[i]
		a := g.byKey[c.Key]
		if a == nil {
			a = &Authority{Key: c.Key, Subject: c.Subject}
			g.byKey[c.Key] = a
		}
		if c.SelfSigned || c.IssuerKey == c.Key {
			a.Root = true
		}
		a.Copies = append(a.Copies, c)
	}
	for _, a := range g.byKey {
		for _, c := range a.Copies {
			p := c.IssuerKey
			if p == "" || p == a.Key || g.byKey[p] == nil {
				continue
			}
			if !slices.Contains(a.Parents, p) {
				a.Parents = append(a.Parents, p)
				g.byKey[p].Children = append(g.byKey[p].Children, a.Key)
			}
		}
	}
	memo := map[string]time.Time{}
	for k := range g.byKey {
		g.expiry(k, memo, map[string]bool{}, 0)
	}
	for _, a := range g.byKey {
		slices.Sort(a.Parents)
		slices.Sort(a.Children)
		slices.SortFunc(a.Copies, func(x, y *Cert) int { return x.NotAfter.Compare(y.NotAfter) })
	}
	return g
}

func (g *Graph) expiry(key string, memo map[string]time.Time, visiting map[string]bool, depth int) time.Time {
	if t, ok := memo[key]; ok {
		return t
	}
	a := g.byKey[key]
	visiting[key] = true
	var best time.Time
	for _, c := range a.Copies {
		end := c.NotAfter
		p := c.IssuerKey
		// A parent on the current path is a mutual cross-sign: the copy's
		// own validity is all that can be said without looping.
		if p != "" && p != key && g.byKey[p] != nil && !visiting[p] && depth < maxDepth {
			if pe := g.expiry(p, memo, visiting, depth+1); pe.Before(end) {
				end = pe
			}
		}
		c.ChainExpiry = end
		if end.After(best) {
			best = end
		}
	}
	delete(visiting, key)
	a.Expiry = best
	memo[key] = best
	return best
}

// Get returns an authority, or nil.
func (g *Graph) Get(key string) *Authority { return g.byKey[key] }

// Len returns the number of authorities.
func (g *Graph) Len() int { return len(g.byKey) }

// All returns the authorities, soonest expiry first.
func (g *Graph) All() []*Authority {
	out := make([]*Authority, 0, len(g.byKey))
	for _, a := range g.byKey {
		out = append(out, a)
	}
	slices.SortFunc(out, func(x, y *Authority) int {
		if c := x.Expiry.Compare(y.Expiry); c != 0 {
			return c
		}
		return compareStrings(x.Key, y.Key)
	})
	return out
}

func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// Expiry returns the effective expiry of the chain above a certificate
// signed by key, and false when key is not in the graph.
func (g *Graph) Expiry(key string) (time.Time, bool) {
	a := g.byKey[key]
	if a == nil {
		return time.Time{}, false
	}
	return a.Expiry, true
}

// Descendants returns key and every authority below it.
func (g *Graph) Descendants(key string) []string {
	return g.walk(key, func(a *Authority) []string { return a.Children })
}

// Ancestors returns key and every authority above it.
func (g *Graph) Ancestors(key string) []string {
	return g.walk(key, func(a *Authority) []string { return a.Parents })
}

func (g *Graph) walk(key string, next func(*Authority) []string) []string {
	if g.byKey[key] == nil {
		return nil
	}
	seen := map[string]bool{key: true}
	level := []string{key}
	out := []string{key}
	for depth := 0; depth < maxDepth && len(level) > 0; depth++ {
		var nextLevel []string
		for _, k := range level {
			for _, n := range next(g.byKey[k]) {
				if !seen[n] {
					seen[n] = true
					nextLevel = append(nextLevel, n)
					out = append(out, n)
				}
			}
		}
		level = nextLevel
	}
	return out
}
