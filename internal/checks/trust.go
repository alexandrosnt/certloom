package checks

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

// Trust store checks (ADR-0030).
const (
	CheckTrustStoreDrift    = "trust_store_drift"
	CheckTrustUnknownAnchor = "trust_store_unknown_anchor"
)

// trustConfirmGrace is how long a store may take to confirm a new version.
const trustConfirmGrace = time.Hour

// TrustStoreInput is one trust store as reported, with its desired state.
type TrustStoreInput struct {
	State agentproto.TrustStoreState
	// Assigned is false for stores no bundle targets; only unknown anchors
	// are checked then.
	Assigned         bool
	Bundle           string
	Desired          map[string]bool // anchor sha256 of the current version
	CurrentVersion   int
	ConfirmedVersion int
	SentAt           *time.Time
	// RootsInUse are anchors that are the root of an authority in use; a
	// store missing one breaks live certificates.
	RootsInUse map[string]bool
	// InBundles holds every anchor of any current bundle version.
	InBundles map[string]bool
	Now       time.Time
}

// TrustStore evaluates drift and unknown anchors of one store.
func TrustStore(in TrustStoreInput) []Finding {
	st := in.State
	var out []Finding
	if in.Assigned && st.Mode == agentproto.TrustManage {
		present := map[string]bool{}
		for _, a := range st.Anchors {
			present[a.SHA256] = true
		}
		var missing, extra []string
		for h := range in.Desired {
			if !present[h] {
				missing = append(missing, h)
			}
		}
		for _, a := range st.Anchors {
			if a.Owned && !in.Desired[a.SHA256] {
				extra = append(extra, a.SHA256)
			}
		}
		slices.Sort(missing)
		slices.Sort(extra)
		late := in.ConfirmedVersion != in.CurrentVersion && in.SentAt != nil && in.Now.Sub(*in.SentAt) > trustConfirmGrace
		if len(missing) > 0 || len(extra) > 0 || late {
			var parts []string
			if len(missing) > 0 {
				parts = append(parts, fmt.Sprintf("%d anchor(s) of bundle %s missing", len(missing), in.Bundle))
			}
			if len(extra) > 0 {
				parts = append(parts, fmt.Sprintf("%d certloom anchor(s) not in the bundle", len(extra)))
			}
			if late {
				parts = append(parts, fmt.Sprintf("version %d not confirmed (store has %d)", in.CurrentVersion, in.ConfirmedVersion))
			}
			sev := Warning
			for _, h := range missing {
				if in.RootsInUse[h] {
					sev = Critical
				}
			}
			f := mk(CheckTrustStoreDrift, sev, strings.Join(parts, "; "),
				"Check the agent's trust.apply results (`certloom trust-bundle status`) and the store on the host.")
			f.Fingerprint = fingerprint(CheckTrustStoreDrift, strings.Join(missing, ","), strings.Join(extra, ","), fmt.Sprint(late))
			out = append(out, f)
		}
	}
	// Windows' root store also holds the Microsoft root program: only what
	// certloom placed there can be judged.
	var unknown []string
	for _, a := range st.Anchors {
		if st.Type == agentproto.TrustWindows && !a.Owned {
			continue
		}
		if !in.InBundles[a.SHA256] {
			unknown = append(unknown, a.SHA256)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		f := mk(CheckTrustUnknownAnchor, Warning,
			fmt.Sprintf("%d locally added anchor(s) are in no trust bundle (first %s)", len(unknown), short(unknown[0])),
			"Add the anchor to a bundle if it is approved, or remove it from the host; accept it with an exception otherwise.")
		f.Fingerprint = fingerprint(CheckTrustUnknownAnchor, strings.Join(unknown, ","))
		out = append(out, f)
	}
	return out
}
