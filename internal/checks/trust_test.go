package checks

import (
	"testing"

	"github.com/alexandrosnt/certloom/internal/agentproto"
)

func trustState(typ string, anchors ...agentproto.TrustAnchor) agentproto.TrustStoreState {
	return agentproto.TrustStoreState{Name: "s", Type: typ, Mode: agentproto.TrustManage, Anchors: anchors}
}

func TestTrustStoreFindings(t *testing.T) {
	desired := map[string]bool{"a": true, "b": true}
	inBundles := map[string]bool{"a": true, "b": true}
	base := TrustStoreInput{Assigned: true, Bundle: "corp", Desired: desired, CurrentVersion: 2, ConfirmedVersion: 2, InBundles: inBundles, Now: t0}

	in := base
	in.State = trustState(agentproto.TrustPEM, agentproto.TrustAnchor{SHA256: "a", Owned: true}, agentproto.TrustAnchor{SHA256: "b", Owned: true})
	if fs := TrustStore(in); len(fs) != 0 {
		t.Fatalf("in sync: %+v", fs)
	}

	in.State = trustState(agentproto.TrustPEM, agentproto.TrustAnchor{SHA256: "a", Owned: true})
	fs := TrustStore(in)
	if len(fs) != 1 || fs[0].Check != CheckTrustStoreDrift || fs[0].Severity != Warning {
		t.Fatalf("missing anchor: %+v", fs)
	}
	in.RootsInUse = map[string]bool{"b": true}
	if fs := TrustStore(in); fs[0].Severity != Critical {
		t.Errorf("missing in-use root must be critical: %+v", fs)
	}

	// An unconfirmed version is drift only after the grace period.
	in = base
	in.State = trustState(agentproto.TrustPEM, agentproto.TrustAnchor{SHA256: "a", Owned: true}, agentproto.TrustAnchor{SHA256: "b", Owned: true})
	in.ConfirmedVersion = 1
	sent := t0.Add(-10 * 60e9)
	in.SentAt = &sent
	if fs := TrustStore(in); len(fs) != 0 {
		t.Errorf("within grace: %+v", fs)
	}
	sent = days(-1)
	if fs := TrustStore(in); len(fs) != 1 {
		t.Errorf("after grace: %+v", fs)
	}

	// Windows: the root program entries are ignored, certloom's are judged.
	in = TrustStoreInput{InBundles: inBundles, Now: t0}
	in.State = trustState(agentproto.TrustWindows, agentproto.TrustAnchor{SHA256: "ms"}, agentproto.TrustAnchor{SHA256: "x", Owned: true})
	fs = TrustStore(in)
	if len(fs) != 1 || fs[0].Check != CheckTrustUnknownAnchor {
		t.Fatalf("windows unknown: %+v", fs)
	}
	in.State = trustState(agentproto.TrustDebian, agentproto.TrustAnchor{SHA256: "local"})
	if fs := TrustStore(in); len(fs) != 1 || fs[0].Check != CheckTrustUnknownAnchor {
		t.Fatalf("debian unknown: %+v", fs)
	}
	// Observe-only stores never drift.
	in = base
	in.State = trustState(agentproto.TrustPEM)
	in.State.Mode = agentproto.TrustObserve
	if fs := TrustStore(in); len(fs) != 0 {
		t.Errorf("observe store drift: %+v", fs)
	}
}
