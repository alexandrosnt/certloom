package store_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alexandrosnt/certloom/internal/audit"
	"github.com/alexandrosnt/certloom/internal/certparse"
	"github.com/alexandrosnt/certloom/internal/checks"
	"github.com/alexandrosnt/certloom/internal/store"
	"github.com/alexandrosnt/certloom/internal/store/storetest"
	"github.com/alexandrosnt/certloom/internal/testpki"
)

var ctx = context.Background()

func mustOrg(t *testing.T, db *storetest.DB, name string) string {
	t.Helper()
	o, err := db.CreateOrg(ctx, name)
	if err != nil {
		t.Fatal(err)
	}
	return o.ID
}

func TestRowLevelSecurityIsolatesOrgs(t *testing.T) {
	db := storetest.New(t)
	a, b := mustOrg(t, db, "a"), mustOrg(t, db, "b")
	h := testpki.NewHierarchy(t, "rls.example.test")
	pc, _ := certparse.FromX509(h.Leaf.Cert)

	var epID string
	err := db.WithOrg(ctx, a, func(tx *store.Tx) error {
		if _, err := tx.UpsertCertificate(ctx, pc, "import"); err != nil {
			return err
		}
		s, err := tx.CreateScope(ctx, "s", store.ScopeConfig{})
		if err != nil {
			return err
		}
		e := &store.Endpoint{Host: "rls.example.test", Port: 443, ScopeID: s.ID}
		if err := tx.CreateEndpoint(ctx, e); err != nil {
			return err
		}
		epID = e.ID
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	err = db.WithOrg(ctx, b, func(tx *store.Tx) error {
		if _, err := tx.GetCertificate(ctx, pc.SHA256); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("org b sees org a's certificate: %v", err)
		}
		if _, err := tx.GetEndpoint(ctx, epID); !errors.Is(err, store.ErrNotFound) {
			t.Errorf("org b sees org a's endpoint: %v", err)
		}
		// Even an unfiltered query returns nothing from other orgs.
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM certificates`).Scan(&n); err != nil {
			return err
		}
		if n != 0 {
			t.Errorf("unfiltered count across RLS = %d, want 0", n)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Writing a row tagged with another org's id is rejected by WITH CHECK.
	err = db.WithOrg(ctx, b, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO teams (id, org_id, name) VALUES ('team_x', $1, 'spoof')`, a)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "row-level security") {
		t.Errorf("cross-org insert should violate RLS, got %v", err)
	}

	// With no org set, tenant tables are invisible.
	var n int
	if err := db.Pool.QueryRow(ctx, `SELECT count(*) FROM endpoints`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("no-org query saw %d endpoints (err %v)", n, err)
	}
}

func TestSameCertificateImportedTwiceIsOneRow(t *testing.T) {
	db := storetest.New(t)
	org := mustOrg(t, db, "dedupe")
	h := testpki.NewHierarchy(t, "d.example.test")
	pc, _ := certparse.FromX509(h.Leaf.Cert)
	for i, want := range []bool{true, false} {
		err := db.WithOrg(ctx, org, func(tx *store.Tx) error {
			ins, err := tx.UpsertCertificate(ctx, pc, "import")
			if ins != want {
				t.Errorf("import %d: inserted=%v want %v", i, ins, want)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestAuditChainAndTamperDetection(t *testing.T) {
	db := storetest.New(t)
	org := mustOrg(t, db, "audit")
	for i := range 5 {
		err := db.WithOrg(ctx, org, func(tx *store.Tx) error {
			return audit.Write(ctx, tx, &audit.Event{OrgID: org, Actor: "user:test", Action: "test.action",
				ResourceType: "thing", ResourceID: "t" + string(rune('0'+i)), Detail: map[string]any{"i": i}})
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	verify := func() audit.VerifyResult {
		var r audit.VerifyResult
		err := db.WithOrg(ctx, org, func(tx *store.Tx) (err error) {
			r, err = audit.Verify(ctx, tx, org)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := verify(); !r.OK || r.Checked != 5 {
		t.Fatalf("fresh chain: %+v", r)
	}

	// The runtime role cannot rewrite or delete audit events.
	err := db.WithOrg(ctx, org, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE audit_events SET actor = 'mallory' WHERE seq = 3`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("certloom_app UPDATE on audit_events should be denied, got %v", err)
	}
	err = db.WithOrg(ctx, org, func(tx *store.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM audit_events WHERE seq = 3`)
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("certloom_app DELETE on audit_events should be denied, got %v", err)
	}

	// A privileged tamper is detected at the first broken event.
	if _, err := db.Owner.Exec(ctx, `UPDATE audit_events SET actor = 'mallory' WHERE org_id = $1 AND seq = 3`, org); err != nil {
		t.Fatal(err)
	}
	if r := verify(); r.OK || r.BrokenAtSeq != 3 {
		t.Fatalf("tampered chain: %+v", r)
	}
}

func TestSyncFindingsOpensEscalatesResolves(t *testing.T) {
	db := storetest.New(t)
	org := mustOrg(t, db, "findings")
	now := time.Now()
	sync := func(fs ...checks.Finding) *store.SyncResult {
		var r *store.SyncResult
		err := db.WithOrg(ctx, org, func(tx *store.Tx) (err error) {
			r, err = tx.SyncFindings(ctx, "endpoint", "ept_1", fs, now)
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	warn := checks.Finding{Check: checks.CheckExpiry, Severity: checks.Warning, Message: "expires in 20 days"}
	crit := checks.Finding{Check: checks.CheckExpiry, Severity: checks.Critical, Message: "expires in 3 days"}
	info := checks.Finding{Check: checks.CheckFingerprintChanged, Severity: checks.Info, Message: "changed"}

	if r := sync(warn, info); len(r.Opened) != 2 {
		t.Fatalf("first sync: %+v", r)
	}
	if r := sync(warn, info); len(r.Opened) != 0 || len(r.Resolved) != 0 {
		t.Fatalf("idempotent re-sync changed state: %+v", r)
	}
	if r := sync(crit, info); len(r.Escalated) != 1 || len(r.Opened) != 0 || r.Escalated[0].Severity != "critical" {
		t.Fatalf("escalation not reported: %+v", r)
	}
	if r := sync(); len(r.Resolved) != 2 {
		t.Fatalf("resolution: %+v", r)
	}
	var alerts []store.Alert
	_ = db.WithOrg(ctx, org, func(tx *store.Tx) (err error) {
		alerts, err = tx.ListAlerts(ctx, nil, 0)
		return err
	})
	// Info findings never create alerts; the expiry alert exists and is resolved.
	if len(alerts) != 1 || alerts[0].State != "resolved" || alerts[0].Severity != "critical" {
		t.Fatalf("alerts: %+v", alerts)
	}
}

func TestTokens(t *testing.T) {
	db := storetest.New(t)
	org := mustOrg(t, db, "tokens")
	var plain string
	err := db.WithOrg(ctx, org, func(tx *store.Tx) error {
		_, v, err := tx.CreateToken(ctx, "ci", store.RoleViewer, "test", time.Hour)
		plain = v.RevealString()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	gotOrg, ok := store.ParseTokenOrg(plain)
	if !ok || gotOrg != org {
		t.Fatalf("ParseTokenOrg(%q) = %q, %v", plain, gotOrg, ok)
	}
	err = db.WithOrg(ctx, org, func(tx *store.Tx) error {
		tok, err := tx.AuthenticateToken(ctx, plain)
		if err != nil {
			return err
		}
		if tok.Role != store.RoleViewer {
			t.Errorf("role %q", tok.Role)
		}
		if _, err := tx.AuthenticateToken(ctx, plain+"x"); !errors.Is(err, store.ErrInvalidToken) {
			t.Errorf("tampered token accepted: %v", err)
		}
		return tx.RevokeToken(ctx, tok.ID)
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = db.WithOrg(ctx, org, func(tx *store.Tx) error {
		if _, err := tx.AuthenticateToken(ctx, plain); !errors.Is(err, store.ErrInvalidToken) {
			t.Errorf("revoked token accepted: %v", err)
		}
		return nil
	})
	// The plaintext token is never stored.
	var n int
	_ = db.Owner.QueryRow(ctx, `SELECT count(*) FROM api_tokens WHERE encode(token_hash,'escape') LIKE '%' || $1 || '%'`, plain[20:]).Scan(&n)
	if n != 0 {
		t.Fatal("token plaintext found in database")
	}
}
