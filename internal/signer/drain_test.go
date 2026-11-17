package signer

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/keystore"
	"github.com/Labontese/keyroster/internal/trust"
	"github.com/Labontese/keyroster/internal/wire"
)

// tableCounts returns the row count of every table of the state database
// at path, read outside the signer (03-12e).
func tableCounts(t *testing.T, path string) map[string]int {
	t.Helper()
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = raw.Close() }()
	rows, err := raw.Query(`SELECT name FROM sqlite_master WHERE type = 'table' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	_ = rows.Close()
	counts := map[string]int{}
	for _, n := range names {
		var c int
		if err := raw.QueryRow(`SELECT count(*) FROM "` + n + `"`).Scan(&c); err != nil { //nolint:gosec // G202: a table name sqlite_master returned
			t.Fatal(err)
		}
		counts[n] = c
	}
	return counts
}

// sameCounts requires the table counts after to equal before.
func sameCounts(t *testing.T, before, after map[string]int) {
	t.Helper()
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("the table row counts changed:\nbefore %v\nafter  %v", before, after)
	}
}

// fixedClock is a clock that always reads t.
func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// roleMaxTTL is the max_ttl_seconds of role in p.
func roleMaxTTL(t *testing.T, p *trust.Policy, role string) uint64 {
	t.Helper()
	for _, prof := range p.CAProfiles {
		if prof.Role == role {
			return prof.MaxTTLSeconds
		}
	}
	t.Fatalf("the policy has no %s profile", role)
	return 0
}

// issueUser issues one user certificate through s valid for validFor
// seconds, created at now.
func issueUser(t *testing.T, e *genEnv, s *Signer, now time.Time, validFor uint64) *ssh.Certificate {
	t.Helper()
	req := &wire.IssueRequest{
		CARole: wire.CARoleUser, SubjectKey: newEd25519(t).PublicKey().Marshal(), Subject: "u:alice",
		Principals: []string{"alice"}, ValidForSeconds: uint32(validFor), CreatedAt: uint64(now.Unix()), //nolint:gosec // G115: a policy TTL and a time after 1970
		InstallationID: e.fx.InstallationID,
	}
	if _, err := rand.Read(req.RequestID[:]); err != nil {
		t.Fatal(err)
	}
	req.Evidence = SignRequest(t, req, e.fx.Admins...)
	resp, err := s.Issue(context.Background(), Peer{UID: 1000}, req)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	pk, err := ssh.ParsePublicKey(resp.Cert)
	if err != nil {
		t.Fatal(err)
	}
	c, ok := pk.(*ssh.Certificate)
	if !ok {
		t.Fatal("Issue returned no certificate")
	}
	return c
}

// switchDocs returns the root-signed successor of the bundle installed in
// e that switches role (its next entry becomes active and its active entry
// draining), built by trust.BuildSuccessor at issuedAt with allowance and
// the installed policy unchanged (03-12e).
func switchDocs(t *testing.T, e *genEnv, issuedAt time.Time, allowance time.Duration, roles ...string) [4][]byte {
	t.Helper()
	sb, err := e.db.LatestBundle(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	prev, err := trust.ParseBundle(sb.Bundle)
	if err != nil {
		t.Fatal(err)
	}
	next, err := trust.BuildSuccessor(prev, sb.Bundle, sb.Policy, trust.SuccessorOptions{
		Roots: prev.Root.Keys, Threshold: prev.Root.Threshold, Policy: sb.Policy,
		IssuedAt: issuedAt.UTC().Format(trust.TimeFormat), InstallationID: prev.InstallationID,
		CASwitch: roles, DrainAllowance: allowance,
	})
	if err != nil {
		t.Fatalf("BuildSuccessor: %v", err)
	}
	pol, err := trust.ParsePolicy(sb.Policy)
	if err != nil {
		t.Fatal(err)
	}
	return docs4(t, next, pol, e.fx.Root)
}

// unixTime formats Unix seconds u in trust.TimeFormat.
func unixTime(u uint64) string {
	return time.Unix(int64(u), 0).UTC().Format(trust.TimeFormat) //nolint:gosec // G115: a test time
}

// TestSwitchTracer (03-12e, the tracer): one user CA switch end to end, in
// process. Ceremony 1 adds the prepared generation 2 as next; a certificate
// of generation 1 issued after the ceremony's clock is valid until V; a
// switch built by trust.BuildSuccessor whose trusted_until leaves that
// certificate live is refused with the certificate named and nothing
// written; with a longer allowance it installs behind the log's checkpoint,
// a restarted signer issues with generation 2, and audit verifies the
// export.
func TestSwitchTracer(t *testing.T) {
	ctx := context.Background()
	// t0 is the ceremony clock: a whole second, a minute ahead of the
	// real clock, so every fake signer clock below is after the leaves
	// written at bootstrap.
	t0 := time.Now().UTC().Truncate(time.Second).Add(time.Minute)
	e := newGenEnv(t)
	g2 := e.mustPrepare(t, keystore.RoleUser)
	if _, err := e.install(editedSuccessor(t, e.db, func(b *trust.Bundle) {
		insertCA(b, nextEntry(t, g2))
		b.IssuedAt = t0.Format(trust.TimeFormat)
	}, nil, e.fx.Root)); err != nil {
		t.Fatalf("ceremony 1: %v", err)
	}
	_, pol := installedDocs(t, e.db)
	m := roleMaxTTL(t, pol, trust.RoleUser)
	s, err := New(Config{Backend: e.be, DB: e.db, Clock: fixedClock(t0.Add(10 * time.Second)), AllowUIDs: []uint32{1000}})
	if err != nil {
		t.Fatalf("start after ceremony 1: %v", err)
	}
	c := issueUser(t, e, s, t0.Add(10*time.Second), m)
	v := uint64(t0.Unix()) + 10 + m //nolint:gosec // G115: after 1970
	if c.ValidBefore != v {
		t.Fatalf("the generation-1 certificate is valid until %d, want %d", c.ValidBefore, v)
	}
	if !bytes.Equal(c.SignatureKey.Marshal(), e.fx.Roles[keystore.RoleUser].PublicKey().Marshal()) {
		t.Fatal("the certificate before the switch is not signed by generation 1")
	}
	installed := false
	t.Run("too_short_refused_writes_nothing", func(t *testing.T) {
		cp, _, err := e.db.LatestCheckpoint(ctx)
		if err != nil {
			t.Fatal(err)
		}
		before, leaves := tableCounts(t, e.dbPath), e.leaves(t)
		d := switchDocs(t, e, t0, 0, trust.RoleUser)
		_, _, err = InstallBundleWithPrevious(ctx, e.db, e.be, nil, 0, d[0], d[1], d[2], d[3], fixedClock(t0.Add(20*time.Second)), cp)
		if !errors.Is(err, ErrDrainWindowTooShort) {
			t.Fatalf("the switch with allowance 0: %v, want drain_window_too_short", err)
		}
		t.Logf("refusal: %v", err)
		for _, want := range []string{
			fmt.Sprintf("serial %d", c.Serial), "key ID " + c.KeyId,
			"the earliest acceptable trusted_until is " + unixTime(v+300),
		} {
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("the refusal %q does not name %q", err, want)
			}
		}
		sameCounts(t, before, tableCounts(t, e.dbPath))
		if n := e.leaves(t); n != leaves {
			t.Fatalf("%d leaves after the refusal, want %d", n, leaves)
		}
	})
	t.Run("installed_and_issues_with_the_new_key", func(t *testing.T) {
		cp, _, err := e.db.LatestCheckpoint(ctx)
		if err != nil {
			t.Fatal(err)
		}
		d := switchDocs(t, e, t0, 20*time.Second, trust.RoleUser)
		b, notes, err := InstallBundleWithPrevious(ctx, e.db, e.be, nil, 0, d[0], d[1], d[2], d[3], fixedClock(t0.Add(20*time.Second)), cp)
		if err != nil {
			t.Fatalf("the switch with allowance 20 s: %v", err)
		}
		if b.Version != 3 || trust.ActiveCA(b, trust.RoleUser).Generation != 2 {
			t.Fatalf("installed bundle v%d with active user generation %d, want v3 and generation 2", b.Version, trust.ActiveCA(b, trust.RoleUser).Generation)
		}
		if len(notes) != 1 || notes[0].Role != trust.RoleUser || notes[0].Generation != 1 || !notes[0].Recorded || notes[0].Max.Serial != c.Serial {
			t.Fatalf("drain notes %+v, want one for user generation 1 naming serial %d", notes, c.Serial)
		}
		installed = true
		s2, err := New(Config{Backend: e.be, DB: e.db, Clock: fixedClock(t0.Add(30 * time.Second)), AllowUIDs: []uint32{1000}})
		if err != nil {
			t.Fatalf("restart after the switch: %v", err)
		}
		c2 := issueUser(t, e, s2, t0.Add(30*time.Second), 600)
		if !bytes.Equal(c2.SignatureKey.Marshal(), g2.PublicKey) {
			t.Fatalf("the certificate after the switch is signed by %s, want generation 2", ssh.FingerprintSHA256(c2.SignatureKey))
		}
	})
	t.Run("audit_verifies_the_switch", func(t *testing.T) {
		if !installed {
			t.Fatal("the switch was not installed")
		}
		var buf bytes.Buffer
		if _, err := audit.Export(ctx, &buf, e.db); err != nil {
			t.Fatal(err)
		}
		rep, err := audit.Verify(&buf, audit.Options{Pins: []string{e.fx.RootPin()}, Threshold: 1})
		if err != nil {
			t.Fatalf("audit.Verify: %v", err)
		}
		if rep.BundleVersion != 3 {
			t.Fatalf("audit reports bundle version %d, want 3", rep.BundleVersion)
		}
	})
}
