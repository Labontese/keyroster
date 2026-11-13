package audit

import (
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/Labontese/keyroster/internal/trust"
)

// newTestInstallationID is a fresh installation ID, as root sign draws one
// for a genesis bundle (03-14c, F05).
func newTestInstallationID(t *testing.T) string {
	t.Helper()
	id, err := trust.NewInstallationID()
	if err != nil {
		t.Fatal(err)
	}
	return id
}

// installationLog is the log of one installation: its root-signed genesis
// bundle_install, naming the installation id ("" for none), and one issue
// entry. root, when set, replaces the fixture's own root, so that two
// installations can share one root set; every other key (log, CAs, ops,
// admin) is the installation's own (03-14c, F05).
func installationLog(t *testing.T, root ssh.Signer, id string) *fixture {
	t.Helper()
	f := newBareFixture(t, "ed25519")
	if root != nil {
		f.root = root
	}
	g := f.genesis()
	g.InstallationID = id
	f.addBundle(f.signDocs(g, f.policy(), f.root))
	f.addIssue()
	return f
}

// TestVerifyInstallationBinding (03-14c, F05): with Options.InstallationID,
// Verify binds the result to the installation the trust bundle in force
// names, so the export of another installation whose bundle chain has the
// same root set is refused, naming both installations. Without it, Verify
// checks nothing and reports the installation (keyroster audit verify then
// refuses an installation-bound log unbound, Q-C7).
func TestVerifyInstallationBinding(t *testing.T) {
	x, y := newTestInstallationID(t), newTestInstallationID(t)
	fx := installationLog(t, nil, x)
	fy := installationLog(t, fx.root, y)
	verify := func(f *fixture, id string) (*Report, error) {
		return Verify(strings.NewReader(join(f.lines())), Options{Pins: f.pins(), Threshold: 1, InstallationID: id})
	}

	t.Run("own_export_ok", func(t *testing.T) {
		rep, err := verify(fx, x)
		if err != nil {
			t.Fatalf("X's export, X expected: %v", err)
		}
		if rep.Bundle == nil || rep.Bundle.InstallationID != x {
			t.Fatalf("the report's bundle names %+v, want installation %s", rep.Bundle, x)
		}
	})

	t.Run("other_installation_refused", func(t *testing.T) {
		if fy.pins()[0] != fx.pins()[0] {
			t.Fatal("the two installations do not share their root")
		}
		_, err := verify(fy, x)
		want := "names installation " + y + ", not the expected " + x
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("Y's export with X expected: err = %v, want %q", err, want)
		}
	})

	t.Run("unchecked_verifies_and_reports", func(t *testing.T) {
		rep, err := verify(fy, "")
		if err != nil {
			t.Fatalf("Y's export, nothing expected: %v", err)
		}
		if rep.Bundle == nil || rep.Bundle.InstallationID != y {
			t.Fatalf("the report's bundle names %+v, want installation %s", rep.Bundle, y)
		}
	})

	t.Run("id_less_bundle_refused", func(t *testing.T) {
		f := installationLog(t, fx.root, "")
		_, err := verify(f, x)
		want := "names no installation ID, but " + x + " is expected"
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("an ID-less export with X expected: err = %v, want %q", err, want)
		}
	})

	t.Run("id_added_after_anchor_ok", func(t *testing.T) {
		// The anchor (genesis) names no installation; its successor adds
		// X, as root sign --installation-id new does. The binding is to
		// the bundle in force, never to the anchor.
		f := newBareFixture(t, "ed25519")
		g := f.signDocs(f.genesis(), f.policy(), f.root)
		f.addBundle(g)
		f.addIssue()
		f.addBundle(f.signDocs(f.successor(g, func(b *trust.Bundle) { b.InstallationID = x }), f.policy(), f.root))
		f.addIssue()
		rep, err := verify(f, x)
		if err != nil {
			t.Fatalf("a log whose successor adds X, X expected: %v", err)
		}
		if rep.AnchorVersion != 1 || rep.Bundle == nil || rep.Bundle.Version != 2 || rep.Bundle.InstallationID != x {
			t.Fatalf("anchor v%d, bundle in force %+v; want anchor v1 and bundle v2 naming %s", rep.AnchorVersion, rep.Bundle, x)
		}
	})

	t.Run("malformed_expected_refused", func(t *testing.T) {
		_, err := Verify(strings.NewReader(""), Options{Pins: fx.pins(), Threshold: 1, InstallationID: "ABC"})
		if err == nil || !strings.Contains(err.Error(), "is not 32 lowercase hex digits") {
			t.Fatalf("InstallationID ABC: err = %v, want the malformed-ID refusal", err)
		}
	})
}
