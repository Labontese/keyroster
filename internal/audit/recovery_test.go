package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/krl"
	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// TestRecoveryNearPublishableMaximum (PR #69 review, D-R1): a recovery of
// a KRL near what the signer publishes, 70,000 serials that are not
// adjacent, fits every limit on its way and verifies: two imported versions
// that differ in 1,000 serials and 64 carried certificates it revokes,
// under an Ed25519 CA and under a P-256 CA (the TPM backend's), through
// krl.RecoveryEntries, the request's SigningBytes, tlog.RecoveryBody's
// encoder, the export line and audit verify. The test logs the measured
// sizes; T-03-269 and the 03-06b summary quote them.
func TestRecoveryNearPublishableMaximum(t *testing.T) {
	const serials, moved, carried = 70000, 1000, 64
	for _, alg := range []string{"ed25519", "p256"} {
		t.Run(alg, func(t *testing.T) {
			f := newBareFixtureAt(t, "ed25519", time.Now())
			f.ca = newSigner(t, alg)
			g := f.genesis()
			g.InstallationID = auditInstallationID
			f.addBundle(f.signDocs(g, f.policy(), f.root))
			rf := &revokeFixture{fixture: f}
			rf.issue()
			caKey := rf.ca.PublicKey().Marshal()
			entries := func(from int) []krl.Entry {
				out := make([]krl.Entry, 0, serials)
				for i := from; i < from+serials; i++ {
					out = append(out, krl.Entry{Kind: krl.EntrySerial, CAKey: caKey, Serial: 2*uint64(i) + 1}) //nolint:gosec // G115: a test index
				}
				return out
			}
			v1 := rf.importKRL(entries(0), 10, nil, auditInstallationID)
			v2 := rf.importKRL(entries(moved), 11, nil, auditInstallationID)
			var certs []wire.RecoveredCertificate
			for i := range carried {
				certs = append(certs, wire.RecoveredCertificate{Cert: rf.lostCert(rf.serial + 1000 + uint64(i)).Marshal(), Revoke: true}) //nolint:gosec // G115: a test index
			}
			rf.recover([]wire.RecoveryImport{v1, v2}, certs, nil)
			leaf, err := tlog.DecodeLeaf(rf.leaves[len(rf.leaves)-1])
			if err != nil {
				t.Fatal(err)
			}
			body, err := tlog.DecodeRecoveryBody(leaf.Body)
			if err != nil {
				t.Fatal(err)
			}
			if want := serials + moved + carried; len(body.Entries) != want {
				t.Fatalf("the recovery lists %d entries, want %d", len(body.Entries), want)
			}
			rf.publish(nil)
			lines := rf.lines()
			longest := 0
			for _, l := range lines {
				longest = max(longest, len(l))
			}
			rep, err := Verify(strings.NewReader(join(lines)), Options{Pins: rf.pins(), Threshold: 1})
			if err != nil || rep.Recoveries != 1 {
				t.Fatalf("Verify: %v", err)
			}
			t.Logf("%s CA: KRLs of %d and %d bytes, request %d bytes (cap %d), body %d bytes (cap %d), %d entries, export line %d bytes (cap %d)",
				alg, len(v1.KRL), len(v2.KRL), len(body.Request), wire.MaxRecoveryRequest, len(leaf.Body), tlog.MaxRecoveryBody,
				len(body.Entries), longest, maxLine)
		})
	}
}
