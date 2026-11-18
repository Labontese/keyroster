package audit

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Labontese/keyroster/internal/tlog"
	"github.com/Labontese/keyroster/internal/wire"
)

// FuzzVerifyExport: Verify never panics on arbitrary input (Forget seeds
// included), and whatever it
// accepts is a non-empty log whose checkpoint the log key of a bundle signed
// by the pinned root signed.
func FuzzVerifyExport(f *testing.F) {
	fx := standard(f, "ed25519")
	lines := fx.lines()
	f.Add([]byte(join(lines)))
	f.Add([]byte(join(lines[:2])))
	f.Add([]byte(join([]string{lines[0], lines[2], lines[1], lines[5]})))
	f.Add([]byte(strings.Repeat("{}\n", 3)))
	f.Add([]byte(`{"index":0,"leaf":"AA=="}` + "\n" + `{"checkpoint":"x"}` + "\n"))
	// Kind 7 and 8 entries (02-04): a log under the same root with a
	// directory install and two logins, which verifies under the same pins,
	// plus a truncation and a reordering of it.
	lf := newLoginFixtureRoot(f, true, fx.root)
	lf.addDirectory(lf.directory(nil), nil)
	lf.addLogin(nil, nil)
	lf.addLogin(nil, nil)
	login := lf.lines() // bundle_install, directory_install, 2 login_issue, checkpoint
	pins := fx.pins()
	if _, err := Verify(strings.NewReader(join(login)), Options{Pins: pins, Threshold: 1}); err != nil {
		f.Fatalf("the login seed does not verify under the pins: %v", err)
	}
	f.Add([]byte(join(login)))
	f.Add([]byte(join([]string{login[0], login[1], login[2], login[4]})))
	f.Add([]byte(join([]string{login[0], login[2], login[1], login[3], login[4]})))
	// A kind 16 entry (03-08c): a log under the same root with two
	// directory installs and a host_forget entry, which verifies under the
	// same pins, plus a truncation of it.
	ff := newForgetFixture(f, 2, fx.root)
	ff.forget(ff.request(), nil)
	forget := ff.lines() // bundle_install, 2 directory_install, host_forget, checkpoint
	if _, err := Verify(strings.NewReader(join(forget)), Options{Pins: pins, Threshold: 1}); err != nil {
		f.Fatalf("the forget seed does not verify under the pins: %v", err)
	}
	f.Add([]byte(join(forget)))
	f.Add([]byte(join([]string{forget[0], forget[1], forget[3], forget[4]})))
	// A kind 13 entry (03-11): a log under the same root with a directory
	// that lists machines and a machine_issue entry, which verifies under
	// the same pins, plus a truncation of it.
	mf := newMachineFixtureWith(f, true, fx.root)
	mf.addMachine(mf.mkey, nil, nil, nil)
	machine := mf.lines()
	if _, err := Verify(strings.NewReader(join(machine)), Options{Pins: pins, Threshold: 1}); err != nil {
		f.Fatalf("the machine seed does not verify under the pins: %v", err)
	}
	f.Add([]byte(join(machine)))
	f.Add([]byte(join(append(slices.Clone(machine[:len(machine)-2]), machine[len(machine)-1]))))
	// A log with a ca_init and a ca_generation entry (03-12), a truncation
	// of it, and two logs Verify must refuse: a ca_generation for the role
	// foo, and one before the first bundle_install.
	gf, _ := initFixture(f, fx.root)
	gf.add(tlog.KindCAGeneration, caGenBody(f, "user", 2, newSigner(f, "ed25519").PublicKey()))
	gen := gf.lines()
	if _, err := Verify(strings.NewReader(join(gen)), Options{Pins: pins, Threshold: 1}); err != nil {
		f.Fatalf("the ca_generation seed does not verify under the pins: %v", err)
	}
	f.Add([]byte(join(gen)))
	f.Add([]byte(join(gen[:2])))
	uf, _ := initFixture(f, fx.root)
	uf.add(tlog.KindCAGeneration, caGenBody(f, "foo", 2, newSigner(f, "ed25519").PublicKey()))
	f.Add([]byte(join(uf.lines())))
	bf := newBareFixture(f, "ed25519")
	bf.root = fx.root
	bf.add(tlog.KindCAGeneration, caGenBody(f, "user", 2, newSigner(f, "ed25519").PublicKey()))
	bf.addBundle(bf.signDocs(bf.genesis(), bf.policy(), bf.root))
	f.Add([]byte(join(bf.lines())))
	// A switch (03-12e): a log under the same root that adds generation 2
	// of the user CA as next and switches to it, and a log with a recovery
	// that carries a revoked certificate; both verify under the same pins.
	t0 := time.Now().UTC().Truncate(time.Second)
	sf, sv2, sc := switchLogWith(f, t0, fx.root, "")
	sf.addBundle(sf.switchBundle(sv2, sc.ValidBefore+300))
	sw := sf.lines()
	if _, err := Verify(strings.NewReader(join(sw)), Options{Pins: pins, Threshold: 1}); err != nil {
		f.Fatalf("the switch seed does not verify under the pins: %v", err)
	}
	f.Add([]byte(join(sw)))
	cf, _, _ := switchLogWith(f, t0, fx.root, auditInstallationID)
	rf := &revokeFixture{fixture: cf}
	lost := rf.lostCert(rf.serial + 1000)
	rf.recover(nil, []wire.RecoveredCertificate{{Cert: lost.Marshal(), Revoke: true}}, nil)
	rf.publish(func(o *publishOpts) { o.bundle = 2 })
	carried := rf.lines()
	if _, err := Verify(strings.NewReader(join(carried)), Options{Pins: pins, Threshold: 1}); err != nil {
		f.Fatalf("the carried-certificate seed does not verify under the pins: %v", err)
	}
	f.Add([]byte(join(carried)))
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := Verify(strings.NewReader(string(data)), Options{Pins: pins, Threshold: 1})
		if err != nil {
			return
		}
		if rep.Size == 0 || len(rep.Root) != tlog.HashSize {
			t.Fatalf("accepted an empty or rootless log: %+v", rep)
		}
	})
}
