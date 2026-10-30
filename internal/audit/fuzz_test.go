package audit

import (
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/tlog"
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
