package audit

import (
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/tlog"
)

// FuzzVerifyExport: Verify never panics on arbitrary input, and whatever it
// accepts is a non-empty log whose checkpoint the pinned key signed.
func FuzzVerifyExport(f *testing.F) {
	fx := standard(f, "ed25519")
	lines := fx.lines()
	f.Add([]byte(join(lines)))
	f.Add([]byte(join(lines[:2])))
	f.Add([]byte(join([]string{lines[1], lines[0], lines[4]})))
	f.Add([]byte(strings.Repeat("{}\n", 3)))
	f.Add([]byte(`{"index":0,"leaf":"AA=="}` + "\n" + `{"checkpoint":"x"}` + "\n"))
	pub := fx.logKey.PublicKey()
	f.Fuzz(func(t *testing.T, data []byte) {
		rep, err := Verify(strings.NewReader(string(data)), Options{LogKey: pub})
		if err != nil {
			return
		}
		if rep.Size == 0 || len(rep.Root) != tlog.HashSize {
			t.Fatalf("accepted an empty or rootless log: %+v", rep)
		}
	})
}
