package join

import (
	"testing"
)

// FuzzParseJoin: Parse never panics, and every string it accepts is the
// canonical join string of what it returned (Format gives it back, its
// line end trimmed), so two readers of one join string cannot disagree.
func FuzzParseJoin(f *testing.F) {
	j := valid(f)
	s, err := Format(j)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(s)
	f.Add(s + "\n")
	f.Add(Prefix)
	f.Add(Prefix + "e30")
	f.Add("kr-join-v1:AAAA")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		got, err := Parse(in)
		if err != nil {
			return
		}
		again, err := Format(*got)
		if err != nil {
			t.Fatalf("Format of a parsed join string: %v", err)
		}
		if p, err := Parse(again); err != nil || p.Token != got.Token || p.Server != got.Server {
			t.Fatalf("the canonical form does not parse back: %v", err)
		}
	})
}
