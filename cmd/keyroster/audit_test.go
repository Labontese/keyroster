package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/audit"
	"github.com/Labontese/keyroster/internal/tlog"
)

// TestVerifyOutput: the OK line, then "host certificates: N" when the log
// holds host_issue entries, and no such line otherwise (03-09).
func TestVerifyOutput(t *testing.T) {
	for _, n := range []uint64{3, 0} {
		rep := &audit.Report{Counts: map[tlog.Kind]uint64{tlog.KindHostIssue: n}, IssuedByCA: map[string]int{}}
		var b bytes.Buffer
		if err := printVerifyOK(&b, verifyResultOf(rep), rep); err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(b.String()), "\n")
		if !strings.HasPrefix(lines[0], "OK: ") {
			t.Fatalf("first line %q", lines[0])
		}
		has := strings.Contains(b.String(), "\nhost certificates: ")
		switch {
		case n > 0 && (len(lines) < 2 || lines[1] != "host certificates: 3"):
			t.Fatalf("output %q, want host certificates: 3 after the OK line", b.String())
		case n == 0 && has:
			t.Fatalf("output %q, want no host certificates line", b.String())
		}
	}
}
