//go:build linux

package spool

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// TestHostCertAnswerCap: a host certificate answer in the spool (03-09) is
// capped at MaxHostCertAnswer, the cap the fetcher's heal applies
// (TestPostHostCerts/oversize_answer_healed removes one above it). Read,
// the applier's, takes no answer as a document, so an answer of any size
// never stops documents from landing.
func TestHostCertAnswerCap(t *testing.T) {
	name := "hostcert-" + strings.Repeat("0f", 32) + ".answer"
	if limit, ok := Cap(name); !ok || limit != MaxHostCertAnswer {
		t.Fatalf("Cap(%q) = %d, %t, want %d, true", name, limit, ok, MaxHostCertAnswer)
	}
	for _, bad := range []string{"hostcert-" + strings.Repeat("0F", 32) + ".answer", "hostcert-" + strings.Repeat("0f", 31) + ".answer", "hostcert-" + strings.Repeat("0f", 32) + ".req"} {
		if _, ok := Cap(bad); ok {
			t.Fatalf("Cap(%q) recognises a name outside the pattern", bad)
		}
	}
	for _, n := range []int64{MaxHostCertAnswer, MaxHostCertAnswer + 1} {
		dir := t.TempDir()
		writeTestFile(t, filepath.Join(dir, name), bytes.Repeat([]byte{'a'}, int(n)))
		st, _, err := Read(dir, Floor{})
		if err != nil || len(st.Bundles)+len(st.Policies)+len(st.Directories)+len(st.KRLs) != 0 {
			t.Fatalf("an answer of %d bytes: %v, state %+v; want no error and no document", n, err, st)
		}
	}
}
