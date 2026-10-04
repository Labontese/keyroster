package cert

import (
	"go/scanner"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Structural guards of the signing boundary (CA-06, CA-07, KEY-01):
//
//   - internal/cert.Build is the only code in the module that references the
//     certificate signing method;
//   - no non-test file on the signing path references a GenerateKey function,
//     so the signer never creates subject keys.
//
// The matcher works on Go tokens, so comments and string literals neither
// trigger nor hide a hit, and a method value (f := c.SignCert) counts the
// same as a call. TestGuardMatcherSelfCheck proves the matcher finds what it
// must, and every walk asserts that it visited files, so neither test can
// pass vacuously.

// forbiddenRef reports the lines of src that reference name: as a selector
// (x.name) when selector is true, otherwise as any identifier.
func forbiddenRef(src []byte, name string, selector bool) []int {
	fset := token.NewFileSet()
	file := fset.AddFile("src.go", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, nil, 0) // mode 0: comments are skipped
	var lines []int
	prev := token.ILLEGAL
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return lines
		}
		if tok == token.IDENT && lit == name && (!selector || prev == token.PERIOD) {
			lines = append(lines, fset.Position(pos).Line)
		}
		prev = tok
	}
}

// moduleRoot returns the directory of the module's go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		t.Fatal("not inside a Go module")
	}
	return filepath.Dir(gomod)
}

// walkGoFiles calls fn with the slash-separated module-relative path and
// content of every non-test .go file, skipping vendor/, testdata/ and
// hidden directories. It returns the number of files visited.
func walkGoFiles(t *testing.T, root string, fn func(rel string, src []byte)) int {
	t.Helper()
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if path != root && (name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".")) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		src, err := os.ReadFile(path) //nolint:gosec // G304: walking the module's own sources
		if err != nil {
			return err
		}
		n++
		fn(filepath.ToSlash(rel), src)
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return n
}

func TestSignCertOnlyInBuild(t *testing.T) {
	root := moduleRoot(t)
	checked := 0
	visited := walkGoFiles(t, root, func(rel string, src []byte) {
		if strings.HasPrefix(rel, "internal/cert/") {
			return
		}
		checked++
		for _, line := range forbiddenRef(src, "SignCert", true) {
			t.Errorf("%s:%d references SignCert; certificates are signed only by internal/cert.Build", rel, line)
		}
	})
	if visited == 0 || checked == 0 {
		t.Fatalf("visited %d files, checked %d outside internal/cert; the walk found nothing", visited, checked)
	}
}

// signingPath lists the code that must never generate keys.
var signingPath = []string{
	"internal/signer/",
	"internal/cert/",
	"internal/wire/",
	"internal/signerclient/",
	"cmd/keyroster/ca.go",
}

func onSigningPath(rel string) bool {
	for _, p := range signingPath {
		if rel == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(rel, p)) {
			return true
		}
	}
	return false
}

func TestNoGenerateKeyOnSigningPath(t *testing.T) {
	root := moduleRoot(t)
	checked := 0
	walkGoFiles(t, root, func(rel string, src []byte) {
		if !onSigningPath(rel) {
			return
		}
		checked++
		for _, line := range forbiddenRef(src, "GenerateKey", false) {
			t.Errorf("%s:%d references GenerateKey; the signing path never generates keys (CA-06)", rel, line)
		}
	})
	if checked == 0 {
		t.Fatal("no signing-path file was checked; the walk or the path list is broken")
	}
}

func TestGuardMatcherSelfCheck(t *testing.T) {
	sample := []byte(`package x

import (
	"crypto/ed25519"
	"crypto/rand"
)

// c.SignCert(rand.Reader, ca) in a comment does not count.
var s = "ed25519.GenerateKey(nil) in a string does not count"

func f(c *ssh.Certificate, ca ssh.Signer) {
	_ = c.SignCert(rand.Reader, ca)
	sign := c.SignCert
	_, _, _ = ed25519.GenerateKey(rand.Reader)
}
`)
	if got, want := forbiddenRef(sample, "SignCert", true), []int{12, 13}; !slices.Equal(got, want) {
		t.Errorf("SignCert matches on lines %v, want %v", got, want)
	}
	if got, want := forbiddenRef(sample, "GenerateKey", false), []int{14}; !slices.Equal(got, want) {
		t.Errorf("GenerateKey matches on lines %v, want %v", got, want)
	}
	if got := forbiddenRef([]byte("package x\nfunc SignCert() {}\n"), "SignCert", true); len(got) != 0 {
		t.Errorf("a declaration named SignCert is not a selector, got matches on lines %v", got)
	}
	for rel, want := range map[string]bool{
		"internal/signer/issue.go":      true,
		"internal/signerdb/db.go":       false,
		"internal/signerclient/x.go":    true,
		"cmd/keyroster/ca.go":           true,
		"cmd/keyroster/commands.go":     false,
		"internal/certificates/zz.go":   false,
		"internal/cert/builder.go":      true,
		"cmd/keyroster-signer/serve.go": false,
	} {
		if got := onSigningPath(rel); got != want {
			t.Errorf("onSigningPath(%q) = %v, want %v", rel, got, want)
		}
	}
}
