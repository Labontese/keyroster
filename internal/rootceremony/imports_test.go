package rootceremony

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestRootCannotReachCertificateSigning pins that the root ceremony's
// dependency graph excludes the certificate builder, the signer and the CA
// key stores (KEY-07): a root key handed to this package has no code path
// to a certificate.
func TestRootCannotReachCertificateSigning(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "github.com/Labontese/keyroster/internal/rootceremony").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	if !slices.Contains(deps, "github.com/Labontese/keyroster/internal/trust") || !slices.Contains(deps, "golang.org/x/crypto/ssh") {
		t.Fatalf("go list -deps output looks wrong (no internal/trust or x/crypto/ssh):\n%s", out)
	}
	for _, forbidden := range []string{
		"github.com/Labontese/keyroster/internal/cert",
		"github.com/Labontese/keyroster/internal/signer",
		"github.com/Labontese/keyroster/internal/keystore",
	} {
		for _, d := range deps {
			if d == forbidden || strings.HasPrefix(d, forbidden+"/") {
				t.Errorf("internal/rootceremony depends on %s", d)
			}
		}
	}
}

// TestExportedAPI pins the package's exported identifiers to exactly
// SignBundle, SignPolicy, Summary and BundleHash.
func TestExportedAPI(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var exported []string
	parsed := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) //nolint:gosec // G304: the package's own sources
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		parsed++
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Name.IsExported() {
					exported = append(exported, d.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch s := spec.(type) {
					case *ast.TypeSpec:
						if s.Name.IsExported() {
							exported = append(exported, s.Name.Name)
						}
					case *ast.ValueSpec:
						for _, n := range s.Names {
							if n.IsExported() {
								exported = append(exported, n.Name)
							}
						}
					}
				}
			}
		}
	}
	if parsed == 0 {
		t.Fatal("no source files parsed")
	}
	slices.Sort(exported)
	want := []string{"BundleHash", "SignBundle", "SignPolicy", "Summary"}
	if !slices.Equal(exported, want) {
		t.Fatalf("exported identifiers = %v, want exactly %v", exported, want)
	}
}
