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

// TestExportedAPI pins the package's exported identifiers, methods
// included, to exactly the root ceremony API, and pins that no exported
// function or method returns a signer or private key: a software root is
// reachable only through Root.SignBundle and Root.SignPolicy (KEY-07).
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
				if !d.Name.IsExported() {
					continue
				}
				name := d.Name.Name
				if d.Recv != nil {
					name = receiverName(t, d.Recv) + "." + name
				}
				exported = append(exported, name)
				if d.Type.Results != nil {
					for _, res := range d.Type.Results.List {
						if typ := exprText(src, fset, res.Type); forbiddenResult(typ) {
							t.Errorf("%s returns %s: no exported API may hand out a root's signer or key", name, typ)
						}
					}
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
	want := []string{
		"BundleHash", "GenerateRoot", "OpenRoot", "ReadPassphrase", "Root",
		"Root.Close", "Root.PublicKey", "Root.SignBundle", "Root.SignPolicy",
		"SignBundle", "SignPolicy", "Summary", "ValidatePassphrase",
	}
	if !slices.Equal(exported, want) {
		t.Fatalf("exported identifiers = %v, want exactly %v", exported, want)
	}
}

// receiverName returns the type name of a method receiver.
func receiverName(t *testing.T, recv *ast.FieldList) string {
	t.Helper()
	typ := recv.List[0].Type
	if star, ok := typ.(*ast.StarExpr); ok {
		typ = star.X
	}
	id, ok := typ.(*ast.Ident)
	if !ok {
		t.Fatalf("unexpected receiver type %T", typ)
	}
	return id.Name
}

// exprText returns the source text of a type expression.
func exprText(src []byte, fset *token.FileSet, e ast.Expr) string {
	return string(src[fset.Position(e.Pos()).Offset:fset.Position(e.End()).Offset])
}

// forbiddenResult reports whether a result type could carry a usable root
// key: a signer of any kind or a private key.
func forbiddenResult(typ string) bool {
	for _, bad := range []string{"Signer", "PrivateKey", "AlgorithmSigner", "crypto.", "ed25519.", "any", "interface"} {
		if strings.Contains(typ, bad) {
			return true
		}
	}
	return false
}
