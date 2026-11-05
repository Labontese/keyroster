package tlog

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// registryPath is the number and format registry, from this package's
// directory.
var registryPath = filepath.Join("..", "..", "docs", "format-registry.md")

// registryRow is one row of a numbered registry table.
type registryRow struct {
	num      uint64
	status   string // "in use", "reserved" or "retired"
	constant string // the Go constant's name; empty for a reserved row
	line     int
}

// TestFormatRegistry pins docs/format-registry.md to the code: every leaf
// kind constant (type Kind in this package) and every wire message type
// constant (Type* in internal/wire) is listed as in use with its number,
// every in-use row names a constant the code has with that number, a
// reserved or retired number has no constant, and each "next free"
// sentence names one more than the highest number listed. It reads the code with
// go/parser, so it is a syntactic gate: a constant must be declared with
// an integer literal, which the test requires rather than evaluates.
func TestFormatRegistry(t *testing.T) {
	doc, err := os.ReadFile(registryPath) //nolint:gosec // G304: a fixed path under docs/
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ReplaceAll(string(doc), "\r\n", "\n")

	t.Run("leaf kinds", func(t *testing.T) {
		rows := registryRows(t, text, "## Merkle log leaf kinds", `^[0-9]+$`)
		code := codeConstants(t, ".", func(name string, typ ast.Expr) bool {
			id, ok := typ.(*ast.Ident)
			return (ok && id.Name == "Kind") || strings.HasPrefix(name, "Kind")
		})
		compareRegistry(t, "leaf kind", "%d", rows, code)
		checkNextFree(t, text, `The next free kind is ([0-9]+)\.`, rows, "%d")
		// The in-use set is also the set valid accepts, and each in-use
		// kind has a name in exports, not unknown(n).
		inUse := map[uint64]bool{}
		for _, r := range rows {
			if r.status == "in use" {
				inUse[r.num] = true
			}
		}
		for b := byte(0); ; b++ {
			k := Kind(b)
			if k.valid() != inUse[uint64(b)] {
				t.Errorf("kind %d: valid() is %v, but the registry lists it in use: %v", b, k.valid(), inUse[uint64(b)])
			}
			if inUse[uint64(b)] && strings.HasPrefix(k.String(), "unknown(") {
				t.Errorf("kind %d is in use but has no String name", b)
			}
			if b == 255 {
				break
			}
		}
	})

	t.Run("wire message types", func(t *testing.T) {
		rows := registryRows(t, text, "## Wire message types", `^0x[0-9A-F]{2}$`)
		code := codeConstants(t, filepath.Join("..", "wire"), func(name string, _ ast.Expr) bool {
			return strings.HasPrefix(name, "Type") && len(name) > len("Type") &&
				name[len("Type")] >= 'A' && name[len("Type")] <= 'Z'
		})
		compareRegistry(t, "wire message type", "0x%02X", rows, code)
		var requests []registryRow
		for _, r := range rows {
			if r.num < 0x80 {
				requests = append(requests, r)
			}
		}
		checkNextFree(t, text, `The next free request type is (0x[0-9A-F]{2})\.`, requests, "0x%02X")
	})
}

// registryRows returns the rows of the tables in the section that starts
// at heading and ends at the next heading of the same or a higher level,
// whose first cell matches num. Each row is | number | status | constant
// | ... |. A number listed twice fails the test.
func registryRows(t *testing.T, doc, heading, num string) []registryRow {
	t.Helper()
	lines := strings.Split(doc, "\n")
	level := strings.Index(heading, " ")
	start := -1
	for i, l := range lines {
		if l == heading {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("%s: no %q section", registryPath, heading)
	}
	numRE := regexp.MustCompile(num)
	var rows []registryRow
	seen := map[uint64]int{}
	for i := start + 1; i < len(lines); i++ {
		l := lines[i]
		if h := strings.Index(l, "# "); strings.HasPrefix(l, "#") && h >= 0 && h+1 <= level {
			break
		}
		if !strings.HasPrefix(l, "|") {
			continue
		}
		cells := strings.Split(strings.Trim(l, "|"), "|")
		for j := range cells {
			cells[j] = strings.TrimSpace(cells[j])
		}
		if len(cells) < 3 || !numRE.MatchString(cells[0]) {
			continue
		}
		n, err := strconv.ParseUint(cells[0], 0, 8)
		if err != nil {
			t.Fatalf("%s:%d: number %q: %v", registryPath, i+1, cells[0], err)
		}
		r := registryRow{num: n, status: cells[1], constant: strings.Trim(cells[2], "`"), line: i + 1}
		switch r.status {
		case "in use":
			if r.constant == "" {
				t.Errorf("%s:%d: %s is in use but names no constant", registryPath, r.line, cells[0])
			}
		case "reserved", "retired":
		default:
			t.Errorf("%s:%d: %s has status %q, want in use, reserved or retired", registryPath, r.line, cells[0], r.status)
		}
		if prev, ok := seen[n]; ok {
			t.Errorf("%s:%d: %s is listed twice (also on line %d)", registryPath, r.line, cells[0], prev)
		}
		seen[n] = r.line
		rows = append(rows, r)
	}
	if len(rows) == 0 {
		t.Fatalf("%s: section %q has no numbered rows", registryPath, heading)
	}
	return rows
}

// codeConstant is one constant found in the code.
type codeConstant struct {
	num uint64
	pos string
}

// codeConstants parses the non-test Go files in dir and returns the
// constants match selects, by name. Each must be declared with an integer
// literal (decimal or hex), so its number is read without evaluation.
func codeConstants(t *testing.T, dir string, match func(name string, typ ast.Expr) bool) map[string]codeConstant {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]codeConstant{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, f, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs := spec.(*ast.ValueSpec)
				for i, name := range vs.Names {
					if !match(name.Name, vs.Type) {
						continue
					}
					pos := fset.Position(name.Pos()).String()
					var lit *ast.BasicLit
					if i < len(vs.Values) {
						lit, _ = vs.Values[i].(*ast.BasicLit)
					}
					if lit == nil || lit.Kind != token.INT {
						t.Errorf("%s: %s is not declared with an integer literal, so this test cannot read its number", pos, name.Name)
						continue
					}
					n, err := strconv.ParseUint(lit.Value, 0, 8)
					if err != nil {
						t.Errorf("%s: %s = %s: %v", pos, name.Name, lit.Value, err)
						continue
					}
					out[name.Name] = codeConstant{num: n, pos: pos}
				}
			}
		}
	}
	if len(out) == 0 {
		t.Fatalf("no constants found in %s", dir)
	}
	return out
}

// compareRegistry fails the test where rows and code disagree. numFmt
// formats a number as the registry writes it.
func compareRegistry(t *testing.T, what, numFmt string, rows []registryRow, code map[string]codeConstant) {
	num := func(n uint64) string { return fmt.Sprintf(numFmt, n) }
	t.Helper()
	byNum := map[uint64]registryRow{}
	for _, r := range rows {
		byNum[r.num] = r
	}
	for name, c := range code {
		r, ok := byNum[c.num]
		switch {
		case !ok:
			t.Errorf("%s: %s %s = %s is not in %s", c.pos, what, name, num(c.num), registryPath)
		case r.status != "in use":
			t.Errorf("%s: %s %s = %s, but %s:%d lists that number as %s", c.pos, what, name, num(c.num), registryPath, r.line, r.status)
		case r.constant != name:
			t.Errorf("%s: %s %s = %s, but %s:%d gives that number to %s", c.pos, what, name, num(c.num), registryPath, r.line, r.constant)
		}
	}
	for _, r := range rows {
		if r.status != "in use" {
			continue
		}
		c, ok := code[r.constant]
		switch {
		case !ok:
			t.Errorf("%s:%d: %s %s is in use as %s, but the code has no such constant", registryPath, r.line, what, num(r.num), r.constant)
		case c.num != r.num:
			t.Errorf("%s:%d: %s %s is %s in the registry and %s in the code (%s)", registryPath, r.line, what, r.constant, num(r.num), num(c.num), c.pos)
		}
	}
}

// checkNextFree checks that the registry's "next free" sentence (pattern,
// with the number as its group) names one more than the highest number in
// rows, whatever its status.
func checkNextFree(t *testing.T, doc, pattern string, rows []registryRow, numFmt string) {
	t.Helper()
	m := regexp.MustCompile(pattern).FindStringSubmatch(doc)
	if m == nil {
		t.Errorf("%s: no sentence matching %q", registryPath, pattern)
		return
	}
	got, err := strconv.ParseUint(m[1], 0, 8)
	if err != nil {
		t.Errorf("%s: next free number %q: %v", registryPath, m[1], err)
		return
	}
	var want uint64
	for _, r := range rows {
		if r.num >= want {
			want = r.num + 1
		}
	}
	if got != want {
		t.Errorf("%s says the next free number is %s, but the highest listed is %s", registryPath, fmt.Sprintf(numFmt, got), fmt.Sprintf(numFmt, want-1))
	}
}
