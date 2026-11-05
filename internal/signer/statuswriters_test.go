package signer

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/Labontese/keyroster/internal/wire"
)

// statusWatched are the names of the fields Status reports or reads
// without the lock (03-08i): the directory state, the snapshot pointer and
// the read-only handle, and the trust state New sets. A selector naming
// one of them, whatever its root, is watched.
var statusWatched = map[string]bool{
	"directory": true, "directoryRaw": true, "directorySigs": true, "directoryVersion": true,
	"directoryAuthorized": true, "directoryState": true, "status": true, "statusDB": true,
	"caKeys": true, "bundleVersion": true, "bundleRow": true,
}

// statusMutators are the functions whose first argument TestStatusWriters
// treats as written: the builtins and the slices functions that change a
// slice in place or return one sharing its array. Read-only calls such as
// slices.Clone, Contains or Equal are not writes.
var (
	statusBuiltinMutators = map[string]bool{"copy": true, "clear": true, "delete": true, "append": true}
	statusSlicesMutators  = map[string]bool{
		"Sort": true, "SortFunc": true, "SortStableFunc": true, "Reverse": true, "Delete": true, "DeleteFunc": true,
		"Insert": true, "Replace": true, "Compact": true, "CompactFunc": true, "Grow": true, "Clip": true,
	}
)

// statusWriteAllow is the allowlist of writes to a watched name outside
// setDirectoryLocked and readDirectory: main's own collisions, each with
// its reason. TestStatusWriters fails when an entry matches nothing.
var statusWriteAllow = []struct {
	file, fn, expr, reason string
}{
	{"trust.go", "loadTrust", "ts.caKeys",
		"trustState.caKeys, a field of the trust state loadTrust returns, not the Signer's; New copies it into its literal"},
}

// statusRequiredFuncs must each be declared exactly once, so a rename
// cannot pass the gate silently.
var statusRequiredFuncs = []string{"setDirectoryLocked", "publishStatusLocked", "readDirectory", "newStatusSnapshot", "Status"}

// statusReplyFields are wire.StatusResponse's fields as the snapshot
// (newStatusSnapshot, copyReply) knows them.
var statusReplyFields = []string{
	"Keys []wire.KeyStatus", "BundleVersion uint64", "Bundle []uint8", "BundleSigs []uint8", "Policy []uint8",
	"PolicySigs []uint8", "DirectoryVersion uint64", "DirectorySHA256 [32]uint8", "DirectoryAuthorized bool",
}

// TestStatusWriters (03-08i) is a syntactic gate on who writes what Status
// reports: every rule of statusWriterViolations, run on this package's
// non-test files. It matches names, not types (go/types would type-check
// every dependency from source), so it catches the common write forms, not
// every possible one: a write through reflection or unsafe would pass.
func TestStatusWriters(t *testing.T) {
	for _, v := range statusWriterViolations(".") {
		t.Error(v)
	}
}

// statusFile is one parsed non-test file.
type statusFile struct {
	name string
	file *ast.File
}

// statusWriterViolations parses every non-test .go file of dir and returns
// one line per violation of the rules on the state Status reports
// (03-08i), each naming the file, the line, the function and the rule.
func statusWriterViolations(dir string) []string {
	var out []string
	fset := token.NewFileSet()
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []string{err.Error()}
	}
	var files []statusFile
	for _, de := range entries {
		n := de.Name()
		if de.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, n), nil, parser.SkipObjectResolution)
		if err != nil {
			return []string{err.Error()}
		}
		files = append(files, statusFile{n, f})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].name < files[j].name })

	report := func(file, fn string, pos token.Pos, format string, args ...any) {
		if fn == "" {
			fn = "(package level)"
		}
		out = append(out, fmt.Sprintf("%s:%d: %s: %s", file, fset.Position(pos).Line, fn, fmt.Sprintf(format, args...)))
	}

	decls := map[string]int{}
	allowUsed := make([]bool, len(statusWriteAllow))
	calls := map[string]map[string]int{} // callee -> caller -> count
	statusStores := 0
	for _, sf := range files {
		for _, d := range sf.file.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				statusCheckNode(d, sf.name, "", report, nil)
				continue
			}
			fn := fd.Name.Name
			decls[fn]++
			if fd.Recv != nil && len(fd.Recv.List) == 1 {
				rt := fd.Recv.List[0].Type
				if st, ok := rt.(*ast.StarExpr); ok {
					rt = st.X
				}
				if id, ok := rt.(*ast.Ident); ok && id.Name == "directoryState" {
					report(sf.name, fn, fd.Pos(), "a method on directoryState; the directory state is written only through Signer.setDirectoryLocked")
				}
			}
			if fd.Body == nil {
				continue
			}
			locals := map[string]bool{}
			if fn == "readDirectory" {
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if vs, ok := n.(*ast.ValueSpec); ok {
						if id, ok := vs.Type.(*ast.Ident); ok && id.Name == "directoryState" {
							for _, name := range vs.Names {
								locals[name.Name] = true
							}
						}
					}
					return true
				})
			}
			ctx := &statusFuncCtx{
				file: sf.name, fn: fn, locals: locals, calls: calls, stores: &statusStores,
				allowUsed: allowUsed,
			}
			statusCheckNode(fd.Body, sf.name, fn, report, ctx)
			switch fn {
			case "InstallDirectory":
				statusCheckPlacement(fd, sf.name, report, true)
			case "loadDirectory":
				statusCheckPlacement(fd, sf.name, report, false)
			}
		}
	}

	for _, name := range statusRequiredFuncs {
		if decls[name] != 1 {
			out = append(out, fmt.Sprintf("%s is declared %d times, want exactly once: a renamed or duplicated function must update TestStatusWriters (03-08i)", name, decls[name]))
		}
	}
	for i, used := range allowUsed {
		if !used {
			a := statusWriteAllow[i]
			out = append(out, fmt.Sprintf("allowlist entry %s %s %s matches nothing: remove it from statusWriteAllow", a.file, a.fn, a.expr))
		}
	}
	want := map[string]map[string]int{
		"setDirectoryLocked":  {"loadDirectory": 1, "InstallDirectory": 1},
		"publishStatusLocked": {"setDirectoryLocked": 1},
	}
	for callee, callers := range want {
		got := calls[callee]
		for caller, n := range got {
			if callers[caller] == 0 {
				out = append(out, fmt.Sprintf("%s calls %s %d times: only %v may call it (03-08i); a new caller must update TestStatusWriters on purpose", caller, callee, n, slices.Sorted(maps.Keys(callers))))
			}
		}
		for caller, n := range callers {
			if got[caller] != n {
				out = append(out, fmt.Sprintf("%s calls %s %d times, want exactly %d (03-08i)", caller, callee, got[caller], n))
			}
		}
	}
	if statusStores != 1 {
		out = append(out, fmt.Sprintf("publishStatusLocked stores the snapshot %d times, want exactly one s.status.Store (03-08i)", statusStores))
	}

	var fields []string
	rt := reflect.TypeFor[wire.StatusResponse]()
	for i := range rt.NumField() {
		f := rt.Field(i)
		fields = append(fields, f.Name+" "+f.Type.String())
	}
	if !slices.Equal(fields, statusReplyFields) {
		out = append(out, fmt.Sprintf("wire.StatusResponse has fields %q, want %q: a new or changed reply field must be added to the snapshot (newStatusSnapshot, copyReply) and to this test (03-08i)", fields, statusReplyFields))
	}
	return out
}

// statusFuncCtx is what statusCheckNode needs to know about the function
// it walks.
type statusFuncCtx struct {
	file, fn  string
	locals    map[string]bool // readDirectory's local directoryState values
	calls     map[string]map[string]int
	stores    *int
	allowUsed []bool
}

// statusUnwrap strips ParenExpr, StarExpr, IndexExpr and SliceExpr.
func statusUnwrap(e ast.Expr) ast.Expr {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		default:
			return e
		}
	}
}

// statusChain walks e down through SelectorExpr.X, IndexExpr.X,
// SliceExpr.X, StarExpr.X and ParenExpr.X and returns the first watched
// name a selector in that chain names ("" for none) and the chain's root
// identifier ("" when the root is not an identifier).
func statusChain(e ast.Expr) (watched, root string) {
	for {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			if watched == "" && statusWatched[x.Sel.Name] {
				watched = x.Sel.Name
			}
			e = x.X
		case *ast.ParenExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.IndexListExpr:
			e = x.X
		case *ast.SliceExpr:
			e = x.X
		case *ast.Ident:
			return watched, x.Name
		default:
			return watched, ""
		}
	}
}

// statusExprString renders a selector chain such as ts.caKeys.
func statusExprString(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return statusExprString(x.X) + "." + x.Sel.Name
	case *ast.ParenExpr:
		return "(" + statusExprString(x.X) + ")"
	case *ast.StarExpr:
		return "*" + statusExprString(x.X)
	case *ast.IndexExpr:
		return statusExprString(x.X) + "[...]"
	case *ast.SliceExpr:
		return statusExprString(x.X) + "[:]"
	default:
		return fmt.Sprintf("%T", e)
	}
}

// statusCheckWrite reports a write (an assignment target, an inc/dec, the
// operand of &, or a mutating call's first argument) to a watched name,
// unless one of the stated exceptions allows it.
func statusCheckWrite(e ast.Expr, how string, ctx *statusFuncCtx, report func(string, string, token.Pos, string, ...any)) {
	watched, root := statusChain(e)
	if watched == "" {
		return
	}
	if ctx != nil {
		switch {
		case ctx.fn == "setDirectoryLocked" && how == "assignment" && watched == "directoryState":
			if sel, ok := statusUnwrap(e).(*ast.SelectorExpr); ok && sel.Sel.Name == "directoryState" {
				return
			}
		case ctx.fn == "readDirectory" && ctx.locals[root]:
			return
		}
		for i, a := range statusWriteAllow {
			if a.file == ctx.file && a.fn == ctx.fn && a.expr == statusExprString(e) {
				ctx.allowUsed[i] = true
				return
			}
		}
	}
	file, fn := "", ""
	if ctx != nil {
		file, fn = ctx.file, ctx.fn
	}
	report(file, fn, e.Pos(), "%s to %s (watched %s): the directory state is written only through setDirectoryLocked, the snapshot only by publishStatusLocked, and the trust state only in New (03-08i)",
		how, statusExprString(e), watched)
}

// statusCheckNode applies the write, composite-literal, snapshot-pointer
// and caller rules to every node under root.
func statusCheckNode(root ast.Node, file, fn string, report func(string, string, token.Pos, string, ...any), ctx *statusFuncCtx) {
	if ctx == nil {
		ctx = &statusFuncCtx{file: file, fn: fn, locals: map[string]bool{}, calls: map[string]map[string]int{}, stores: new(int), allowUsed: make([]bool, len(statusWriteAllow))}
	}
	var stack []ast.Node
	ast.Inspect(root, func(n ast.Node) bool {
		if n == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		parent := ast.Node(nil)
		if len(stack) > 0 {
			parent = stack[len(stack)-1]
		}
		stack = append(stack, n)
		switch x := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range x.Lhs {
				if _, ok := statusParenless(lhs).(*ast.StarExpr); ok {
					report(file, fn, lhs.Pos(), "an assignment through a pointer dereference (%s): it can overwrite the directory state or the snapshot without the setter (03-08i)", statusExprString(lhs))
					continue
				}
				statusCheckWrite(lhs, "assignment", ctx, report)
			}
		case *ast.IncDecStmt:
			statusCheckWrite(x.X, "inc/dec", ctx, report)
		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN {
				for _, e := range []ast.Expr{x.Key, x.Value} {
					if e != nil {
						statusCheckWrite(e, "range assignment", ctx, report)
					}
				}
			}
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				statusCheckWrite(x.X, "address-of", ctx, report)
			}
		case *ast.CallExpr:
			if len(x.Args) > 0 {
				switch f := x.Fun.(type) {
				case *ast.Ident:
					if statusBuiltinMutators[f.Name] {
						statusCheckWrite(x.Args[0], f.Name, ctx, report)
					}
				case *ast.SelectorExpr:
					if id, ok := f.X.(*ast.Ident); ok && id.Name == "slices" && statusSlicesMutators[f.Sel.Name] {
						statusCheckWrite(x.Args[0], "slices."+f.Sel.Name, ctx, report)
					}
				}
			}
		case *ast.CompositeLit:
			statusCheckSignerLit(x, file, fn, report)
		case *ast.SelectorExpr:
			switch x.Sel.Name {
			case "setDirectoryLocked", "publishStatusLocked":
				if call, ok := parent.(*ast.CallExpr); ok && call.Fun == x {
					if ctx.calls[x.Sel.Name] == nil {
						ctx.calls[x.Sel.Name] = map[string]int{}
					}
					ctx.calls[x.Sel.Name][fn]++
				} else {
					report(file, fn, x.Pos(), "a method value of %s: call it, from its allowed callers only (03-08i)", x.Sel.Name)
				}
			case "status":
				statusCheckPointerUse(x, parent, stack, file, fn, report, ctx)
			}
		}
		return true
	})
}

// statusParenless strips ParenExpr only.
func statusParenless(e ast.Expr) ast.Expr {
	for {
		p, ok := e.(*ast.ParenExpr)
		if !ok {
			return e
		}
		e = p.X
	}
}

// statusCheckPointerUse requires every use of a .status selector to be a
// call of its Load method, or the one Store in publishStatusLocked.
func statusCheckPointerUse(sel *ast.SelectorExpr, parent ast.Node, stack []ast.Node, file, fn string, report func(string, string, token.Pos, string, ...any), ctx *statusFuncCtx) {
	method, ok := parent.(*ast.SelectorExpr)
	if !ok || method.X != sel {
		report(file, fn, sel.Pos(), "%s used other than through its Load method (03-08i)", statusExprString(sel))
		return
	}
	var call *ast.CallExpr
	if len(stack) >= 3 {
		call, _ = stack[len(stack)-3].(*ast.CallExpr)
	}
	if call == nil || call.Fun != method {
		report(file, fn, sel.Pos(), "a method value %s.%s: only a call of Load reads the snapshot (03-08i)", statusExprString(sel), method.Sel.Name)
		return
	}
	switch {
	case method.Sel.Name == "Load":
	case method.Sel.Name == "Store" && fn == "publishStatusLocked":
		*ctx.stores++
	default:
		report(file, fn, sel.Pos(), "%s.%s: only publishStatusLocked stores the snapshot, and everything else only loads it (03-08i)", statusExprString(sel), method.Sel.Name)
	}
}

// statusCheckSignerLit applies the composite-literal rule to a Signer
// literal: caKeys, bundleVersion, bundleRow and statusDB may be set only
// in New, and directoryState and status never.
func statusCheckSignerLit(lit *ast.CompositeLit, file, fn string, report func(string, string, token.Pos, string, ...any)) {
	id, ok := lit.Type.(*ast.Ident)
	if !ok || id.Name != "Signer" {
		return
	}
	for _, elt := range lit.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			report(file, fn, elt.Pos(), "an unkeyed Signer literal (03-08i)")
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		switch key.Name {
		case "directoryState", "status":
			report(file, fn, kv.Pos(), "a Signer literal sets %s: the directory state and the snapshot are set only through setDirectoryLocked (03-08i)", key.Name)
		case "caKeys", "bundleVersion", "bundleRow", "statusDB":
			if fn != "New" {
				report(file, fn, kv.Pos(), "a Signer literal outside New sets %s: only New sets the trust state Status reports (03-08i)", key.Name)
			}
		}
	}
}

// statusCheckPlacement requires the setter call in fd to be a top-level
// statement of its body: in InstallDirectory after the `err = s.logTx(`
// assignment and the `if err != nil` block that follows it (the publish
// after COMMIT), in loadDirectory after `ds, err := s.readDirectory(`.
func statusCheckPlacement(fd *ast.FuncDecl, file string, report func(string, string, token.Pos, string, ...any), install bool) {
	fn := fd.Name.Name
	anchor, after := -1, -1
	for i, st := range fd.Body.List {
		as, ok := st.(*ast.AssignStmt)
		if !ok || len(as.Rhs) != 1 {
			continue
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok {
			continue
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			continue
		}
		if install && sel.Sel.Name == "logTx" && as.Tok == token.ASSIGN {
			anchor = i
			if i+1 < len(fd.Body.List) {
				if is, ok := fd.Body.List[i+1].(*ast.IfStmt); ok && statusIsErrNotNil(is.Cond) {
					after = i + 1
				}
			}
		}
		if !install && sel.Sel.Name == "readDirectory" && as.Tok == token.DEFINE {
			anchor, after = i, i
		}
	}
	if anchor < 0 || after < 0 {
		report(file, fn, fd.Pos(), "no %s found as a top-level statement: the publish after COMMIT cannot be checked (03-08i)",
			map[bool]string{true: "`err = s.logTx(` followed by `if err != nil`", false: "`ds, err := s.readDirectory(`"}[install])
		return
	}
	top := -1
	for i, st := range fd.Body.List {
		es, ok := st.(*ast.ExprStmt)
		if !ok {
			continue
		}
		if call, ok := es.X.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "setDirectoryLocked" {
				top = i
			}
		}
	}
	if top < 0 {
		report(file, fn, fd.Pos(), "setDirectoryLocked is not called as a top-level statement of the function body (inside no closure or block) (03-08i)")
		return
	}
	if top <= after {
		report(file, fn, fd.Body.List[top].Pos(), "setDirectoryLocked comes before the transaction's result is handled: the snapshot is published only after COMMIT (03-08i)")
	}
}

// statusIsErrNotNil reports whether cond is `err != nil`.
func statusIsErrNotNil(cond ast.Expr) bool {
	be, ok := cond.(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ {
		return false
	}
	l, lok := be.X.(*ast.Ident)
	r, rok := be.Y.(*ast.Ident)
	return lok && rok && l.Name == "err" && r.Name == "nil"
}
