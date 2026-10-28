package paths

import (
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// agentDirs are the applier's packages, relative to the module root.
var agentDirs = []string{"internal/agent/apply", "internal/agent/state", "internal/agent/spool", "internal/agent/execsite", "cmd/keyroster-agent"}

// execsiteDir is the one package that may import os/exec.
const execsiteDir = "internal/agent/execsite"

// execsitePath is its import path.
const execsitePath = "github.com/Labontese/keyroster/internal/agent/execsite"

func moduleRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	return filepath.Dir(strings.TrimSpace(string(out)))
}

// parsed is one non-test source file of the applier.
type parsed struct {
	path string
	file *ast.File
}

func parseAgent(t *testing.T, root string) ([]parsed, *token.FileSet) {
	t.Helper()
	fset := token.NewFileSet()
	var out []parsed
	for _, d := range agentDirs {
		entries, err := os.ReadDir(filepath.Join(root, d))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			p := filepath.Join(root, d, e.Name())
			f, err := parser.ParseFile(fset, p, nil, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, parsed{path: filepath.ToSlash(filepath.Join(d, e.Name())), file: f})
		}
	}
	return out, fset
}

func render(fset *token.FileSet, n ast.Node) string {
	var b bytes.Buffer
	_ = printer.Fprint(&b, fset, n)
	return b.String()
}

// callName is the printed callee of a call: "exec.CommandContext",
// "e.replaceLink", "os.Rename".
func callName(fset *token.FileSet, c *ast.CallExpr) string { return render(fset, c.Fun) }

// eachCall walks every call in every function declaration.
func eachCall(files []parsed, fn func(p parsed, decl *ast.FuncDecl, c *ast.CallExpr)) {
	for _, p := range files {
		for _, d := range p.file.Decls {
			decl, ok := d.(*ast.FuncDecl)
			if !ok || decl.Body == nil {
				continue
			}
			ast.Inspect(decl.Body, func(n ast.Node) bool {
				if c, ok := n.(*ast.CallExpr); ok {
					fn(p, decl, c)
				}
				return true
			})
		}
	}
}

// writeCalls are the calls that write the file system. unix.Openat counts
// when its flags name O_WRONLY, O_RDWR or O_CREAT.
var writeCalls = []string{
	"os.WriteFile", "os.Create", "os.OpenFile", "os.Rename", "os.Symlink", "os.Remove", "os.RemoveAll",
	"os.Mkdir", "os.MkdirAll", "os.Chmod", "os.Chown", "os.Link", "os.Truncate",
	"unix.Renameat", "unix.Renameat2", "unix.Unlinkat", "unix.Mkdirat", "unix.Symlinkat", "unix.Linkat", "unix.Fchmodat",
	"spool.WriteFileAt", "spool.Write",
}

func isWrite(fset *token.FileSet, c *ast.CallExpr) bool {
	name := callName(fset, c)
	if slices.Contains(writeCalls, name) {
		return true
	}
	if name == "unix.Openat" && len(c.Args) >= 3 {
		flags := render(fset, c.Args[2])
		return strings.Contains(flags, "O_WRONLY") || strings.Contains(flags, "O_RDWR") || strings.Contains(flags, "O_CREAT")
	}
	return false
}

func callsAllowed(fset *token.FileSet, decl *ast.FuncDecl) bool {
	return callsFunc(fset, decl, "paths.Allowed")
}

// removeCalls are the writes that only remove; AllowedRemoval may guard
// them (03-06, D-08: the Phase 2 layout is removed, never written).
var removeCalls = []string{"os.Remove", "os.RemoveAll", "unix.Unlinkat"}

func callsFunc(fset *token.FileSet, decl *ast.FuncDecl, fn string) bool {
	found := false
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if name := callName(fset, c); name == fn {
				found = true
			}
		}
		return true
	})
	return found
}

// TestPaths confines the root applier (D-05, D-07, T-03-30, T-03-31):
// (1) its dependency graph holds no HTTP, TLS or RPC; (2) it runs
// programs only at the exec sites ExecSites lists, each an
// internal/agent/execsite constructor with its fixed binary and flags
// called from its one function in sshd.go (a constructor used as a value
// or outside a function is refused, and no package of the module but
// internal/agent/apply imports execsite), and nothing outside execsite
// names os/exec or a program-starting call; (3) every write is preceded by
// Allowed in the same function; (4) no function that writes names
// sshd_config, authorized_keys, PasswordAuthentication,
// AuthorizedKeysFile, Port or ListenAddress; (5) only swapCurrent in
// swap.go renames or symlinks over current.
func TestPaths(t *testing.T) {
	root := moduleRoot(t)
	files, fset := parseAgent(t, root)

	t.Run("deps_no_http_tls_rpc", func(t *testing.T) {
		cmd := exec.Command("go", "list", "-deps", "./cmd/keyroster-agent")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS=linux", "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list -deps: %v", err)
		}
		for _, pkg := range strings.Fields(string(out)) {
			for _, banned := range []string{"net/http", "crypto/tls", "net/rpc"} {
				if pkg == banned || strings.HasPrefix(pkg, banned+"/") {
					t.Errorf("keyroster-agent depends on %s", pkg)
				}
			}
		}
	})

	t.Run("exec_only_in_execsite", func(t *testing.T) {
		// PR #67 review: os/exec under any name (an alias, a dot or blank
		// import) and the program-starting calls of os, syscall and
		// x/sys/unix are refused outside execsite's ExecRunner.Run,
		// whatever the spelling; so are cgo and plugin.
		forbidden := map[string][]string{
			"os":                    {"StartProcess"},
			"syscall":               {"Exec", "ForkExec", "StartProcess"},
			"golang.org/x/sys/unix": {"Exec"},
		}
		for _, p := range files {
			names := importNames(p.file)
			inExecsite := strings.HasPrefix(p.path, execsiteDir+"/")
			for path, name := range names {
				where := p.path + ": import " + strconv.Quote(path)
				switch {
				case path == "C" || path == "plugin":
					t.Errorf("%s: not allowed in the agent", where)
				case path == "os/exec" && !inExecsite:
					t.Errorf("%s outside %s", where, execsiteDir)
				case path == "os/exec" && (name == "." || name == "_"):
					t.Errorf("%s as %q", where, name)
				}
			}
			ast.Inspect(p.file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				x, ok := sel.X.(*ast.Ident)
				if !ok {
					return true
				}
				for path, name := range names {
					if x.Name != name {
						continue
					}
					line := fset.Position(sel.Pos()).Line
					if path == "os/exec" && !inMethod(p.file, sel.Pos(), "ExecRunner", "Run") {
						t.Errorf("%s:%d: %s.%s outside execsite's ExecRunner.Run", p.path, line, name, sel.Sel.Name)
					}
					if slices.Contains(forbidden[path], sel.Sel.Name) {
						t.Errorf("%s:%d: %s.%s starts a program outside execsite's ExecRunner.Run", p.path, line, path, sel.Sel.Name)
					}
				}
				return true
			})
		}
	})

	t.Run("exec_sites_pinned", func(t *testing.T) {
		sites := map[string]ExecSite{}
		for _, s := range ExecSites {
			sites[s.Ctor] = s
		}
		// The constructors: every function of execsite that makes a Cmd
		// is listed, and returns exactly Cmd{path: bin, args: []string{bin,
		// <Args>}}.
		ctors := map[string]bool{}
		for _, p := range files {
			if !strings.HasPrefix(p.path, execsiteDir+"/") {
				continue
			}
			for _, d := range p.file.Decls {
				decl, ok := d.(*ast.FuncDecl)
				if !ok || decl.Body == nil {
					continue
				}
				makesCmd := false
				ast.Inspect(decl.Body, func(n ast.Node) bool {
					if cl, ok := n.(*ast.CompositeLit); ok && render(fset, cl.Type) == "Cmd" {
						makesCmd = true
					}
					return true
				})
				if !makesCmd {
					continue
				}
				site, listed := sites[decl.Name.Name]
				if !listed || decl.Recv != nil {
					t.Errorf("%s: %s makes an execsite.Cmd and is not a constructor in paths.ExecSites", p.path, decl.Name.Name)
					continue
				}
				ctors[decl.Name.Name] = true
				if err := checkCtor(fset, decl, site.Args); err != nil {
					t.Errorf("%s: %s: %v", p.path, decl.Name.Name, err)
				}
			}
		}
		for c := range sites {
			if !ctors[c] {
				t.Errorf("paths.ExecSites names constructor %s, which execsite does not define", c)
			}
		}
		// The callers: every call of a constructor is a listed site, from
		// its function, with its arguments as written.
		found := map[ExecSite]bool{}
		for _, p := range files {
			if strings.HasPrefix(p.path, execsiteDir+"/") {
				continue
			}
			pkg, ok := importNames(p.file)[execsitePath]
			if !ok {
				continue
			}
			if pkg == "." {
				t.Errorf("%s: dot import of %s: its constructors would escape this check", p.path, execsitePath)
				continue
			}
			// PR #67 fix round 2: a constructor taken as a value (f :=
			// execsite.KeygenFingerprint), or called outside a function
			// declaration (a package-level var), is never a pinned call.
			// Every selector of a constructor must be the callee of a call
			// matched below.
			pinned := map[token.Pos]bool{}
			eachCall([]parsed{p}, func(p parsed, decl *ast.FuncDecl, c *ast.CallExpr) {
				sel, ok := c.Fun.(*ast.SelectorExpr)
				if !ok {
					return
				}
				if x, ok := sel.X.(*ast.Ident); !ok || x.Name != pkg || !ctors[sel.Sel.Name] {
					return
				}
				pinned[sel.Pos()] = true // matched below, or reported
				var args []string
				for _, a := range c.Args {
					args = append(args, render(fset, a))
				}
				got := ExecSite{Func: decl.Name.Name, Ctor: sel.Sel.Name, Call: strings.Join(args, " "), Args: sites[sel.Sel.Name].Args}
				if got != sites[got.Ctor] {
					t.Errorf("%s:%d: execsite.%s(%s) in %s is not in paths.ExecSites", p.path, fset.Position(c.Pos()).Line, got.Ctor, got.Call, got.Func)
					return
				}
				found[got] = true
			})
			ast.Inspect(p.file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if x, ok := sel.X.(*ast.Ident); ok && x.Name == pkg && ctors[sel.Sel.Name] && !pinned[sel.Pos()] {
					t.Errorf("%s:%d: execsite.%s is used other than as the callee of a call in paths.ExecSites", p.path, fset.Position(sel.Pos()).Line, sel.Sel.Name)
				}
				return true
			})
		}
		for _, s := range ExecSites {
			if !found[s] {
				t.Errorf("paths.ExecSites lists %+v, which no code runs", s)
			}
		}
	})

	t.Run("execsite_imported_only_by_apply", func(t *testing.T) {
		// PR #67 fix round 2: a package outside agentDirs is never parsed
		// above, so a helper there could call a constructor with another
		// binary. No package of the module but internal/agent/apply, the
		// pinned callers', imports execsite outside its tests.
		cmd := exec.Command("go", "list", "-e", "-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", "./...")
		cmd.Dir = root
		cmd.Env = append(os.Environ(), "GOOS=linux", "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list: %v", err)
		}
		module := strings.TrimSuffix(execsitePath, "/"+execsiteDir)
		allowed := []string{module + "/internal/agent/apply", execsitePath}
		seen := 0
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			f := strings.Fields(line)
			if len(f) == 0 {
				continue
			}
			seen++
			if slices.Contains(f[1:], execsitePath) && !slices.Contains(allowed, f[0]) {
				t.Errorf("%s imports %s; only internal/agent/apply may", f[0], execsitePath)
			}
		}
		if seen < 10 {
			t.Fatalf("go list listed %d packages", seen)
		}
	})

	t.Run("writes_through_allowed", func(t *testing.T) {
		eachCall(files, func(p parsed, decl *ast.FuncDecl, c *ast.CallExpr) {
			if !isWrite(fset, c) {
				return
			}
			name := callName(fset, c)
			where := p.path + ":" + strconv.Itoa(fset.Position(c.Pos()).Line)
			if p.path == "internal/agent/spool/spool.go" {
				// The spool's own primitives: WriteFileAt creates, renames
				// and unlinks relative to a descriptor its caller opened
				// after Allowed, and Write is the fetcher's writer.
				if decl.Name.Name == "WriteFileAt" || decl.Name.Name == "Write" {
					return
				}
			}
			if name == "spool.Write" {
				t.Errorf("%s: the applier calls spool.Write, the fetcher's writer", where)
			}
			if slices.Contains(removeCalls, name) && callsFunc(fset, decl, "paths.AllowedRemoval") {
				return // a removal, guarded by the removal-only allowlist
			}
			if !callsAllowed(fset, decl) {
				t.Errorf("%s: %s in %s without paths.Allowed in the same function", where, name, decl.Name.Name)
			}
		})
	})

	t.Run("no_sshd_config_in_write_paths", func(t *testing.T) {
		forbidden := []string{`sshd_config"`, "authorized_keys", "PasswordAuthentication", "AuthorizedKeysFile", "Port ", "ListenAddress"}
		for _, p := range files {
			for _, d := range p.file.Decls {
				decl, ok := d.(*ast.FuncDecl)
				if !ok || decl.Body == nil {
					continue
				}
				writes := false
				ast.Inspect(decl.Body, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok && isWrite(fset, c) {
						writes = true
					}
					return true
				})
				if !writes {
					continue
				}
				ast.Inspect(decl.Body, func(n ast.Node) bool {
					lit, ok := n.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					for _, f := range forbidden {
						if strings.Contains(lit.Value, f) {
							t.Errorf("%s:%d: %s, which writes, names %q", p.path, fset.Position(lit.Pos()).Line, decl.Name.Name, f)
						}
					}
					return true
				})
			}
		}
	})

	t.Run("current_renamed_only_in_swapCurrent", func(t *testing.T) {
		renames := []string{"os.Rename", "os.Symlink", "unix.Renameat", "unix.Renameat2", "unix.Symlinkat", "e.replaceLink", "replaceLink", "e.renameDir"}
		eachCall(files, func(p parsed, decl *ast.FuncDecl, c *ast.CallExpr) {
			if !slices.Contains(renames, callName(fset, c)) {
				return
			}
			names := false
			for _, a := range c.Args {
				s := render(fset, a)
				if strings.Contains(s, ".Current()") || strings.Contains(s, `"current"`) {
					names = true
				}
			}
			if names && (p.path != "internal/agent/apply/swap.go" || decl.Name.Name != "swapCurrent") {
				t.Errorf("%s:%d: %s moves current outside swap.go's swapCurrent", p.path, fset.Position(c.Pos()).Line, decl.Name.Name)
			}
		})
	})
}

// TestAllowed checks the allowlist itself: exactly the keyroster tree,
// the drop-in file and the state directory.
func TestAllowed(t *testing.T) {
	l := Layout{Root: "/r", StateDir: "/var/lib/keyroster-agent"}
	for _, p := range []string{"/r/etc/ssh/keyroster", "/r/etc/ssh/keyroster/gen/3/user_ca_keys", "/r/etc/ssh/keyroster/current",
		"/r/etc/ssh/sshd_config.d/00-keyroster.conf", "/var/lib/keyroster-agent", "/var/lib/keyroster-agent/pins.json",
		// 03-07: install's four paths outside the state directory, exactly.
		"/r/etc/keyroster-agent", "/r/etc/keyroster-agent/fetch.json", "/r/var/lib/keyroster-agent-fetch", "/r/var/lib/keyroster-agent-fetch/join-token",
		// 03-08: the two systemd units and the two OpenRC scripts, exactly.
		"/r/etc/systemd/system/keyroster-agent.service", "/r/etc/systemd/system/keyroster-agent-fetch.service",
		"/r/etc/init.d/keyroster-agent", "/r/etc/init.d/keyroster-agent-fetch"} {
		if err := Allowed(l, p); err != nil {
			t.Errorf("Allowed(%s) = %v", p, err)
		}
	}
	if got := l.ServiceFiles(); len(got) != 4 {
		t.Errorf("ServiceFiles = %q, want exactly four paths", got)
	}
	for _, p := range []string{"/r/etc/systemd/system", "/r/etc/systemd/system/ssh.service", "/r/etc/systemd/system/keyroster-agent.service.d/x.conf",
		"/r/etc/init.d", "/r/etc/init.d/sshd", "/r/etc/init.d/keyroster-agent.bak", "/r/etc/systemd/system/keyroster-signer.service"} {
		if err := Allowed(l, p); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Allowed(%s) = %v, want path_not_allowed", p, err)
		}
	}
	for _, p := range []string{"/r/etc/ssh/sshd_config", "/r/etc/ssh/sshd_config.d/50-other.conf", "/r/etc/ssh/sshd_config.d",
		"/r/root/.ssh/authorized_keys", "/r/etc/ssh/keyroster-evil", "/var/lib/keyroster-agent-x/a", "/r/etc/ssh/keyroster/../sshd_config", "relative/path",
		"/r/etc/keyroster-agent/other.json", "/r/etc/keyroster-agent/fetch.json/x", "/r/var/lib/keyroster-agent-fetch/identity", "/r/var/lib/keyroster-agent-fetch/join-token.tmp",
		"/r/var/lib", "/r/etc"} {
		if err := Allowed(l, p); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Allowed(%s) = %v, want path_not_allowed", p, err)
		}
	}
	// 03-06 (D-08): the Phase 2 layout's three paths are removable once,
	// never writable.
	phase2 := []string{"/r/etc/ssh/sshd_config.d/50-keyroster.conf", "/r/etc/ssh/keyroster_user_ca.pub", "/r/etc/ssh/principals", "/r/etc/ssh/principals/deploy"}
	for _, p := range phase2 {
		if err := Allowed(l, p); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Allowed(%s) = %v, want path_not_allowed: the Phase 2 layout is never written", p, err)
		}
		if err := AllowedRemoval(l, p); err != nil {
			t.Errorf("AllowedRemoval(%s) = %v", p, err)
		}
	}
	for _, p := range []string{"/r/etc/ssh/keyroster/gen/3", "/var/lib/keyroster-agent/pins.json"} {
		if err := AllowedRemoval(l, p); err != nil {
			t.Errorf("AllowedRemoval(%s) = %v (everything Allowed may be removed)", p, err)
		}
	}
	for _, p := range []string{"/r/etc/ssh/sshd_config", "/r/etc/ssh/sshd_config.d/50-other.conf", "/r/etc/ssh/principals/a/b",
		"/r/etc/ssh/principals/../sshd_config", "/r/etc/ssh/keyroster_user_ca.pub.bak", "/r/etc/ssh", "relative/principals"} {
		if err := AllowedRemoval(l, p); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("AllowedRemoval(%s) = %v, want path_not_allowed", p, err)
		}
	}
}

// importNames maps each import path of f to the name it is used by.
func importNames(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, im := range f.Imports {
		path, _ := strconv.Unquote(im.Path.Value)
		name := path[strings.LastIndex(path, "/")+1:]
		if im.Name != nil {
			name = im.Name.Name
		}
		out[path] = name
	}
	return out
}

// inMethod reports whether pos lies in the method recv.name of f.
func inMethod(f *ast.File, pos token.Pos, recv, name string) bool {
	for _, d := range f.Decls {
		decl, ok := d.(*ast.FuncDecl)
		if !ok || decl.Recv == nil || len(decl.Recv.List) != 1 || decl.Name.Name != name {
			continue
		}
		if id, ok := decl.Recv.List[0].Type.(*ast.Ident); ok && id.Name == recv && decl.Pos() <= pos && pos < decl.End() {
			return true
		}
	}
	return false
}

// isParamWord reports whether w, a word of ExecSite.Args, stands for a
// constructor parameter (upper case) rather than a literal flag.
func isParamWord(w string) bool { return strings.Trim(w, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" }

// checkCtor checks that an execsite constructor's body is exactly
// return Cmd{path: p0, args: []string{p0, <args>}}: p0 its first
// parameter, each literal flag of args a string literal, each upper-case
// word one of its parameters, and every parameter used.
func checkCtor(fset *token.FileSet, decl *ast.FuncDecl, args string) error {
	var params []string
	for _, f := range decl.Type.Params.List {
		for _, n := range f.Names {
			params = append(params, n.Name)
		}
	}
	if len(params) == 0 || len(decl.Body.List) != 1 {
		return errors.New("not a single return of a Cmd literal over its parameters")
	}
	ret, ok := decl.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return errors.New("not a single return statement")
	}
	cl, ok := ret.Results[0].(*ast.CompositeLit)
	if !ok || render(fset, cl.Type) != "Cmd" || len(cl.Elts) != 2 {
		return errors.New("does not return Cmd{path: ..., args: ...}")
	}
	fields := map[string]ast.Expr{}
	for _, e := range cl.Elts {
		kv, ok := e.(*ast.KeyValueExpr)
		if !ok {
			return errors.New("an unkeyed Cmd literal")
		}
		fields[render(fset, kv.Key)] = kv.Value
	}
	if fields["path"] == nil || render(fset, fields["path"]) != params[0] {
		return fmt.Errorf("path is not its first parameter %s", params[0])
	}
	argv, ok := fields["args"].(*ast.CompositeLit)
	if !ok || render(fset, argv.Type) != "[]string" {
		return errors.New("args is not a []string literal")
	}
	want := append([]string{"BIN"}, strings.Fields(args)...)
	if len(argv.Elts) != len(want) {
		return fmt.Errorf("argv has %d words, paths.ExecSites says %d", len(argv.Elts), len(want))
	}
	used := map[string]bool{}
	for i, e := range argv.Elts {
		w := want[i]
		if lit, ok := e.(*ast.BasicLit); ok && lit.Kind == token.STRING {
			v, _ := strconv.Unquote(lit.Value)
			if isParamWord(w) || v != w {
				return fmt.Errorf("argv word %d is the literal %q, want %s", i, v, w)
			}
			continue
		}
		id, ok := e.(*ast.Ident)
		if !ok || !isParamWord(w) || !slices.Contains(params, id.Name) || i == 0 && id.Name != params[0] {
			return fmt.Errorf("argv word %d is %s, want %s", i, render(fset, e), w)
		}
		used[id.Name] = true
	}
	for _, p := range params {
		if !used[p] {
			return fmt.Errorf("parameter %s is not in argv", p)
		}
	}
	return nil
}
