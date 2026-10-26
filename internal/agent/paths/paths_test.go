package paths

import (
	"bytes"
	"errors"
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
var agentDirs = []string{"internal/agent/apply", "internal/agent/state", "internal/agent/spool", "cmd/keyroster-agent"}

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
	found := false
	ast.Inspect(decl.Body, func(n ast.Node) bool {
		if c, ok := n.(*ast.CallExpr); ok {
			if name := callName(fset, c); name == "paths.Allowed" {
				found = true
			}
		}
		return true
	})
	return found
}

// TestPaths confines the root applier (D-05, D-07, T-03-30, T-03-31):
// (1) its dependency graph holds no HTTP, TLS or RPC; (2) it runs
// programs only at the exec sites ExecSites lists, all in sshd.go, each
// with its fixed binary and flags; (3) every write is preceded by
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

	t.Run("exec_sites_pinned", func(t *testing.T) {
		found := map[ExecSite]bool{}
		eachCall(files, func(p parsed, decl *ast.FuncDecl, c *ast.CallExpr) {
			name := callName(fset, c)
			if name != "exec.Command" && name != "exec.CommandContext" {
				return
			}
			where := p.path + ":" + strconv.Itoa(fset.Position(c.Pos()).Line)
			if p.path != "internal/agent/apply/sshd.go" {
				t.Errorf("%s: %s outside internal/agent/apply/sshd.go", where, name)
				return
			}
			args := c.Args
			if name == "exec.CommandContext" {
				args = args[1:]
			}
			if len(args) == 0 {
				t.Errorf("%s: no binary", where)
				return
			}
			var shape []string
			for _, a := range args[1:] {
				if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					s, _ := strconv.Unquote(lit.Value)
					shape = append(shape, s)
					continue
				}
				shape = append(shape, render(fset, a))
			}
			site := ExecSite{Func: decl.Name.Name, Bin: render(fset, args[0])}
			ok := false
			for _, s := range ExecSites {
				if s.Func != site.Func || s.Bin != site.Bin {
					continue
				}
				want := strings.Fields(s.Args)
				if len(want) != len(shape) {
					continue
				}
				match := true
				for i, w := range want {
					// An upper-case word stands for a value the applier
					// fills in; it must not be a string literal.
					if strings.Trim(w, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") == "" {
						if lit, isLit := args[i+1].(*ast.BasicLit); isLit && lit.Kind == token.STRING {
							match = false
						}
						continue
					}
					if w != shape[i] {
						match = false
					}
				}
				if match {
					ok, found[s] = true, true
				}
			}
			if !ok {
				t.Errorf("%s: %s(%s %s) in %s is not in paths.ExecSites", where, name, site.Bin, strings.Join(shape, " "), site.Func)
			}
		})
		for _, s := range ExecSites {
			if !found[s] {
				t.Errorf("paths.ExecSites lists %+v, which no code runs", s)
			}
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
		"/r/etc/ssh/sshd_config.d/00-keyroster.conf", "/var/lib/keyroster-agent", "/var/lib/keyroster-agent/pins.json"} {
		if err := Allowed(l, p); err != nil {
			t.Errorf("Allowed(%s) = %v", p, err)
		}
	}
	for _, p := range []string{"/r/etc/ssh/sshd_config", "/r/etc/ssh/sshd_config.d/50-other.conf", "/r/etc/ssh/sshd_config.d",
		"/r/root/.ssh/authorized_keys", "/r/etc/ssh/keyroster-evil", "/var/lib/keyroster-agent-x/a", "/r/etc/ssh/keyroster/../sshd_config", "relative/path"} {
		if err := Allowed(l, p); !errors.Is(err, ErrNotAllowed) {
			t.Errorf("Allowed(%s) = %v, want path_not_allowed", p, err)
		}
	}
}
