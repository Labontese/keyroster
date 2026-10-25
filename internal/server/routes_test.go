package server

import (
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// passkeyRoutes are the only registered patterns whose text names a way
// to sign in or to hold a session, each with the reason it is a step of a
// passkey ceremony (03-02, the 02-10 prohibition: no password, TOTP,
// recovery-code or magic-link sign-in). Adding a route that matches one
// of signInKeywords, or removing one of these, fails
// TestNoNonPasskeySignInRoute until this list is changed on purpose.
var passkeyRoutes = map[string]string{
	"GET /login":                        "the web sign-in page; it only starts the browser's passkey ceremony",
	"GET /login/{id}":                   "the keyroster login approval page; it shows the request and asks for a passkey assertion over it",
	"GET /api/v1/login/options":         "what the CLI may request (roles, principals, TTL caps); it signs nobody in",
	"POST /api/v1/login/begin":          "stores the CLI's request with PKCE; it signs nobody in",
	"POST /api/v1/login/{id}/assertion": "the only route that creates a login code, after a passkey assertion over the stored request",
	"POST /api/v1/login/{id}/redeem":    "the only route that obtains a login certificate, for that code and its PKCE verifier",
	"POST /api/v1/web/login/begin":      "the web sign-in challenge (allowCredentials from the directory); it signs nobody in",
	"POST /api/v1/web/login/finish":     "the only route that creates a session, after a passkey assertion",
}

// signInKeywords mark a pattern as a sign-in or session route.
var signInKeywords = []string{"login", "signin", "sign-in", "session", "password", "totp", "otp", "recovery", "magic"}

// TestNoNonPasskeySignInRoute: the server registers no sign-in or session
// route but the passkey ceremony's (02-10 prohibition, 03-02). It reads the
// patterns New's routeMux recorded while registering them, so the list
// and the mux cannot differ, and checks that no other mux exists.
func TestNoNonPasskeySignInRoute(t *testing.T) {
	e := newSignInEnv(t, highSignInLimits)
	patterns := e.s.patterns
	if !slices.Contains(patterns, "GET /healthz") || !slices.Contains(patterns, "POST /api/v1/login/{id}/redeem") {
		t.Fatalf("the recorded patterns miss routes New registers: %q", patterns)
	}
	t.Run("keyword_route_not_allowlisted", func(t *testing.T) {
		for _, p := range patterns {
			lower := strings.ToLower(p)
			for _, k := range signInKeywords {
				if strings.Contains(lower, k) {
					if _, ok := passkeyRoutes[p]; !ok {
						t.Errorf("route %q contains %q and is not a passkey ceremony step in passkeyRoutes", p, k)
					}
					break
				}
			}
		}
	})
	t.Run("allowlist_entry_not_registered", func(t *testing.T) {
		for p := range passkeyRoutes {
			if !slices.Contains(patterns, p) {
				t.Errorf("passkeyRoutes lists %q, which the server does not register; remove the stale entry", p)
			}
		}
	})
	t.Run("single_mux", func(t *testing.T) {
		requireOnlyRouteMux(t)
	})
	t.Run("probes", func(t *testing.T) {
		type probe struct {
			method, target, body string
			hdr                  map[string]string
		}
		var probes []probe
		for _, p := range []string{"/login/password", "/totp", "/recovery", "/magic"} {
			probes = append(probes, probe{method: http.MethodGet, target: p}, probe{method: http.MethodPost, target: p})
		}
		probes = append(probes, probe{method: http.MethodPost, target: "/login", body: "user=alice&password=x",
			hdr: map[string]string{"Content-Type": "application/x-www-form-urlencoded"}})
		for _, p := range probes {
			rec := e.request(p.method, p.target, p.body, "", "", p.hdr)
			if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
				t.Errorf("%s %s = %d, want 404 or 405", p.method, p.target, rec.Code)
			}
			if c := rec.Header().Values("Set-Cookie"); len(c) != 0 {
				t.Errorf("%s %s set a cookie: %q", p.method, p.target, c)
			}
		}
	})
}

// requireOnlyRouteMux fails when a non-test Go file of this package builds
// an http.ServeMux anywhere but in newRouteMux: a call or reference to
// http.NewServeMux, an http.ServeMux literal or new(http.ServeMux). A mux
// built that way would register routes no recorded list shows. It also
// requires newRouteMux itself to call http.NewServeMux exactly once, so
// the scan is known to see the call it allows.
func requireOnlyRouteMux(t *testing.T) {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	inRouteMux := 0
	scanned := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name) //nolint:gosec // G304: this package's own source files
		if err != nil {
			t.Fatal(err)
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, src, 0)
		if err != nil {
			t.Fatal(err)
		}
		scanned++
		httpName := ""
		for _, imp := range f.Imports {
			if path, _ := strconv.Unquote(imp.Path.Value); path == "net/http" {
				httpName = "http"
				if imp.Name != nil {
					httpName = imp.Name.Name
				}
			}
		}
		if httpName == "" {
			continue
		}
		isHTTP := func(x ast.Expr, sel string) bool {
			s, ok := x.(*ast.SelectorExpr)
			if !ok || s.Sel.Name != sel {
				return false
			}
			id, ok := s.X.(*ast.Ident)
			return ok && id.Name == httpName
		}
		for _, decl := range f.Decls {
			owner := ""
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Recv == nil {
				owner = fd.Name.Name
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.SelectorExpr:
					if isHTTP(n, "NewServeMux") {
						if owner == "newRouteMux" {
							inRouteMux++
						} else {
							t.Errorf("%s: http.NewServeMux outside newRouteMux; build every mux with newRouteMux", fset.Position(n.Pos()))
						}
					}
				case *ast.CompositeLit:
					if isHTTP(n.Type, "ServeMux") {
						t.Errorf("%s: an http.ServeMux literal; build every mux with newRouteMux", fset.Position(n.Pos()))
					}
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "new" && len(n.Args) == 1 && isHTTP(n.Args[0], "ServeMux") {
						t.Errorf("%s: new(http.ServeMux); build every mux with newRouteMux", fset.Position(n.Pos()))
					}
				}
				return true
			})
		}
	}
	if scanned == 0 || inRouteMux != 1 {
		t.Fatalf("scanned %d source files and found %d http.NewServeMux calls in newRouteMux, want files and exactly 1", scanned, inRouteMux)
	}
}
