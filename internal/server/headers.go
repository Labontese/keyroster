package server

import "net/http"

// contentSecurityPolicy is STACK.md's "Web UI" policy plus connect-src
// 'self', which the page's own fetch() needs (RESEARCH Pitfall 3).
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; " +
	"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

// securityHeaders are set on every response, errors and static files
// included.
var securityHeaders = [][2]string{
	{"Content-Security-Policy", contentSecurityPolicy},
	{"Strict-Transport-Security", "max-age=63072000"},
	{"Cross-Origin-Opener-Policy", "same-origin"},
	{"X-Content-Type-Options", "nosniff"},
	{"Referrer-Policy", "no-referrer"},
	{"Cache-Control", "no-store"},
}

// secure sets securityHeaders and then passes every request through
// http.CrossOriginProtection, which refuses a cross-origin unsafe-method
// request with 403. The headers are set outside the protection, so its 403
// carries them too.
func secure(h http.Handler) http.Handler {
	protected := http.NewCrossOriginProtection().Handler(h)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hd := w.Header()
		for _, kv := range securityHeaders {
			hd.Set(kv[0], kv[1])
		}
		protected.ServeHTTP(w, r)
	})
}
