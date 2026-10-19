package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"

	"github.com/Labontese/keyroster/internal/custodytext"
	"github.com/Labontese/keyroster/internal/server/web"
	"github.com/Labontese/keyroster/internal/serverclient"
	"github.com/Labontese/keyroster/internal/wire"
)

// pageNames are the pages under templates/; each is parsed together with
// base.html into its own template set.
var pageNames = []string{"index", "error"}

// parsePages parses every page once from the embedded templates.
func parsePages() (map[string]*template.Template, error) {
	out := map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := template.New(name).ParseFS(web.FS, "templates/base.html", "templates/"+name+".html")
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		out[name] = t
	}
	return out, nil
}

// pageData is what every page template sees. Banner is the custody
// warning (empty when no key is in software custody); the other fields
// are set by the page that uses them.
type pageData struct {
	Title   string
	Banner  string
	Message string

	RPID             string
	BundleVersion    uint64
	PolicyVersion    uint64
	DirectoryVersion uint64
	Keys             []wire.KeyStatus
}

// statusPage fills the banner from v: the owner-approved evaluation-only
// text whenever the signer reports software custody for any key (KEY-06).
func statusPage(v *statusView, title string) pageData {
	d := pageData{Title: title}
	if len(v.softwareRoles) > 0 {
		d.Banner = custodytext.SoftwareCABanner(v.softwareRoles)
	}
	return d
}

// renderPage renders a page built from the current status v: it sets the
// custody header, renders into a buffer (a template error never sends a
// partial page) and writes it with code.
func (s *Server) renderPage(w http.ResponseWriter, v *statusView, code int, name string, data pageData) {
	var buf bytes.Buffer
	if err := s.pages[name].ExecuteTemplate(&buf, "base", data); err != nil {
		s.log.Error("render page", "page", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if v != nil {
		w.Header().Set(serverclient.CustodyHeader, v.custody)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	_, _ = w.Write(buf.Bytes())
}

// writeJSON writes body as JSON with code; v, when not nil, is the status
// the body was built from and sets the custody header.
func (s *Server) writeJSON(w http.ResponseWriter, v *statusView, code int, body any) {
	data, err := json.Marshal(body)
	if err != nil {
		s.log.Error("encode JSON", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if v != nil {
		w.Header().Set(serverclient.CustodyHeader, v.custody)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_, _ = w.Write(append(data, '\n'))
}

// signerUnavailable answers a request whose status refresh failed: 503
// with no RP, policy, custody or directory data and no custody header.
// HTML routes get error.html, the others JSON.
func (s *Server) signerUnavailable(w http.ResponseWriter, html bool) {
	if html {
		s.renderPage(w, nil, http.StatusServiceUnavailable, "error", pageData{
			Title:   "Signer unavailable",
			Message: "This keyroster server cannot reach its signer right now. Try again in a moment.",
		})
		return
	}
	s.writeJSON(w, nil, http.StatusServiceUnavailable, serverclient.APIError{Error: "signer unavailable"})
}

// staticTypes gives the Content-Type of each embedded static file by
// extension. A file whose extension has no entry is answered 404, so
// nothing is served with a sniffed type.
var staticTypes = map[string]string{
	".css": "text/css; charset=utf-8",
	".js":  "text/javascript; charset=utf-8",
}

// staticFS is the static/ directory of the embedded FS.
func staticFS() (fs.FS, error) { return fs.Sub(web.FS, "static") }
