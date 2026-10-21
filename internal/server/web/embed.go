// Package web holds keyroster-server's pages and static assets, embedded
// in the binary: html/template files, plain CSS and one hand-written JS
// file, static/app.js, which runs the passkey registration ceremony
// (02-08). No npm package, third-party asset, inline script
// or inline style (UI-01).
package web

import "embed"

// FS holds templates/ and static/.
//
//go:embed templates static
var FS embed.FS
