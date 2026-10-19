// Package web holds keyroster-server's pages and static assets, embedded
// in the binary: html/template files and plain CSS (and, from 02-07, one
// hand-written JS file). No npm package, third-party asset, inline script
// or inline style (UI-01).
package web

import "embed"

// FS holds templates/ and static/.
//
//go:embed templates static
var FS embed.FS
