// Package report renders an HTML report of scan results and opens it
// in the user's default browser.
package report

import (
	"embed"
	"fmt"
	"html/template"
)

// assets holds the embedded HTML template and any future assets.
// The //go:embed directive must reference files relative to the source file
// containing it. Only one //go:embed directive can target the same variable.
//
//go:embed template.html
var assets embed.FS

// reportTemplate is the parsed HTML template used by Generate and tests.
// Parsing happens at package initialization so a malformed template fails
// the build rather than at runtime.
var reportTemplate = template.Must(template.ParseFS(assets, "template.html"))

// ErrTemplateParse indicates a (currently unrecoverable) template parse error.
// Kept as a sentinel so callers and tests can distinguish it from I/O errors.
var ErrTemplateParse = fmt.Errorf("report: template parse error")
