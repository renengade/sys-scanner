package types

import "html"

// SafeString wraps a string value and provides HTML-safe rendering.
// When used in HTML templates, String() returns the HTML-escaped value.
type SafeString string

// HTMLEscape returns the string with HTML special characters escaped:
// & < > " '
func (s SafeString) HTMLEscape() string {
	return html.EscapeString(string(s))
}

// String returns the HTML-escaped value, suitable for use in templates.
func (s SafeString) String() string {
	return s.HTMLEscape()
}
