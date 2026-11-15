//go:build darwin

package scanner

import (
	"sys-scanner/internal/platform"
	"sys-scanner/internal/scanner/macos"
)

// NewScanner returns a macOS Scanner for Darwin targets.
func NewScanner() platform.PlatformDetector {
	return macos.New()
}
