//go:build windows

package scanner

import (
	"sys-scanner/internal/platform"
	"sys-scanner/internal/scanner/windows"
)

// NewScanner returns a WindowsScanner for Windows targets.
func NewScanner() platform.PlatformDetector {
	return windows.NewWindowsScanner()
}
