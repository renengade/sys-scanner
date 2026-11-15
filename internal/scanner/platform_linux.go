//go:build linux

package scanner

import (
	"sys-scanner/internal/platform"
	"sys-scanner/internal/scanner/linux"
)

// NewScanner returns a LinuxScanner for Linux targets.
func NewScanner() platform.PlatformDetector {
	return linux.NewLinuxScanner()
}
