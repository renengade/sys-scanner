// Package platform defines the interface for OS-specific program detection.
package platform

import (
	"os"

	"sys-scanner/internal/types"
)

// PlatformDetector is implemented by each OS-specific scanner.
type PlatformDetector interface {
	Detect() ([]types.Program, error)
}

// UserHomeDir returns the current user's home directory.
// It checks the HOME environment variable first, then falls back to os.UserHomeDir.
func UserHomeDir() (string, error) {
	if home := os.Getenv("HOME"); home != "" {
		return home, nil
	}
	return os.UserHomeDir()
}
