// Package scanner provides a platform-aware factory for OS-specific scanners.
// The NewScanner function is defined in platform_<goos>.go files with build
// tags so that each platform only imports its own scanner package.
package scanner

// NewScanner returns the PlatformDetector for the current operating system.
// The implementation is in platform_windows.go, platform_darwin.go, or
// platform_linux.go depending on the build target.
