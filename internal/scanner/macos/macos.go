//go:build darwin

package macos

import (
	"context"
	"log"
	"os"
	"path/filepath"

	"sys-scanner/internal/merge"
	"sys-scanner/internal/scanner/shared"
	"sys-scanner/internal/signatures"
	"sys-scanner/internal/types"
)

// Scanner implements platform.PlatformDetector for macOS.
type Scanner struct {
	// Stats tracks error counts per source for diagnostics.
	Stats map[string]int
}

// New creates a new macOS Scanner.
func New() *Scanner {
	return &Scanner{
		Stats: make(map[string]int),
	}
}

// Detect runs all macOS detection sources sequentially and returns
// deduplicated programs. Each source is run independently; errors are
// logged but do not abort the scan.
func (s *Scanner) Detect() ([]types.Program, error) {
	return s.DetectContext(context.Background())
}

// DetectContext is the context-aware variant of Detect. It returns partial
// results together with the context error if the deadline is reached.
func (s *Scanner) DetectContext(ctx context.Context) ([]types.Program, error) {
	var all []types.Program
	finish := func(err error) ([]types.Program, error) {
		return merge.Deduplicate(all), err
	}

	// 1. .app bundles
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	apps, err := scanAppBundles()
	if err != nil {
		log.Printf("macos: app bundle scan error: %v", err)
		s.Stats["app_bundle"]++
	} else {
		all = append(all, apps...)
	}

	// 2. Homebrew
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	brew, err := scanHomebrew()
	if err != nil {
		log.Printf("macos: homebrew scan error: %v", err)
		s.Stats["homebrew"]++
	} else {
		all = append(all, brew...)
	}

	// 3. system_profiler
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	sp, err := scanSysProfiler()
	if err != nil {
		log.Printf("macos: system_profiler scan error: %v", err)
		s.Stats["system_profiler"]++
	} else {
		all = append(all, sp...)
	}

	// 4. PATH
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	pathPrograms, err := s.scanPATHContext(ctx)
	if err != nil {
		log.Printf("macos: PATH scan error: %v", err)
		s.Stats["PATH"]++
	} else {
		all = append(all, pathPrograms...)
	}

	// 5. Dedup
	return finish(nil)
}

// scanPATH uses the shared PATH scanner with macOS-specific allowlist and
// AI binary list.
func (s *Scanner) scanPATH() ([]types.Program, error) {
	return s.scanPATHContext(context.Background())
}

func (s *Scanner) scanPATHContext(ctx context.Context) ([]types.Program, error) {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil, nil
	}

	dirs := filepath.SplitList(pathEnv)

	allowlist := macosPATHAllowlist()
	aiBinaries := signatures.BinaryNames()

	return shared.ScanPATH(ctx, dirs, allowlist, aiBinaries)
}

// macosPATHAllowlist returns the binary names to look for in PATH directories
// on macOS. Combines common developer tools and AI-related binaries.
func macosPATHAllowlist() []string {
	return []string{
		// Developer tools
		"git", "make", "cmake", "gcc", "g++", "clang", "python3", "python",
		"node", "npm", "ruby", "java", "javac", "go", "rustc", "cargo",
		"swift", "swiftc", "brew",
	}
}
