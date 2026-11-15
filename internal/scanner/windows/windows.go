//go:build windows

package windows

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"sys-scanner/internal/merge"
	"sys-scanner/internal/platform"
	"sys-scanner/internal/types"
)

// compile-time interface check.
var _ platform.PlatformDetector = (*WindowsScanner)(nil)

// WindowsScanner is the top-level Windows platform detector. It runs each
// sub-scanner sequentially, logging errors and continuing on failure.
type WindowsScanner struct{}

// NewWindowsScanner returns a new WindowsScanner.
func NewWindowsScanner() *WindowsScanner {
	return &WindowsScanner{}
}

// scanSource is a named scanner function that returns programs and an
// optional error. Errors are logged but do not halt the pipeline.
type scanSource struct {
	name string
	fn   func() ([]types.Program, error)
}

// Detect runs all Windows scanners sequentially, collects results, tracks
// per-source statistics, and returns deduplicated programs.
//
// Scan order: registry → apppaths → PATH → store → wsl.
//
// Start Menu .lnk scanning is off by default: shortcuts are mostly duplicates
// of registry entries, resolving them through COM is slow, and inbox Windows
// shortcuts add a lot of noise. Set SYS_SCANNER_SCAN_LNK=1 to enable it.
func (s *WindowsScanner) Detect() ([]types.Program, error) {
	return s.DetectContext(context.Background())
}

// DetectContext is the context-aware variant of Detect. It checks for
// cancellation between sources and returns partial results with the context
// error when the deadline is reached.
func (s *WindowsScanner) DetectContext(ctx context.Context) ([]types.Program, error) {
	start := time.Now()

	sources := []scanSource{
		{"registry", scanRegistry},
		{"apppaths", scanAppPaths},
		{"PATH", scanWindowsPATH},
		{"store", scanStoreApps},
		{"wsl", scanWSLTools},
	}
	if includeStartMenu() {
		sources = append(sources, scanSource{"startmenu", scanStartMenu})
	}

	// The sources are independent and dominated by I/O / subprocess waits
	// (PowerShell Get-AppxPackage, wsl.exe probes, registry enumeration).
	// Run them concurrently, but keep the result order fixed by source so
	// deduplication remains deterministic.
	type sourceResult struct {
		programs []types.Program
		err      error
	}
	results := make([]sourceResult, len(sources))
	var wg sync.WaitGroup
	for i := range sources {
		if err := ctx.Err(); err != nil {
			return merge.Deduplicate(nil), err
		}
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			progs, err := sources[i].fn()
			results[i] = sourceResult{programs: progs, err: err}
		}(i)
	}
	wg.Wait()

	var all []types.Program
	stats := make(map[string]int)
	errStats := make(map[string]int)
	for i, src := range sources {
		if results[i].err != nil {
			slog.Warn("scanner source failed", "source", src.name, "error", results[i].err)
			errStats[src.name]++
			continue
		}
		stats[src.name] = len(results[i].programs)
		all = append(all, results[i].programs...)
	}

	slog.Info("Windows scan complete",
		"duration", time.Since(start),
		"total_raw", len(all),
		"by_source", stats,
		"errors", errStats,
	)

	deduped := merge.Deduplicate(all)
	if err := ctx.Err(); err != nil {
		return deduped, err
	}
	return deduped, nil
}
