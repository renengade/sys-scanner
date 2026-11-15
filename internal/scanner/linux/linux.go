package linux

import (
	"context"
	"os"
	"strings"
	"time"

	"sys-scanner/internal/merge"
	"sys-scanner/internal/platform"
	"sys-scanner/internal/scanner/shared"
	"sys-scanner/internal/signatures"
	"sys-scanner/internal/types"
)

var _ platform.PlatformDetector = (*LinuxScanner)(nil)

// LinuxScanner implements platform.PlatformDetector for Linux systems.
// It orchestrates scanning of .desktop files, package managers, /opt/, and PATH.
type LinuxScanner struct {
	// Stats tracks the number of programs found per source and errors per source.
	Stats *types.ScanResult
}

// NewLinuxScanner creates a LinuxScanner with initialized stats.
func NewLinuxScanner() *LinuxScanner {
	return &LinuxScanner{
		Stats: types.NewScanResult(),
	}
}

// Detect runs all Linux-specific scanners sequentially and returns
// deduplicated results. Each scanner runs independently; failures are
// tracked in stats but do not abort the scan.
func (s *LinuxScanner) Detect() ([]types.Program, error) {
	return s.DetectContext(context.Background())
}

// DetectContext is the context-aware variant of Detect. It checks for
// cancellation between sources and returns the partial, deduplicated result
// together with the context error when the deadline is reached.
func (s *LinuxScanner) DetectContext(ctx context.Context) ([]types.Program, error) {
	start := time.Now()

	var allPrograms []types.Program
	finish := func(err error) ([]types.Program, error) {
		result := merge.Deduplicate(allPrograms)
		s.Stats.ScanDuration = time.Since(start)
		s.Stats.Programs = result
		return result, err
	}

	// 1. Scan .desktop files.
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	desktopPrograms := scanDesktopFiles()
	s.recordSource(".desktop", desktopPrograms, len(desktopPrograms) == 0)
	allPrograms = append(allPrograms, desktopPrograms...)

	// 2. Scan package managers (dpkg, rpm, snap, flatpak).
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	pkgPrograms := scanPackages()
	s.recordSource("package_manager", pkgPrograms, len(pkgPrograms) == 0)
	allPrograms = append(allPrograms, pkgPrograms...)

	// 3. Scan /opt/ directory.
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	optPrograms := scanOpt()
	s.recordSource("opt", optPrograms, len(optPrograms) == 0)
	allPrograms = append(allPrograms, optPrograms...)

	// 4. Scan PATH directories.
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	pathPrograms := s.scanPATHDirsContext(ctx)
	s.recordSource("PATH", pathPrograms, len(pathPrograms) == 0)
	allPrograms = append(allPrograms, pathPrograms...)

	// 5. Deduplicate.
	if err := ctx.Err(); err != nil {
		return finish(err)
	}
	return finish(nil)
}

// scanPATHDirs reads the PATH environment variable and delegates to
// the shared PATH scanner with the Linux allowlist.
func (s *LinuxScanner) scanPATHDirs() []types.Program {
	return s.scanPATHDirsContext(context.Background())
}

func (s *LinuxScanner) scanPATHDirsContext(ctx context.Context) []types.Program {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return nil
	}

	dirs := strings.Split(pathEnv, ":")
	pathCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	programs, err := shared.ScanPATH(pathCtx, dirs, linuxPATHAllowlist(), signatures.BinaryNames())
	if err != nil {
		s.Stats.ErrorsBySource["PATH"]++
		return nil
	}

	return programs
}

// linuxPATHAllowlist returns the binary names to look for in PATH directories
// on Linux. It filters out non-program executables (config files, icons, etc.)
// so only common CLI tools are reported as programs. AI binaries are handled
// separately by signatures.BinaryNames() and always pass through.
func linuxPATHAllowlist() []string {
	return []string{
		// Version control & CI
		"git", "gh", "glab",
		// Languages & runtimes
		"python3", "python", "pip3", "pip", "node", "npm", "npx", "yarn",
		"pnpm", "ruby", "gem", "bundle", "java", "javac", "go", "cargo",
		"rustc", "rustup",
		// Compilers & build tools
		"gcc", "g++", "clang", "clang++", "make", "cmake",
		// Debuggers
		"gdb", "lldb",
		// Containers & infra
		"docker", "podman", "kubectl", "helm", "terraform", "ansible",
		// Editors
		"vim", "nvim", "emacs", "nano",
		// Terminal & session tools
		"tmux", "screen",
		// Networking & transfer
		"curl", "wget", "ssh", "scp", "rsync",
		// Archiving
		"tar", "zip", "unzip",
		// Media
		"ffmpeg", "convert", "magick",
		// System monitoring & data
		"htop", "jq", "yq", "sqlite3", "psql", "mysql", "redis-cli", "mongo",
	}
}

// recordSource updates stats for a given source.
func (s *LinuxScanner) recordSource(source string, programs []types.Program, isEmpty bool) {
	if isEmpty {
		// Track that we attempted this source but found nothing — not necessarily an error.
		return
	}
	s.Stats.CountBySource[source] = len(programs)
}
