// Package shared provides cross-platform scanning utilities.
package shared

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"sys-scanner/internal/types"
)

const (
	maxEntriesPerDir = 1000
	dirTimeout       = 3 * time.Second
)

// ScanPATH scans a list of directories for executable files and returns
// detected programs. Each directory is scanned with a 3-second timeout and
// a cap of 1000 entries.
//
// allowlist filters results to only binaries whose name (without extension)
// matches an entry. aiBinaries always pass through regardless of allowlist.
func ScanPATH(ctx context.Context, dirs []string, allowlist []string, aiBinaries []string) ([]types.Program, error) {
	if len(dirs) == 0 {
		return nil, nil
	}

	allowSet := make(map[string]struct{}, len(allowlist))
	for _, name := range allowlist {
		allowSet[strings.ToLower(name)] = struct{}{}
	}

	aiSet := make(map[string]struct{}, len(aiBinaries))
	for _, name := range aiBinaries {
		aiSet[strings.ToLower(name)] = struct{}{}
	}

	var programs []types.Program

	for _, dir := range dirs {
		dir = strings.TrimSpace(dir)
		if dir == "" {
			continue
		}

		entries, err := scanDir(ctx, dir, allowSet, aiSet)
		if err != nil {
			// Skip directories that don't exist or timeout — don't abort entire scan.
			continue
		}
		programs = append(programs, entries...)
	}

	return programs, nil
}

// scanDir scans a single directory for executables with timeout.
func scanDir(ctx context.Context, dir string, allowSet, aiSet map[string]struct{}) ([]types.Program, error) {
	dirCtx, cancel := context.WithTimeout(ctx, dirTimeout)
	defer cancel()

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return nil, err
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var programs []types.Program
	count := 0

	for _, entry := range entries {
		select {
		case <-dirCtx.Done():
			return programs, nil
		default:
		}

		if count >= maxEntriesPerDir {
			break
		}

		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		baseName := stripExeSuffix(name)
		lowerName := strings.ToLower(baseName)

		// AI binaries always pass.
		_, isAI := aiSet[lowerName]

		// Check allowlist (skip if non-empty and name not in allowlist and not AI).
		if len(allowSet) > 0 && !isAI {
			if _, ok := allowSet[lowerName]; !ok {
				continue
			}
		}

		fullPath := filepath.Join(dir, name)

		if !isExecutable(fullPath, entry) {
			continue
		}

		count++

		p := types.Program{
			Name:            baseName,
			InstallLocation: dir,
			Source:          "PATH",
		}
		if isAI {
			p.IsAITool = true
			p.AIToolName = baseName
		}

		programs = append(programs, p)
	}

	return programs, nil
}

// isExecutable checks whether a file is executable.
// On Windows, it checks for .exe/.bat/.cmd/.ps1 extensions.
// On Unix, it checks the executable permission bit.
func isExecutable(path string, entry os.DirEntry) bool {
	if runtime.GOOS == "windows" {
		lower := strings.ToLower(filepath.Ext(path))
		switch lower {
		case ".exe", ".bat", ".cmd", ".ps1", ".com":
			return true
		}
		return false
	}

	info, err := entry.Info()
	if err != nil {
		return false
	}
	return info.Mode()&0o111 != 0
}

// stripExeSuffix removes .exe (case-insensitive) from the end of a name.
func stripExeSuffix(name string) string {
	if strings.ToLower(filepath.Ext(name)) == ".exe" {
		return name[:len(name)-4]
	}
	return name
}
