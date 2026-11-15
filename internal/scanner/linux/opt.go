package linux

import (
	"os"
	"path/filepath"

	"sys-scanner/internal/types"
)

// optRoot is the directory scanned for third-party software packages.
// Exported as a variable so tests can override it.
var optRoot = "/opt"

// scanOpt walks /opt/ at depth 1. Each immediate subdirectory is treated
// as a potential program. This catches vendor-installed software such as
// /opt/google/chrome, /opt/vscode, /opt/zoom, etc.
func scanOpt() []types.Program {
	return scanOptDir(optRoot)
}

// scanOptDir walks the given root at depth 1 and returns programs.
// Extracted for testing with temp directories.
func scanOptDir(root string) []types.Program {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil
	}

	var programs []types.Program

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		name := entry.Name()
		// Skip hidden directories.
		if len(name) > 0 && name[0] == '.' {
			continue
		}

		fullPath := filepath.Join(root, name)

		p := types.Program{
			Name:            name,
			InstallLocation: fullPath,
			Source:          "opt",
		}

		programs = append(programs, p)
	}

	return programs
}
