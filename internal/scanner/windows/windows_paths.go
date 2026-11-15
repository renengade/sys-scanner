//go:build windows

package windows

import (
	"os"
	"path/filepath"
	"strings"
)

// windowsRootDir returns the Windows installation directory. Used to build
// absolute paths for system executables so subprocess launch cannot be
// hijacked by a hostile PATH or current directory.
func windowsRootDir() string {
	if root := os.Getenv("SystemRoot"); root != "" {
		return root
	}
	return `C:\Windows`
}

// windowsSystemToolPath returns the absolute path of a tool under
// %SystemRoot%\System32.
func windowsSystemToolPath(name string) string {
	return filepath.Join(windowsRootDir(), "System32", name)
}

// includeStartMenu enables the slow, deduplication-heavy .lnk scan. It is off
// by default because registry/App Paths coverage is better and Start Menu
// shortcuts are mostly duplicates.
func includeStartMenu() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SYS_SCANNER_SCAN_LNK")))
	return v == "1" || v == "true" || v == "yes"
}
