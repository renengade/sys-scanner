// Package windows implements the Windows platform scanner.
//
// helpers.go contains pure logic functions (no Windows API calls) that are
// compiled on all platforms so tests can exercise them from Linux.
package windows

import (
	"os"
	"path/filepath"
	"strings"

	"sys-scanner/internal/types"
)

// Registry value names used across Uninstall and App Paths keys.
const (
	valDisplayName     = "DisplayName"
	valDisplayVersion  = "DisplayVersion"
	valPublisher       = "Publisher"
	valInstallLocation = "InstallLocation"
	valInstallDate     = "InstallDate"
	valSystemComponent = "SystemComponent"
	valNoRemove        = "NoRemove"
	valParentKeyName   = "ParentKeyName"
	valReleaseType     = "ReleaseType"
	valHideARP         = "HideARP"
)

// filteredReleaseTypes are ReleaseType values that indicate OS-level patches
// rather than user-installed programs.
var filteredReleaseTypes = map[string]bool{
	"Hotfix":          true,
	"Security Update": true,
	"Update Rollup":   true,
	"Service Pack":    true,
}

// builtinNamePrefixes lists lowercase display-name prefixes for Windows /
// Microsoft components that are shipped with the OS or are runtime
// prerequisites, rather than applications a user chose to install.
var builtinNamePrefixes = []string{
	"microsoft windows",
	"windows ",
	"windows sdk",
	"windows driver package",
	"windows software development kit",
	"windows subsystem for linux",
	"microsoft visual c++",
	"microsoft vc++",
	"microsoft .net",
	"microsoft.net",
	"microsoft edge",
	"microsoft update",
	"microsoft store",
	"microsoft xbox",
	"microsoft gaming services",
	"microsoft directx",
	"microsoft silverlight",
	"microsoft xna",
	"microsoft heif image",
	"microsoft av1 video",
	"microsoft vp9 video",
	"microsoft webp image",
	"microsoft raw image",
	"microsoft mpeg-2",
	"microsoft ui.xaml",
	"microsoft.services.store",
	"microsoft.windowsappruntime",
	"microsoft.vclibs",
	"microsoft.winget",
}

// includeBuiltinEntries lets power users include OS/runtime entries for
// auditing by setting SYS_SCANNER_INCLUDE_BUILTIN=1.
func includeBuiltinEntries() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("SYS_SCANNER_INCLUDE_BUILTIN")))
	return v == "1" || v == "true" || v == "yes"
}

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
// %SystemRoot%\\System32.
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

// isWindowsBuiltinName reports whether a display name belongs to a Windows or
// Microsoft built-in component rather than a user-installed application.
func isWindowsBuiltinName(name string) bool {
	if includeBuiltinEntries() {
		return false
	}
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return false
	}
	for _, prefix := range builtinNamePrefixes {
		if strings.HasPrefix(n, prefix) {
			return true
		}
	}
	return false
}

// isWindowsSystemPath reports whether a path points into the Windows
// installation directory (System32, SysWOW64, WinSxS, ...).
func isWindowsSystemPath(path string) bool {
	if includeBuiltinEntries() {
		return false
	}
	p := strings.ToLower(strings.Trim(strings.TrimSpace(path), `"`))
	if p == "" {
		return false
	}
	root := strings.ToLower(strings.TrimSpace(os.Getenv("SystemRoot")))
	if root == "" {
		root = `c:\windows`
	}
	root = strings.TrimRight(root, `\`)
	return p == root || strings.HasPrefix(p, root+`\`)
}

// isBuiltinStorePackage reports whether a Microsoft Store/AppX package is an
// OS component, inbox app, or opaque shell package. Only third-party and
// explicitly allowlisted Microsoft applications are kept.
func isBuiltinStorePackage(name string) bool {
	if includeBuiltinEntries() {
		return false
	}
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return true
	}

	// Keep a few Microsoft apps that users install on purpose; everything
	// else under Microsoft.* is an inbox component or runtime.
	keep := map[string]bool{
		"microsoft.visualstudiocode": true,
		"microsoft.powertoys":        true,
	}
	if keep[n] {
		return false
	}

	if strings.HasPrefix(n, "microsoft.") ||
		strings.HasPrefix(n, "microsoftwindows.") ||
		strings.HasPrefix(n, "windows.") ||
		strings.HasPrefix(n, "microsoftcorporationii.") {
		return true
	}

	// Shell integrations, opaque package names and GUIDs are not
	// user-facing applications.
	if strings.Contains(n, "shellextension") || strings.Contains(n, "shell.") {
		return true
	}
	if !strings.Contains(n, ".") {
		return true
	}
	if isGUID(n) {
		return true
	}
	return false
}

// isGUID reports whether s looks like a canonical 8-4-4-4-12 GUID.
func isGUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if r != '-' {
				return false
			}
			continue
		}
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// builtinExecutableNames are App Paths keys for Windows inbox tools.
var builtinExecutableNames = map[string]bool{
	"gethelp":                     true,
	"iediag":                      true,
	"iediagcmd":                   true,
	"iexplore":                    true,
	"mplayer2":                    true,
	"mspaint":                     true,
	"notepad":                     true,
	"powershell":                  true,
	"pwsh":                        true,
	"cmd":                         true,
	"conhost":                     true,
	"snippingtool":                true,
	"store":                       true,
	"tabtip":                      true,
	"wab":                         true,
	"wabmig":                      true,
	"windowspackagemanagerserver": true,
	"winget":                      true,
	"wt":                          true,
	"msedge":                      true,
	"explorer":                    true,
	"control":                     true,
	"mmc":                         true,
	"regedit":                     true,
	"taskmgr":                     true,
	"charmap":                     true,
	"wordpad":                     true,
	"write":                       true,
	"copilotapp":                  true,
	"skypeserver":                 true,
	"wmplayer":                    true,
}

// isBuiltinExecutableName reports whether an App Paths key names an inbox
// Windows/Office helper executable rather than a user application.
func isBuiltinExecutableName(name string) bool {
	if includeBuiltinEntries() {
		return false
	}
	n := strings.ToLower(strings.TrimSpace(name))
	n = strings.TrimSuffix(n, ".exe")
	if builtinExecutableNames[n] {
		return true
	}
	// Office helper processes (msoadfsb, msoasb, msoxmled, ...) and shell
	// extension DLL hosts are not applications.
	return strings.HasPrefix(n, "mso") || strings.HasSuffix(n, "shellext")
}

// shouldFilterEntry returns true if the registry values describe an entry
// that should NOT be reported as an installed program.
func shouldFilterEntry(values map[string]string) bool {
	if values[valSystemComponent] == "1" {
		return true
	}
	if values[valNoRemove] == "1" {
		return true
	}
	if values[valParentKeyName] != "" {
		return true
	}
	if filteredReleaseTypes[values[valReleaseType]] {
		return true
	}
	if values[valHideARP] == "1" {
		return true
	}
	return false
}

// parseRegistryEntry converts a flat map of registry string values into a
// types.Program. Returns (zero, false) when the entry should be skipped
// (filtered out or missing DisplayName).
func parseRegistryEntry(values map[string]string, source string) (types.Program, bool) {
	if shouldFilterEntry(values) {
		return types.Program{}, false
	}

	name := strings.TrimSpace(values[valDisplayName])
	if name == "" {
		return types.Program{}, false
	}
	if isWindowsBuiltinName(name) {
		return types.Program{}, false
	}

	meta := make(map[string]string)
	if v := values[valInstallDate]; v != "" {
		meta["InstallDate"] = v
	}

	return types.Program{
		Name:            name,
		Version:         strings.TrimSpace(values[valDisplayVersion]),
		Publisher:       strings.TrimSpace(values[valPublisher]),
		InstallLocation: strings.TrimSpace(values[valInstallLocation]),
		Source:          source,
		RawMetadata:     meta,
	}, true
}

// expandEnvVars replaces %VAR% references in s. If env is non-nil it is
// consulted first; missing keys and a nil env fall back to os.Getenv.
func expandEnvVars(s string, env map[string]string) string {
	var b strings.Builder
	b.Grow(len(s))

	i := 0
	for i < len(s) {
		if s[i] != '%' {
			b.WriteByte(s[i])
			i++
			continue
		}
		// Found '%', look for closing '%'.
		j := strings.IndexByte(s[i+1:], '%')
		if j < 0 {
			// No closing '%': emit the rest literally.
			b.WriteString(s[i:])
			break
		}
		j += i + 1 // absolute index of closing '%'

		varName := s[i+1 : j]
		varVal := ""
		if env != nil {
			varVal = env[varName]
		}
		if varVal == "" && env == nil {
			varVal = os.Getenv(varName)
		}
		b.WriteString(varVal)
		i = j + 1
	}
	return b.String()
}

// splitWindowsPATH splits a Windows PATH string on ';' and trims whitespace
// from each entry. Empty entries are discarded.
func splitWindowsPATH(path string) []string {
	parts := strings.Split(path, ";")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// parseWSLOutput parses the combined output of the WSL probe script and
// returns synthetic AI-tool programs. Output lines are "BIN:<name>" for
// binaries found on WSL PATH and "DIR:<expanded path>" for config dirs found.
//
// For each line, the first tool whose BinaryNames (case-insensitive) or linux
// ConfigDirs match wins. Results are deduplicated by AIToolName so a tool
// detected via both a binary and a config dir is reported only once.
func parseWSLOutput(out string, tools []types.ToolSignature) []types.Program {
	seen := make(map[string]bool)
	var progs []types.Program

	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var tool types.ToolSignature
		var ok bool
		switch {
		case strings.HasPrefix(line, "BIN:"):
			tool, ok = findToolByBinary(tools, strings.TrimPrefix(line, "BIN:"))
		case strings.HasPrefix(line, "DIR:"):
			tool, ok = findToolByConfigDir(tools, strings.TrimPrefix(line, "DIR:"))
		default:
			continue
		}
		if !ok {
			continue
		}
		if seen[tool.Name] {
			continue
		}
		seen[tool.Name] = true
		progs = append(progs, wslProgram(tool))
	}
	return progs
}

// wslProgram builds the synthetic Program entry for a tool detected inside WSL.
func wslProgram(t types.ToolSignature) types.Program {
	return types.Program{
		Name:       t.DisplayName,
		Source:     "wsl",
		IsAITool:   true,
		AIToolName: t.Name,
		RawMetadata: map[string]string{
			"ai_confidence": "high",
		},
	}
}

// findToolByBinary returns the first tool whose BinaryNames contains name
// (case-insensitive).
func findToolByBinary(tools []types.ToolSignature, name string) (types.ToolSignature, bool) {
	for _, t := range tools {
		for _, bn := range t.BinaryNames {
			if strings.EqualFold(bn, name) {
				return t, true
			}
		}
	}
	return types.ToolSignature{}, false
}

// findToolByConfigDir returns the first tool whose linux ConfigDirs contains a
// dir matching path. Dir entries use a "~" prefix which bash expands to $HOME,
// so a "~" entry is normalized to its home-relative suffix before comparing
// against the already-expanded path.
func findToolByConfigDir(tools []types.ToolSignature, path string) (types.ToolSignature, bool) {
	for _, t := range tools {
		for _, dir := range t.ConfigDirs["linux"] {
			if configDirMatches(dir, path) {
				return t, true
			}
		}
	}
	return types.ToolSignature{}, false
}

// configDirMatches reports whether a linux config dir (which may carry a "~"
// prefix) matches an already-expanded path from the WSL probe.
func configDirMatches(dir, path string) bool {
	if strings.HasPrefix(dir, "~") {
		// Normalize "~/.cursor" to "/.cursor" and require path to equal it or
		// end with it. The leading "/" keeps the boundary unambiguous.
		suffix := dir[1:]
		if suffix == "" {
			return false
		}
		return path == suffix || strings.HasSuffix(path, suffix)
	}
	return path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/")
}

// buildWSLProbeScript generates the bash probe script from the signature DB so
// it stays in sync with the tools being detected.
//
// The script deliberately avoids shell variables and double quotes. When the
// Windows binary is started from inside WSL, wsl.exe receives the script as a
// single Windows command-line argument; quoting/variable expansion through
// that layer is unreliable, so every probe is emitted as an explicit command.
func buildWSLProbeScript(tools []types.ToolSignature) string {
	var b strings.Builder

	seenBins := make(map[string]struct{})
	for _, t := range tools {
		for _, name := range t.BinaryNames {
			lower := strings.ToLower(name)
			if _, ok := seenBins[lower]; ok {
				continue
			}
			seenBins[lower] = struct{}{}
			b.WriteString("command -v ")
			b.WriteString(lower)
			b.WriteString(" >/dev/null 2>&1 && echo BIN:")
			b.WriteString(lower)
			b.WriteString("; ")
		}
	}

	seenDirs := make(map[string]struct{})
	for _, t := range tools {
		for _, dir := range t.ConfigDirs["linux"] {
			if _, ok := seenDirs[dir]; ok {
				continue
			}
			seenDirs[dir] = struct{}{}
			b.WriteString("[ -e ")
			b.WriteString(dir)
			b.WriteString(" ] && echo DIR:")
			b.WriteString(dir)
			b.WriteString("; ")
		}
	}

	b.WriteString("true")
	return b.String()
}
