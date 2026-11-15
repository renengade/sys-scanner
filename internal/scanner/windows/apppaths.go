//go:build windows

package windows

import (
	"context"
	"log/slog"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"

	"sys-scanner/internal/scanner/shared"
	"sys-scanner/internal/signatures"
	"sys-scanner/internal/types"
)

const appPathsKeyPath = `SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths`

// System PATH registry locations.
const (
	systemEnvKeyPath = `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`
	systemEnvValName = "Path"
	userEnvKeyPath   = `Environment`
	userEnvValName   = "Path"
)

// scanAppPaths enumerates the App Paths registry keys under HKLM and HKCU.
// Each subkey name is the executable name (e.g. "WINWORD.EXE") and its
// (Default) value holds the full path to the binary.
func scanAppPaths() ([]types.Program, error) {
	views := []struct {
		root  registry.Key
		label string
	}{
		{registry.LOCAL_MACHINE, "HKLM/App Paths"},
		{registry.CURRENT_USER, "HKCU/App Paths"},
	}

	var programs []types.Program

	for _, v := range views {
		progs, err := scanAppPathsView(v.root, v.label)
		if err != nil {
			slog.Warn("App Paths scan failed", "view", v.label, "error", err)
			continue
		}
		programs = append(programs, progs...)
	}
	return programs, nil
}

// scanAppPathsView reads a single App Paths registry hive.
func scanAppPathsView(root registry.Key, label string) ([]types.Program, error) {
	k, err := registry.OpenKey(root, appPathsKeyPath, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil, err
	}
	defer k.Close()

	subKeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	programs := make([]types.Program, 0, len(subKeys))
	for _, name := range subKeys {
		sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			slog.Debug("App Paths subkey open failed", "key", name, "error", err)
			continue
		}

		// (Default) value holds the full executable path.
		defaultVal, _, err := sk.GetStringValue("")
		_ = sk.Close()
		if err != nil || defaultVal == "" {
			continue
		}

		defaultVal = strings.TrimSpace(defaultVal)
		// Strip surrounding quotes if present.
		defaultVal = strings.Trim(defaultVal, "\"")

		// Skip Windows system executables (System32, SysWOW64, WinSxS).
		if isWindowsSystemPath(defaultVal) {
			continue
		}
		if isWindowsBuiltinName(name) {
			continue
		}
		if isBuiltinExecutableName(name) {
			continue
		}

		baseName := strings.TrimSuffix(name, filepath.Ext(name))
		if baseName == "" {
			baseName = name
		}

		programs = append(programs, types.Program{
			Name:            baseName,
			InstallLocation: filepath.Dir(defaultVal),
			Source:          "apppaths",
			RawMetadata: map[string]string{
				"Executable": name,
				"FullPath":   defaultVal,
			},
		})
	}
	return programs, nil
}

// scanWindowsPATH reads the system and user PATH from the registry, expands
// %VAR% references, splits on ';', and delegates to shared.ScanPATH.
func scanWindowsPATH() ([]types.Program, error) {
	dirs, err := collectWindowsPATHDirs()
	if err != nil {
		slog.Warn("Windows PATH collection failed", "error", err)
		// Degrade gracefully: try the process-level PATH env as fallback.
	}

	if len(dirs) == 0 {
		return nil, nil
	}

	ctx := context.Background()
	return shared.ScanPATH(ctx, dirs, windowsPATHAllowlist(), signatures.BinaryNames())
}

// windowsPATHAllowlist returns the binary names to look for in PATH directories
// on Windows. It filters out non-program executables so only common CLI tools
// are reported as programs. AI binaries are handled separately by
// signatures.BinaryNames() and always pass through.
func windowsPATHAllowlist() []string {
	return []string{
		// Version control & CI
		"git", "gh",
		// Languages & runtimes
		"python", "python3", "pip", "pip3", "node", "npm", "npx", "yarn",
		"pnpm", "ruby", "gem", "bundle", "java", "javac", "go", "cargo",
		"rustc", "rustup", "dotnet",
		// Compilers & build tools
		"gcc", "g++", "clang", "make", "cmake", "msbuild",
		// Debuggers
		"gdb", "windbg",
		// Containers & infra
		"docker", "kubectl", "helm", "terraform", "ansible", "minikube",
		// Editors
		"vim", "nvim", "emacs", "nano", "code",
		// Terminal & session tools
		"tmux",
		// Networking & transfer
		"curl", "wget", "ssh", "scp", "rsync", "ftp", "telnet",
		// Archiving
		"tar", "zip", "unzip", "7z", "rar",
		// Media
		"ffmpeg", "magick", "convert",
		// System monitoring & data
		"htop", "jq", "yq", "sqlite3", "psql", "mysql", "redis-cli", "mongo",
	}
}

// collectWindowsPATHDirs reads system + user PATH from the registry, expands
// environment variables, and returns the de-duplicated list of directories.
func collectWindowsPATHDirs() ([]string, error) {
	var rawPaths []string

	// System PATH (HKLM).
	if v, err := readEnvString(registry.LOCAL_MACHINE, systemEnvKeyPath, systemEnvValName, registry.WOW64_64KEY); err == nil {
		rawPaths = append(rawPaths, v)
	} else {
		slog.Debug("system PATH read failed", "error", err)
	}

	// User PATH (HKCU).
	if v, err := readEnvString(registry.CURRENT_USER, userEnvKeyPath, userEnvValName, 0); err == nil {
		rawPaths = append(rawPaths, v)
	} else {
		slog.Debug("user PATH read failed", "error", err)
	}

	// Expand %VAR% references using the process environment.
	var expanded []string
	for _, raw := range rawPaths {
		expanded = append(expanded, expandEnvVars(raw, nil))
	}

	// Combine, split, and de-duplicate.
	seen := make(map[string]bool)
	var dirs []string
	for _, p := range expanded {
		for _, d := range splitWindowsPATH(p) {
			// Windows system directories contain only OS binaries; exclude
			// them so PATH doesn't surface built-in Windows tools.
			if isWindowsSystemPath(d) {
				continue
			}
			clean := strings.ToLower(d)
			if !seen[clean] {
				seen[clean] = true
				dirs = append(dirs, d)
			}
		}
	}
	return dirs, nil
}

// readEnvString reads a REG_SZ / REG_EXPAND_SZ value from a registry key.
func readEnvString(root registry.Key, path, value string, access uint32) (string, error) {
	k, err := registry.OpenKey(root, path, registry.READ|access)
	if err != nil {
		return "", err
	}
	defer k.Close()

	// Try REG_SZ first.
	if s, _, err := k.GetStringValue(value); err == nil {
		return s, nil
	}
	return "", registry.ErrNotExist
}
