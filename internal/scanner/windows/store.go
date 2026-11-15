//go:build windows

package windows

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"

	"sys-scanner/internal/types"
)

const (
	powerShellTimeout = 30 * time.Second
	appxRegPath       = `SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Applications`
)

// getCmdAppxPackage builds the PowerShell command text for Get-AppxPackage.
// It is a pure function so it can be tested cross-platform.
// windowsPowerShellPath returns the absolute path of Windows PowerShell under
// %SystemRoot% so a hostile PATH or current directory cannot substitute a
// different executable.
func windowsPowerShellPath() string {
	return filepath.Join(windowsRootDir(), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
}

func getCmdAppxPackage() string {
	// Force UTF-8 console output: PowerShell redirects stdout in the legacy
	// console code page by default, which would garble non-ASCII publisher
	// names (e.g. Chinese OEMs) before Go parses the JSON.
	return "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8; " +
		"Get-AppxPackage | Select-Object Name, Version, Publisher | ConvertTo-Json -Compress"
}

// scanStoreApps attempts to enumerate Microsoft Store (UWP / AppX) packages.
// Primary: powershell.exe Get-AppxPackage (JSON output, 30 s timeout).
// Fallback: read the AppxAllUserStore\Applications registry key.
func scanStoreApps() ([]types.Program, error) {
	progs, err := scanStoreAppsPowerShell()
	if err == nil && len(progs) > 0 {
		return progs, nil
	}
	if err != nil {
		slog.Warn("Store scanner: PowerShell failed, trying registry fallback", "error", err)
	}

	progs, err = scanStoreAppsRegistry()
	if err != nil {
		slog.Warn("Store scanner: registry fallback also failed", "error", err)
		return nil, err
	}
	return progs, nil
}

// ---- PowerShell path ------------------------------------------------------

// appxPackageJSON mirrors the JSON produced by Get-AppxPackage | Select-Object.
type appxPackageJSON struct {
	Name      string `json:"Name"`
	Version   string `json:"Version"`
	Publisher string `json:"Publisher"`
}

// scanStoreAppsPowerShell invokes powershell.exe to enumerate Store apps.
func scanStoreAppsPowerShell() ([]types.Program, error) {
	ctx, cancel := context.WithTimeout(context.Background(), powerShellTimeout)
	defer cancel()

	// #nosec G204 -- absolute path under %SystemRoot%; arguments are fixed.
	cmd := exec.CommandContext(ctx,
		windowsPowerShellPath(),
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		getCmdAppxPackage(),
	)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("powershell Get-AppxPackage: %w: %s", err, stderr.String())
	}

	out := stripJSONBOM(strings.TrimSpace(stdout.String()))
	if out == "" || out == "null" {
		return nil, nil
	}

	// Get-AppxPackage may return a single object or an array.
	var pkgs []appxPackageJSON
	if err := json.Unmarshal([]byte(out), &pkgs); err != nil {
		// Try as a single object.
		var single appxPackageJSON
		if err2 := json.Unmarshal([]byte(out), &single); err2 != nil {
			return nil, fmt.Errorf("parse AppX JSON: %w", err)
		}
		pkgs = append(pkgs, single)
	}

	programs := make([]types.Program, 0, len(pkgs))
	for _, p := range pkgs {
		if p.Name == "" {
			continue
		}
		if isBuiltinStorePackage(p.Name) {
			continue
		}
		programs = append(programs, types.Program{
			Name:      p.Name,
			Version:   p.Version,
			Publisher: cleanPublisher(p.Publisher),
			Source:    "store",
		})
	}
	return programs, nil
}

// cleanPublisher converts a Publisher string (often a certificate subject
// like "CN=Microsoft Corporation, O=...") into a short name.
func cleanPublisher(pub string) string {
	// Extract CN= if present.
	for _, part := range strings.Split(pub, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "CN=") {
			return part[3:]
		}
	}
	return strings.TrimSpace(pub)
}

// ---- Registry fallback path ----------------------------------------------

// scanStoreAppsRegistry reads the Appx registry as a fallback when
// PowerShell is unavailable or too slow.
func scanStoreAppsRegistry() ([]types.Program, error) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, appxRegPath, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil, fmt.Errorf("open Appx registry: %w", err)
	}
	defer k.Close()

	subKeys, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, fmt.Errorf("enumerate Appx subkeys: %w", err)
	}

	programs := make([]types.Program, 0, len(subKeys))
	for _, name := range subKeys {
		sk, err := registry.OpenKey(k, name, registry.QUERY_VALUE)
		if err != nil {
			slog.Debug("Appx subkey open failed", "key", name, "error", err)
			continue
		}
		vals := readRegistryStringValues(sk)
		_ = sk.Close()

		displayName := strings.TrimSpace(vals[valDisplayName])
		if displayName == "" {
			displayName = name // fall back to the subkey name
		}
		if isBuiltinStorePackage(name) || isWindowsBuiltinName(displayName) {
			continue
		}

		programs = append(programs, types.Program{
			Name:      displayName,
			Version:   strings.TrimSpace(vals[valDisplayVersion]),
			Publisher: strings.TrimSpace(vals[valPublisher]),
			Source:    "store",
		})
	}
	return programs, nil
}
