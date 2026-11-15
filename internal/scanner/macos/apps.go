//go:build darwin

// Package macos implements macOS-specific program detection.
package macos

import (
	"log"
	"os"
	"path/filepath"
	"strings"

	"howett.net/plist"

	"sys-scanner/internal/types"
)

// appDirs returns the directories to scan for .app bundles.
func appDirs() []string {
	home, err := os.UserHomeDir()
	dirs := []string{"/Applications", "/System/Applications"}
	if err == nil {
		dirs = append(dirs, filepath.Join(home, "Applications"))
	}
	return dirs
}

// scanAppBundles walks the standard macOS application directories at depth 1
// and parses each .app bundle's Info.plist to extract program metadata.
func scanAppBundles() ([]types.Program, error) {
	var programs []types.Program

	for _, dir := range appDirs() {
		entries, err := os.ReadDir(dir)
		if err != nil {
			log.Printf("macos: skipping app dir %s: %v", dir, err)
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() || !strings.HasSuffix(entry.Name(), ".app") {
				continue
			}
			appPath := filepath.Join(dir, entry.Name())
			p, err := parseAppBundle(appPath)
			if err != nil {
				log.Printf("macos: failed to parse app bundle %s: %v", appPath, err)
				continue
			}
			programs = append(programs, p)
		}
	}

	return programs, nil
}

// parseAppBundle reads Contents/Info.plist from a .app bundle and returns a
// Program. The name resolution order is: CFBundleDisplayName → CFBundleName →
// directory basename.
func parseAppBundle(appPath string) (types.Program, error) {
	plistPath := filepath.Join(appPath, "Contents", "Info.plist")
	data, err := os.ReadFile(plistPath)
	if err != nil {
		return types.Program{}, err
	}

	var info map[string]any
	if _, err := plist.Unmarshal(data, &info); err != nil {
		return types.Program{}, err
	}

	name := plistString(info, "CFBundleDisplayName")
	if name == "" {
		name = plistString(info, "CFBundleName")
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(appPath), ".app")
	}

	version := plistString(info, "CFBundleShortVersionString")
	publisher := plistString(info, "CFBundleIdentifier")

	return types.Program{
		Name:            name,
		Version:         version,
		Publisher:       publisher,
		InstallLocation: appPath,
		Source:          "app_bundle",
		RawMetadata:     buildRawMetadata(info),
	}, nil
}

// plistString extracts a string value from a plist map, returning "" if the
// key is absent or the value is not a string.
func plistString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// buildRawMetadata copies selected Info.plist keys into the RawMetadata map.
func buildRawMetadata(info map[string]any) map[string]string {
	keys := []string{
		"CFBundleDisplayName",
		"CFBundleName",
		"CFBundleShortVersionString",
		"CFBundleIdentifier",
		"CFBundleVersion",
		"CFBundleExecutable",
		"LSMinimumSystemVersion",
	}
	meta := make(map[string]string)
	for _, k := range keys {
		if v := plistString(info, k); v != "" {
			meta[k] = v
		}
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}
